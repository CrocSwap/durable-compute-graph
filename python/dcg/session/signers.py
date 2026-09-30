"""Fee-payer, authority, and writer signing roles for session transactions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from solders.keypair import Keypair
from solders.message import Message
from solders.signature import Signature

from dcg.sequencer import BlockhashLease, SignedTransaction


def _shortvec(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _keypair(path: str | Path) -> Keypair:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        raise ValueError("keypair file must be readable Solana byte-array JSON") from None
    if (
        not isinstance(payload, list)
        or len(payload) != 64
        or any(not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255 for item in payload)
    ):
        raise ValueError("keypair file must contain exactly 64 byte values")
    secret = bytearray(payload)
    del payload
    try:
        return Keypair.from_bytes(bytes(secret))
    except Exception:
        raise ValueError("keypair file contains an invalid Solana keypair") from None
    finally:
        secret[:] = bytes(len(secret))


class SessionSigners:
    """Sign only the required message keys using caller-assigned role keys."""

    def __init__(self, *, payer: Keypair, authority: Keypair, writer: Keypair | None = None):
        self.payer = payer
        self.authority = authority
        self.writer = writer or authority
        self._by_pubkey: dict[bytes, Keypair] = {}
        for keypair in (self.payer, self.authority, self.writer):
            self._by_pubkey[bytes(keypair.pubkey())] = keypair

    @classmethod
    def from_files(
        cls, *, payer: str | Path, authority: str | Path, writer: str | Path | None = None
    ) -> SessionSigners:
        return cls(
            payer=_keypair(payer),
            authority=_keypair(authority),
            writer=_keypair(writer) if writer is not None else None,
        )

    @property
    def public_key(self) -> str:
        return str(self.payer.pubkey())

    @property
    def signature_count(self) -> int:
        return len(self._by_pubkey)

    @property
    def signature_size_bytes(self) -> int:
        return 64

    @property
    def authority_public_key(self) -> str:
        return str(self.authority.pubkey())

    @property
    def writer_public_key(self) -> str:
        return str(self.writer.pubkey())

    def for_roles(self, roles: set[str]) -> SessionSigners:
        """Return the exact signer set required by one built instruction."""

        role_keys = {"payer": self.payer, "authority": self.authority, "writer": self.writer}
        missing = roles - role_keys.keys()
        if missing:
            raise ValueError(f"unknown session signer role(s): {', '.join(sorted(missing))}")
        selected = object.__new__(SessionSigners)
        selected.payer = self.payer
        selected.authority = self.authority
        selected.writer = self.writer
        selected._by_pubkey = {bytes(role_keys[role].pubkey()): role_keys[role] for role in roles}
        return selected

    async def sign(self, message: bytes, lease: BlockhashLease) -> SignedTransaction:
        del lease  # The recent blockhash is already in the canonical message.
        try:
            parsed = Message.from_bytes(message)
            required = parsed.header.num_required_signatures
            signer_keys = parsed.account_keys[:required]
        except Exception as exc:
            raise ValueError("session signer received an invalid Solana message") from exc
        if required == 0 or len(signer_keys) != required:
            raise ValueError("session message has no complete required-signer prefix")
        signatures: list[bytes] = []
        for pubkey in signer_keys:
            keypair = self._by_pubkey.get(bytes(pubkey))
            if keypair is None:
                raise ValueError(f"no supplied signer has the required role for {pubkey}")
            signatures.append(bytes(keypair.sign_message(message)))
        first_signature = Signature.from_bytes(signatures[0])
        raw = _shortvec(required) + b"".join(signatures) + message
        return SignedTransaction(signature=str(first_signature), raw_bytes=raw)
