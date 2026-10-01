"""Solana keypair-file signer implementation."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature

from .types import BlockhashLease, SignedTransaction


class KeypairFileSigner:
    """Sign one-signer Solana legacy or v0 messages from a keypair JSON file.

    The file is opened only during construction. Key bytes are kept in the
    Solders keypair object in memory; this class has no logging or journal
    path. A hardware or remote signer can implement the public ``Signer``
    protocol instead of this class.
    """

    def __init__(self, keypair: Keypair):
        self._keypair = keypair
        self._public_key = str(keypair.pubkey())
        self._public_key_bytes = bytes(keypair.pubkey())

    @classmethod
    def from_file(cls, path: str | Path) -> KeypairFileSigner:
        try:
            encoded = Path(path).read_text(encoding="utf-8")
        except OSError:
            raise ValueError("could not read keypair file") from None
        try:
            numbers = json.loads(encoded)
        except (ValueError, TypeError):
            raise ValueError("keypair file must contain a Solana byte-array JSON value") from None
        del encoded
        if (
            not isinstance(numbers, list)
            or len(numbers) != 64
            or any(not isinstance(byte, int) or isinstance(byte, bool) or not 0 <= byte <= 255 for byte in numbers)
        ):
            raise ValueError("keypair file must contain exactly 64 byte values")
        secret = bytearray(numbers)
        del numbers
        try:
            keypair = Keypair.from_bytes(bytes(secret))
        except Exception:
            raise ValueError("keypair file contains an invalid Solana keypair") from None
        finally:
            secret[:] = b"\x00" * len(secret)
        return cls(keypair)

    @property
    def public_key(self) -> str:
        return self._public_key

    @property
    def signature_count(self) -> int:
        return 1

    @property
    def signature_size_bytes(self) -> int:
        return 64

    async def sign(self, message: bytes, lease: BlockhashLease) -> SignedTransaction:
        del lease  # The blockhash is already part of the exact message bytes.
        signer_count, first_signer = _message_signer(message)
        if signer_count != 1:
            raise ValueError("keypair-file signer only accepts messages with one required signer")
        if first_signer != self._public_key_bytes:
            raise ValueError("message fee payer does not match the keypair signer")
        signature = self._keypair.sign_message(message)
        signature_bytes = bytes(signature)
        raw_transaction = _shortvec(1) + signature_bytes + message
        return SignedTransaction(signature=str(signature), raw_bytes=raw_transaction)

    async def sign_message(self, message: bytes) -> bytes:
        """Return this injected keypair's signature for a multi-signer message."""

        required, signers = _message_signers(message)
        if required <= 1 or self._public_key_bytes not in signers:
            raise ValueError("keypair is not a required signer in the supplied message")
        return bytes(self._keypair.sign_message(message))


class MultiSigner:
    """Combine signatures from explicitly injected message signers.

    The signer order must match the required-signer prefix in the transaction
    message. This object retains only the signer objects supplied by its
    caller and never reads or discovers key material.
    """

    def __init__(self, signers):
        self._signers = tuple(signers)
        if len(self._signers) < 2:
            raise ValueError("MultiSigner requires at least two injected signers")
        keys = tuple(signer.public_key for signer in self._signers)
        if any(not isinstance(key, str) or not key for key in keys) or len(set(keys)) != len(keys):
            raise ValueError("injected signer public keys must be non-empty and unique")
        self._public_keys = keys

    @property
    def public_key(self) -> str:
        return self._public_keys[0]

    @property
    def public_keys(self) -> tuple[str, ...]:
        return self._public_keys

    @property
    def signature_count(self) -> int:
        return len(self._signers)

    @property
    def signature_size_bytes(self) -> int:
        return 64

    async def sign(self, message: bytes, lease: BlockhashLease) -> SignedTransaction:
        del lease
        required, message_signers = _message_signers(message)
        expected = tuple(_pubkey_bytes(key) for key in self._public_keys)
        if required != len(expected) or message_signers != expected:
            raise ValueError("transaction required signers do not match the injected signer order")
        signatures = await asyncio.gather(*(signer.sign_message(message) for signer in self._signers))
        if any(not isinstance(signature, bytes) or len(signature) != 64 for signature in signatures):
            raise ValueError("message signers must return exactly 64 signature bytes")
        if any(
            not Signature.from_bytes(signature).verify(Pubkey.from_bytes(public_key), message)
            for public_key, signature in zip(expected, signatures, strict=True)
        ):
            raise ValueError("an injected signer returned a signature that does not verify")
        signature = str(Signature.from_bytes(signatures[0]))
        return SignedTransaction(signature=signature, raw_bytes=_shortvec(len(signatures)) + b"".join(signatures) + message)


def _pubkey_bytes(value: str) -> bytes:
    from solders.pubkey import Pubkey

    return bytes(Pubkey.from_string(value))


def _message_signers(message: bytes) -> tuple[int, tuple[bytes, ...]]:
    if not message:
        raise ValueError("transaction message is empty")
    versioned = bool(message[0] & 0x80)
    header_at = 1 if versioned else 0
    if versioned and (message[0] & 0x7F) != 0:
        raise ValueError("unsupported versioned transaction message")
    if len(message) < header_at + 3:
        raise ValueError("transaction message header is truncated")
    required = message[header_at]
    account_count, account_keys_at = _read_shortvec(message, header_at + 3)
    if account_count == 0 or required == 0 or required > account_count:
        raise ValueError("transaction message has an invalid signer header")
    key_end = account_keys_at + 32 * account_count
    if key_end > len(message):
        raise ValueError("transaction message account keys are truncated")
    return required, tuple(
        message[account_keys_at + index * 32 : account_keys_at + (index + 1) * 32]
        for index in range(required)
    )


def _message_signer(message: bytes) -> tuple[int, bytes]:
    if not message:
        raise ValueError("transaction message is empty")
    versioned = bool(message[0] & 0x80)
    header_at = 1 if versioned else 0
    if versioned and (message[0] & 0x7F) != 0:
        raise ValueError("unsupported versioned transaction message")
    if len(message) < header_at + 3:
        raise ValueError("transaction message header is truncated")
    required_signatures = message[header_at]
    account_count, account_keys_at = _read_shortvec(message, header_at + 3)
    if account_count == 0 or required_signatures > account_count:
        raise ValueError("transaction message has an invalid signer header")
    key_end = account_keys_at + 32 * account_count
    if key_end > len(message):
        raise ValueError("transaction message account keys are truncated")
    return required_signatures, message[account_keys_at : account_keys_at + 32]


def _read_shortvec(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift <= 14:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise ValueError("transaction message contains an invalid account-key length")


def _shortvec(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)
