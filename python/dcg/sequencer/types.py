"""Public data types and adapter protocols for :mod:`dcg.sequencer`."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Protocol, Sequence


class FailureClass(str, Enum):
    RESUMABLE = "resumable"
    TERMINAL = "terminal"
    AMBIGUOUS = "ambiguous"


class SequencerError(Exception):
    failure_class = FailureClass.TERMINAL


class PlanError(SequencerError):
    """The plan is malformed or cannot be safely bound to a journal."""


class PacketTooLarge(SequencerError):
    """The transaction exceeds its packet limit before signing."""


class RpcError(SequencerError):
    """Base class for explicitly classified provider failures."""

    failure_class = FailureClass.RESUMABLE


class RpcConfigurationError(SequencerError):
    """The endpoint rejected its credentials or the request configuration."""


class RpcUnavailable(RpcError):
    """The endpoint is temporarily unavailable or timed out."""


class RateLimited(RpcError):
    """The endpoint returned a rate-limit response."""

    def __init__(self, message: str = "RPC rate limited", retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class BlockhashExpired(RpcError):
    """The provider rejected a packet because its blockhash is expired."""


class ProgramRefused(SequencerError):
    """The chain finalized the transaction with a program error."""


class AmbiguousFate(SequencerError):
    """Neither signature status nor application state proves the outcome."""

    failure_class = FailureClass.AMBIGUOUS


class ReconciliationRequired(AmbiguousFate):
    """A stream branch needs application state reconciliation before continuing."""


class StepTimeCapExceeded(SequencerError):
    """The configured per-step time cap expired; journal state is resumable."""

    failure_class = FailureClass.RESUMABLE


class JournalError(SequencerError):
    """The journal is corrupt, incompatible, or inconsistent with the plan."""


class RetryPolicy(str, Enum):
    SAME_BYTES = "same-bytes"
    RECONCILE = "reconcile-with-adapter"
    NEVER = "never"


class Commitment(str, Enum):
    PROCESSED = "processed"
    CONFIRMED = "confirmed"
    FINALIZED = "finalized"


class LatencyMode(str, Enum):
    CONFIRMED = "confirmed"
    PROCESSED = "processed"


@dataclass(frozen=True)
class BlockhashLease:
    blockhash: str
    genesis_hash: str
    fetched_at_unix: float
    last_valid_block_height: int | None = None
    context_slot: int | None = None
    lifetime_seconds: float = 6.0


@dataclass(frozen=True)
class SendReceipt:
    signature: str


@dataclass(frozen=True)
class SignatureObservation:
    signature: str
    commitment: Commitment
    error: str | None = None
    slot: int | None = None
    transaction_metadata_available: bool = False
    fee_lamports: int | None = None
    compute_units_consumed: int | None = None


@dataclass(frozen=True)
class AccountInfo:
    owner: str
    lamports: int
    executable: bool
    rent_epoch: int | None
    data: bytes
    context_slot: int | None = None


@dataclass(frozen=True)
class SimulationResult:
    error: object | None
    logs: tuple[str, ...]
    units_consumed: int | None
    return_data: object | None = None


@dataclass(frozen=True)
class PostconditionResult:
    """Application state observation; ``None`` means not enough evidence."""

    satisfied: bool | None
    state_digest: str | None = None


@dataclass(frozen=True)
class RecoveryEvidence:
    signature: str
    lease: BlockhashLease
    status: SignatureObservation | None
    postcondition: PostconditionResult
    lease_expired: bool


@dataclass(frozen=True)
class SignedTransaction:
    signature: str
    raw_bytes: bytes


class Signer(Protocol):
    """Signing capability. Implementations retain all private key material."""

    @property
    def public_key(self) -> str: ...

    @property
    def signature_count(self) -> int: ...

    @property
    def signature_size_bytes(self) -> int: ...

    async def sign(self, message: bytes, lease: BlockhashLease) -> SignedTransaction: ...


class MessageSigner(Protocol):
    """Injected signer for one required account in a multi-signer message."""

    @property
    def public_key(self) -> str: ...

    async def sign_message(self, message: bytes) -> bytes: ...


class RpcEndpoint(Protocol):
    """RPC boundary. Network-specific wire encoding stays in this adapter."""

    @property
    def endpoint_id(self) -> str: ...

    async def latest_blockhash(self, genesis_hash: str, lifetime_seconds: float) -> BlockhashLease: ...

    async def send_raw_transaction(self, raw_bytes: bytes) -> SendReceipt: ...

    async def signature_status(self, signature: str) -> SignatureObservation | None: ...

    async def get_multiple_accounts(
        self, addresses: Sequence[str], commitment: Commitment
    ) -> tuple[AccountInfo | None, ...]: ...

    async def get_program_accounts(
        self,
        program_id: str,
        *,
        filters: Sequence[dict[str, object]],
        commitment: Commitment,
    ) -> tuple[tuple[str, AccountInfo], ...]: ...


Postcondition = Callable[[RpcEndpoint], Awaitable[PostconditionResult]]
RebuildAuthorizer = Callable[[RecoveryEvidence], Awaitable[bool]]
MessageBuilder = Callable[[BlockhashLease], bytes]
EventHook = Callable[[str, str | None], Awaitable[None]]


@dataclass(frozen=True)
class TransactionStep:
    step_id: str
    dependencies: tuple[str, ...]
    endpoint_id: str
    compute_class: str
    compute_unit_limit: int
    intent_digest: str
    recovery_policy_digest: str
    build_message: MessageBuilder
    postcondition: Postcondition
    max_packet_bytes: int = 1232
    write_locks: tuple[str, ...] = ()
    retry_policy: RetryPolicy = RetryPolicy.SAME_BYTES
    authorize_rebuild: RebuildAuthorizer | None = None
    route_group: str | None = None
    route_affinity: str | None = None
    provider_id: str | None = None
    reconcile_dropped: Callable[[RpcEndpoint, str, PostconditionResult], Awaitable[None]] | None = None


@dataclass(frozen=True)
class TransactionPlan:
    genesis_hash: str
    program_id: str
    destination_accounts: tuple[str, ...]
    signer_public_key: str
    steps: tuple[TransactionStep, ...]
    signer_public_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class EndpointLimits:
    sends_per_second: float = 10.0
    max_in_flight: int = 8
    requests_per_second: float = 100.0
    weight: float = 1.0
    route_group: str | None = None


@dataclass(frozen=True)
class Backoff:
    initial_seconds: float = 0.25
    maximum_seconds: float = 4.0
    multiplier: float = 2.0


@dataclass(frozen=True)
class SequencerConfig:
    endpoint_limits: dict[str, EndpointLimits]
    max_batch_size: int = 32
    max_packet_bytes: int = 1232
    blockhash_lifetime_seconds: float = 6.0
    per_step_time_cap_seconds: float = 90.0
    confirmation_poll_seconds: float = 0.25
    backoff: Backoff = Backoff()
    pool_acquire_timeout_seconds: float = 30.0
    health_score_threshold: float = 6.0
    health_cooldown_seconds: float = 1.0
    health_max_cooldown_seconds: float = 60.0
    health_rate_limit_points: float = 6.0
    health_transport_error_points: float = 2.0
    status_batch_window_seconds: float = 0.002
    status_batch_size: int = 256
    latency_mode: LatencyMode = LatencyMode.CONFIRMED
    optimistic_max_depth: int = 2
    optimistic_max_seconds: float = 2.0
    optimistic_drop_status_misses: int = 2
    stream_journal_quota_bytes: int = 1_000_000_000
    stream_checkpoint_retention: int = 2
    monotonic_clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
