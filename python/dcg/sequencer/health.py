"""Translate RPC and transport exceptions into endpoint-pool observations."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import httpx

from .pool import HealthObservation, HealthSignal
from .types import RateLimited, RpcUnavailable


def classify(exc: Exception) -> HealthObservation:
    """Classify a transport exception without treating app refusals as health.

    ``RateLimited.retry_after`` and HTTP ``Retry-After`` values are carried into
    the pool cooldown. HTTP 408 is a timeout; HTTP 425 and 5xx responses are
    transport errors. Unknown/application exceptions raise ``TypeError`` so a
    program refusal cannot accidentally mark a healthy endpoint as unhealthy.
    """

    if isinstance(exc, RateLimited):
        return HealthObservation(
            HealthSignal.RATE_LIMITED,
            retry_after_seconds=exc.retry_after,
        )

    status = _status_code(exc)
    retry_after = _retry_after(exc)
    if status == 408:
        return HealthObservation(HealthSignal.TIMEOUT, retry_after_seconds=retry_after)
    if status == 429:
        return HealthObservation(
            HealthSignal.RATE_LIMITED,
            retry_after_seconds=retry_after,
        )
    if status == 425 or (status is not None and 500 <= status <= 599):
        return HealthObservation(
            HealthSignal.TRANSPORT_ERROR,
            retry_after_seconds=retry_after,
        )
    if isinstance(exc, RpcUnavailable):
        return HealthObservation(HealthSignal.TRANSPORT_ERROR)
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return HealthObservation(HealthSignal.TIMEOUT)
    if isinstance(exc, (httpx.TransportError, OSError, ConnectionError)):
        return HealthObservation(HealthSignal.TRANSPORT_ERROR)
    raise TypeError(f"cannot classify {type(exc).__name__} as endpoint health")


def _status_code(exc: Exception) -> int | None:
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if status is None:
        status = getattr(exc, "status_code", None)
    return status if isinstance(status, int) else None


def _retry_after(exc: Exception) -> float | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get("Retry-After")
    if not isinstance(value, str):
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            seconds = (retry_at - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(seconds):
        return None
    return max(0.0, seconds)
