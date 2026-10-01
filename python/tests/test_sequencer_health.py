from __future__ import annotations

import unittest

import httpx

from dcg.sequencer.health import classify
from dcg.sequencer.pool import HealthSignal
from dcg.sequencer.types import ProgramRefused, RateLimited, RpcUnavailable


def status_error(status_code: int, *, retry_after: str | None = None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://rpc.invalid")
    headers = {"Retry-After": retry_after} if retry_after is not None else None
    response = httpx.Response(status_code, request=request, headers=headers)
    return httpx.HTTPStatusError("endpoint response", request=request, response=response)


class EndpointHealthClassificationTests(unittest.TestCase):
    def test_rate_limited_retry_after_is_preserved(self) -> None:
        observation = classify(RateLimited("429", retry_after=2.5))
        self.assertIs(observation.signal, HealthSignal.RATE_LIMITED)
        self.assertEqual(observation.retry_after_seconds, 2.5)

    def test_rpc_unavailable_is_a_transport_error(self) -> None:
        observation = classify(RpcUnavailable("offline"))
        self.assertIs(observation.signal, HealthSignal.TRANSPORT_ERROR)

    def test_http_statuses_map_to_health_signals(self) -> None:
        timeout = classify(status_error(408))
        too_early = classify(status_error(425))
        server = classify(status_error(503, retry_after="3"))
        throttled = classify(status_error(429, retry_after="1.5"))
        self.assertIs(timeout.signal, HealthSignal.TIMEOUT)
        self.assertIs(too_early.signal, HealthSignal.TRANSPORT_ERROR)
        self.assertIs(server.signal, HealthSignal.TRANSPORT_ERROR)
        self.assertEqual(server.retry_after_seconds, 3.0)
        self.assertIs(throttled.signal, HealthSignal.RATE_LIMITED)
        self.assertEqual(throttled.retry_after_seconds, 1.5)

    def test_application_refusal_is_not_endpoint_health(self) -> None:
        with self.assertRaises(TypeError):
            classify(ProgramRefused("program rejected transaction"))


if __name__ == "__main__":
    unittest.main()
