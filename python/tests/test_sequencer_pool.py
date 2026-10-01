from __future__ import annotations

import asyncio
import unittest

from dcg.sequencer.pool import (
    EndpointNodeConfig,
    EndpointPool,
    HealthObservation,
    HealthPolicy,
    HealthSignal,
    RequestKind,
)


class FakeEndpoint:
    def __init__(self, endpoint_id: str):
        self.endpoint_id = endpoint_id


class EndpointPoolTests(unittest.IsolatedAsyncioTestCase):
    def node(
        self,
        endpoint_id: str,
        *,
        weight: float = 1.0,
        requests_per_second: float = 10_000.0,
        sends_per_second: float = 10_000.0,
        max_in_flight: int = 8,
        route_group: str = "default",
    ) -> EndpointNodeConfig:
        return EndpointNodeConfig(
            endpoint=FakeEndpoint(endpoint_id),  # type: ignore[arg-type]
            sends_per_second=sends_per_second,
            requests_per_second=requests_per_second,
            max_in_flight=max_in_flight,
            weight=weight,
            route_group=route_group,
        )

    async def test_per_node_in_flight_and_request_rate_caps(self) -> None:
        pool = EndpointPool(
            [
                self.node("slow", requests_per_second=25, max_in_flight=1),
                self.node("fast", requests_per_second=500, max_in_flight=2),
            ]
        )
        first = await pool.acquire(RequestKind.RPC, endpoint_id="slow")
        started = asyncio.get_running_loop().time()
        queued = asyncio.create_task(pool.acquire(RequestKind.RPC, endpoint_id="slow"))
        await asyncio.sleep(0.005)
        self.assertFalse(queued.done(), "same-node request should wait behind its in-flight cap")

        # A separate node has its own semaphore and rate schedule.
        other = await asyncio.wait_for(pool.acquire(RequestKind.RPC, endpoint_id="fast"), 0.05)
        self.assertEqual(other.endpoint_id, "fast")
        await other.close()
        await first.close()

        second = await asyncio.wait_for(queued, 0.2)
        elapsed = asyncio.get_running_loop().time() - started
        self.assertGreaterEqual(elapsed, 0.035, "slow node request budget must pace its second request")
        await second.close()

    async def test_send_rate_is_separate_from_total_rpc_rate(self) -> None:
        pool = EndpointPool([self.node("a", sends_per_second=5, requests_per_second=500)])
        first = await pool.acquire(RequestKind.SEND, endpoint_id="a")
        await first.close()

        started = asyncio.get_running_loop().time()
        second = await pool.acquire(RequestKind.SEND, endpoint_id="a")
        elapsed = asyncio.get_running_loop().time() - started
        self.assertGreaterEqual(elapsed, 0.16)
        await second.close()

        # A non-send RPC still consumes the shared request budget, not the send-only budget.
        started = asyncio.get_running_loop().time()
        read = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        self.assertLess(asyncio.get_running_loop().time() - started, 0.08)
        await read.close()

    async def test_weighted_selection_matches_configured_ratio(self) -> None:
        pool = EndpointPool([self.node("heavy", weight=3), self.node("light", weight=1)])
        selections: list[str] = []
        for _ in range(40):
            lease = await pool.acquire(RequestKind.RPC)
            selections.append(lease.endpoint_id)
            await lease.close()
        self.assertEqual(selections.count("heavy"), 30)
        self.assertEqual(selections.count("light"), 10)

    async def test_health_cools_node_then_requires_a_successful_probe(self) -> None:
        pool = EndpointPool(
            [self.node("a"), self.node("b")],
            health_policy=HealthPolicy(cooldown_seconds=0.03, max_cooldown_seconds=0.1),
        )
        bad = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        await bad.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await bad.close()

        routed = await pool.acquire(RequestKind.RPC)
        self.assertEqual(routed.endpoint_id, "b")
        await routed.close()
        self.assertEqual(await pool.probe_due(), ())

        await asyncio.sleep(0.04)
        self.assertEqual(await pool.probe_due(), ("a",))
        probe = await pool.acquire(RequestKind.PROBE, endpoint_id="a")
        self.assertTrue(probe.route.is_probe)
        await probe.observe(HealthObservation(HealthSignal.SUCCESS, latency_seconds=0.001))
        await probe.close()

        recovered = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        self.assertEqual(recovered.endpoint_id, "a")
        await recovered.close()

    async def test_retry_after_cools_endpoint_and_probe_failure_extends_cooldown(self) -> None:
        pool = EndpointPool(
            [self.node("a"), self.node("b")],
            health_policy=HealthPolicy(cooldown_seconds=0.01, max_cooldown_seconds=0.02),
        )
        lease = await pool.acquire(RequestKind.SEND, endpoint_id="a")
        await lease.observe(
            HealthObservation(HealthSignal.RATE_LIMITED, retry_after_seconds=0.04)
        )
        await lease.close()
        snapshot = {item.endpoint_id: item for item in await pool.snapshots()}["a"]
        self.assertGreaterEqual(snapshot.cooldown_until, asyncio.get_running_loop().time() + 0.02)

        await asyncio.sleep(0.05)
        probe = await pool.acquire(RequestKind.PROBE, endpoint_id="a")
        await probe.observe(HealthObservation(HealthSignal.TIMEOUT))
        await probe.close()
        self.assertEqual(await pool.probe_due(), ())
        snapshot = {item.endpoint_id: item for item in await pool.snapshots()}["a"]
        self.assertGreater(snapshot.cooldown_until, asyncio.get_running_loop().time())

    async def test_affinity_is_preferred_and_falls_back_when_node_is_cooling(self) -> None:
        pool = EndpointPool(
            [self.node("a"), self.node("b")],
            health_policy=HealthPolicy(cooldown_seconds=0.05, max_cooldown_seconds=0.1),
        )
        pool.remember_affinity("lane-1", "a")
        preferred = await pool.acquire(RequestKind.RPC, route_affinity="lane-1")
        self.assertEqual(preferred.endpoint_id, "a")
        await preferred.close()

        unhealthy = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        await unhealthy.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await unhealthy.close()
        fallback = await pool.acquire(RequestKind.RPC, route_affinity="lane-1")
        self.assertEqual(fallback.endpoint_id, "b")
        self.assertEqual(fallback.route.affinity_key, "lane-1")
        await fallback.close()

    async def test_abandoned_probe_does_not_rehabilitate_endpoint(self) -> None:
        pool = EndpointPool(
            [self.node("a")],
            health_policy=HealthPolicy(cooldown_seconds=0.01, max_cooldown_seconds=0.02),
        )
        lease = await pool.acquire(RequestKind.RPC)
        await lease.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await lease.close()
        await asyncio.sleep(0.02)
        probe = await pool.acquire(RequestKind.PROBE)
        await probe.close()
        snapshot = (await pool.snapshots())[0]
        self.assertTrue(snapshot.probe_required)
        self.assertGreater(snapshot.cooldown_until, asyncio.get_running_loop().time())


if __name__ == "__main__":
    unittest.main()
