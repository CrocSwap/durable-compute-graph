from __future__ import annotations

import asyncio
import unittest

from dcg.sequencer.pool import (
    EndpointNodeConfig,
    EndpointPool,
    EndpointPoolExhausted,
    HealthObservation,
    HealthPolicy,
    HealthSignal,
    RequestKind,
)


class FakeClock:
    def __init__(self, now: float = 100.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def wake(pool: EndpointPool) -> None:
    async with pool._condition:  # test-only clock advance notification
        pool._condition.notify_all()


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
        clock = FakeClock()
        pool = EndpointPool(
            [
                self.node("slow", requests_per_second=25, max_in_flight=1),
                self.node("fast", requests_per_second=500, max_in_flight=2),
            ],
            clock=clock,
        )
        first = await pool.acquire(RequestKind.RPC, endpoint_id="slow")
        queued = asyncio.create_task(pool.acquire(RequestKind.RPC, endpoint_id="slow"))
        await asyncio.sleep(0)
        self.assertFalse(queued.done(), "same-node request should wait behind its in-flight cap")
        snapshot = {item.endpoint_id: item for item in await pool.snapshots()}["slow"]
        self.assertEqual(snapshot.waiter_count, 1)

        # A separate node has its own semaphore and rate schedule.
        other = await pool.acquire(RequestKind.RPC, endpoint_id="fast")
        self.assertEqual(other.endpoint_id, "fast")
        await other.close()
        await first.close()

        clock.advance(0.04)
        await wake(pool)
        second = await queued
        await second.close()

    async def test_send_rate_is_separate_from_total_rpc_rate(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a", sends_per_second=5, requests_per_second=500)], clock=clock
        )
        first = await pool.acquire(RequestKind.SEND, endpoint_id="a")
        await first.close()

        queued = asyncio.create_task(pool.acquire(RequestKind.SEND, endpoint_id="a"))
        await asyncio.sleep(0)
        self.assertFalse(queued.done())
        clock.advance(0.2)
        await wake(pool)
        second = await queued
        await second.close()

        # A non-send RPC still consumes the shared request budget, not the send-only budget.
        clock.advance(0.002)
        read = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        await read.close()

    async def test_weighted_selection_uses_due_nodes_and_approaches_sum_of_rates(self) -> None:
        clock = FakeClock(0.0)
        pool = EndpointPool(
            [
                self.node("slow", sends_per_second=5, requests_per_second=5),
                self.node("fast", sends_per_second=1_000, requests_per_second=1_000),
            ],
            clock=clock,
            default_acquire_timeout_seconds=1.0,
        )
        selected: dict[str, int] = {"slow": 0, "fast": 0}
        for tick in range(1_001):
            if tick:
                clock.advance(0.001)
            lease = await pool.acquire(RequestKind.SEND, deadline=clock())
            selected[lease.endpoint_id] += 1
            await lease.close()
        self.assertGreaterEqual(sum(selected.values()), 1_000)
        self.assertGreaterEqual(selected["fast"], 995)
        self.assertGreaterEqual(selected["slow"], 4)

    async def test_deadline_raises_classified_pool_exhaustion(self) -> None:
        clock = FakeClock()
        pool = EndpointPool([self.node("a", max_in_flight=1)], clock=clock)
        lease = await pool.acquire(RequestKind.RPC)
        try:
            with self.assertRaises(EndpointPoolExhausted) as error:
                await pool.acquire(RequestKind.RPC, deadline=clock())
            self.assertEqual(error.exception.classification, "pool-exhausted")
            self.assertEqual(error.exception.failure_class.value, "resumable")
        finally:
            await lease.close()

    async def test_first_caller_after_all_nodes_cool_gets_probe_lease(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a")],
            clock=clock,
            health_policy=HealthPolicy(cooldown_seconds=0.25, max_cooldown_seconds=1.0),
        )
        bad = await pool.acquire(RequestKind.RPC)
        await bad.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await bad.close()
        waiting = asyncio.create_task(pool.acquire(RequestKind.SEND, deadline=clock() + 1))
        await asyncio.sleep(0)
        clock.advance(0.25)
        await wake(pool)
        probe = await waiting
        self.assertIs(probe.kind, RequestKind.PROBE)
        self.assertTrue(probe.route.is_probe)
        await probe.observe(HealthObservation(HealthSignal.SUCCESS))
        await probe.close()

    async def test_weighted_selection_matches_configured_ratio(self) -> None:
        clock = FakeClock(0.0)
        pool = EndpointPool(
            [self.node("heavy", weight=3), self.node("light", weight=1)], clock=clock
        )
        selections: list[str] = []
        for _ in range(40):
            if selections:
                clock.advance(0.0001)
            lease = await pool.acquire(RequestKind.RPC)
            selections.append(lease.endpoint_id)
            await lease.close()
        self.assertEqual(selections.count("heavy"), 30)
        self.assertEqual(selections.count("light"), 10)

    async def test_health_cools_node_then_requires_a_successful_probe(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a"), self.node("b")],
            health_policy=HealthPolicy(cooldown_seconds=0.03, max_cooldown_seconds=0.1),
            clock=clock,
        )
        bad = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        await bad.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await bad.close()

        routed = await pool.acquire(RequestKind.RPC)
        self.assertEqual(routed.endpoint_id, "b")
        await routed.close()
        self.assertEqual(await pool.probe_due(), ())

        clock.advance(0.04)
        self.assertEqual(await pool.probe_due(), ("a",))
        probe = await pool.acquire(RequestKind.PROBE, endpoint_id="a")
        self.assertTrue(probe.route.is_probe)
        await probe.observe(HealthObservation(HealthSignal.SUCCESS, latency_seconds=0.001))
        await probe.close()

        clock.advance(0.0001)
        recovered = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        self.assertEqual(recovered.endpoint_id, "a")
        await recovered.close()

    async def test_retry_after_cools_endpoint_and_probe_failure_extends_cooldown(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a"), self.node("b")],
            health_policy=HealthPolicy(cooldown_seconds=0.01, max_cooldown_seconds=0.02),
            clock=clock,
        )
        lease = await pool.acquire(RequestKind.SEND, endpoint_id="a")
        await lease.observe(
            HealthObservation(HealthSignal.RATE_LIMITED, retry_after_seconds=0.04)
        )
        await lease.close()
        snapshot = {item.endpoint_id: item for item in await pool.snapshots()}["a"]
        self.assertGreaterEqual(snapshot.cooldown_until, clock() + 0.04)

        clock.advance(0.05)
        probe = await pool.acquire(RequestKind.PROBE, endpoint_id="a")
        await probe.observe(HealthObservation(HealthSignal.TIMEOUT))
        await probe.close()
        self.assertEqual(await pool.probe_due(), ())
        snapshot = {item.endpoint_id: item for item in await pool.snapshots()}["a"]
        self.assertGreater(snapshot.cooldown_until, clock())

    async def test_affinity_is_preferred_and_falls_back_when_node_is_cooling(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a"), self.node("b")],
            health_policy=HealthPolicy(cooldown_seconds=0.05, max_cooldown_seconds=0.1),
            clock=clock,
        )
        pool.remember_affinity("lane-1", "a")
        preferred = await pool.acquire(RequestKind.RPC, route_affinity="lane-1")
        self.assertEqual(preferred.endpoint_id, "a")
        await preferred.close()

        clock.advance(0.0001)
        unhealthy = await pool.acquire(RequestKind.RPC, endpoint_id="a")
        await unhealthy.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await unhealthy.close()
        fallback = await pool.acquire(RequestKind.RPC, route_affinity="lane-1")
        self.assertEqual(fallback.endpoint_id, "b")
        self.assertEqual(fallback.route.affinity_key, "lane-1")
        await fallback.close()

    async def test_m5_route_group_fails_within_group_then_over_to_pool(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a1", route_group="g"), self.node("a2", route_group="g"),
             self.node("b", route_group="other")],
            health_policy=HealthPolicy(cooldown_seconds=0.05, max_cooldown_seconds=0.1),
            clock=clock,
        )
        bad = await pool.acquire(RequestKind.RPC, endpoint_id="a1")
        await bad.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await bad.close()
        within = await pool.acquire(RequestKind.RPC, route_group="g")
        self.assertEqual(within.endpoint_id, "a2", "a cooling node fails over inside its group first")
        await within.close()

        clock.advance(0.0001)
        bad = await pool.acquire(RequestKind.RPC, endpoint_id="a2")
        await bad.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await bad.close()
        outside = await asyncio.wait_for(pool.acquire(RequestKind.RPC, route_group="g"), timeout=1)
        self.assertEqual(outside.endpoint_id, "b", "a fully cooling group fails over to the whole pool")
        await outside.close()

    async def test_abandoned_probe_does_not_rehabilitate_endpoint(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a")],
            health_policy=HealthPolicy(cooldown_seconds=0.01, max_cooldown_seconds=0.02),
            clock=clock,
        )
        lease = await pool.acquire(RequestKind.RPC)
        await lease.observe(HealthObservation(HealthSignal.UNHEALTHY))
        await lease.close()
        clock.advance(0.02)
        probe = await pool.acquire(RequestKind.PROBE)
        await probe.close()
        snapshot = (await pool.snapshots())[0]
        self.assertTrue(snapshot.probe_required)
        self.assertGreater(snapshot.cooldown_until, clock())

    async def test_concurrent_timeouts_extend_cooldown_without_bumping_backoff(self) -> None:
        clock = FakeClock()
        pool = EndpointPool(
            [self.node("a", max_in_flight=8)],
            health_policy=HealthPolicy(cooldown_seconds=0.1, max_cooldown_seconds=10),
            clock=clock,
        )
        leases = []
        for index in range(8):
            if index:
                clock.advance(0.0001)
            leases.append(await pool.acquire(RequestKind.RPC))
        await asyncio.gather(
            *(lease.observe(HealthObservation(HealthSignal.TIMEOUT)) for lease in leases)
        )
        await asyncio.gather(*(lease.close() for lease in leases))
        snapshot = (await pool.snapshots())[0]
        self.assertEqual(snapshot.cooldown_until, clock() + 0.1)

    async def test_affinity_entries_are_bounded(self) -> None:
        pool = EndpointPool([self.node("a"), self.node("b")], max_affinity_entries=2)
        pool.remember_affinity("old", "a")
        pool.remember_affinity("middle", "a")
        pool.remember_affinity("new", "b")
        self.assertEqual(len(pool._affinity), 2)
        self.assertNotIn("old", pool._affinity)


if __name__ == "__main__":
    unittest.main()
