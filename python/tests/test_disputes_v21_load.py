"""Executor-wait extension and challenger puppet controls."""

from dcg.disputes_v21.load import LoadClock


def test_additive_waits_and_challenger_puppets():
    for executor_first in (True, False):
        clock = LoadClock(750)
        challenger_base = 1750
        if executor_first:
            first_e = clock.begin_executor_wait(1000)
            clock.end_executor_wait()
        # Opening another dispute while the puppet waits on its challenger
        # must not bank a slot of extension.
        second_e = clock.begin_executor_wait(1001)
        assert clock.extension_total == 0
        if not executor_first:
            first_e = clock.begin_executor_wait(1002)
        else:
            first_e = clock.begin_executor_wait(1002)
        assert clock.extension_total == 750
        assert clock.deadline(challenger_base, executor_wait=False) == challenger_base
        assert clock.deadline(second_e, executor_wait=True) == second_e + 750
        assert not clock.timed_out(second_e + 750, clock.deadline(second_e, executor_wait=True))
        assert clock.timed_out(second_e + 751, clock.deadline(second_e, executor_wait=True))
        clock.end_executor_wait()
        clock.end_executor_wait()
        assert clock.waiting_e == 0
        assert first_e >= 1750
