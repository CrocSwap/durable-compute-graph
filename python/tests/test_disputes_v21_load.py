"""Frozen executor-phase deadlines, including the review's P1 and P2 probes."""

from dcg.disputes_v21.load import LoadClock


def test_expired_phase_stays_expired_after_later_open():
    for executor_first in (True, False):
        clock = LoadClock(750)
        expired = clock.begin_executor_wait(10)
        assert clock.timed_out(810, expired)
        if executor_first:
            clock.begin_executor_wait(810)
        else:
            clock.end_executor_wait()
            clock.begin_executor_wait(810)
        assert clock.timed_out(810, expired)


def test_puppets_cannot_bank_future_extension():
    for executor_first in (True, False):
        clock = LoadClock(750)
        if executor_first:
            clock.begin_executor_wait(0)
        for _ in range(2):
            clock.begin_executor_wait(0)
            clock.end_executor_wait()
        if executor_first:
            clock.end_executor_wait()
        assert clock.waiting_e == 0
        assert clock.begin_executor_wait(1) == 751


def test_cap_is_per_phase():
    clock = LoadClock(750, max_window=1_000)
    assert clock.begin_executor_wait(10) == 760
    assert clock.begin_executor_wait(11) == 1_011
    clock.end_executor_wait()
    clock.end_executor_wait()
    assert clock.begin_executor_wait(12) == 762
