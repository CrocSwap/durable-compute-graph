"""Tag-227 skeleton's per-phase executor-wait clock."""

from dataclasses import dataclass


@dataclass
class LoadClock:
    phase_window: int
    waiting_e: int = 0
    max_window: int = 10_000_000

    @staticmethod
    def _u64(value: int) -> int:
        if not 0 <= value <= (1 << 64) - 1:
            raise OverflowError("u64 load clock overflow")
        return value

    def begin_executor_wait(self, now: int) -> int:
        if self.waiting_e == (1 << 32) - 1:
            raise OverflowError("u32 executor wait overflow")
        deadline = self._u64(now + min(self.phase_window * (1 + self.waiting_e), self.max_window))
        self.waiting_e += 1
        return deadline

    def end_executor_wait(self) -> None:
        if self.waiting_e == 0:
            raise ValueError("no executor wait")
        self.waiting_e -= 1

    @staticmethod
    def timed_out(now: int, deadline: int) -> bool:
        return now > deadline
