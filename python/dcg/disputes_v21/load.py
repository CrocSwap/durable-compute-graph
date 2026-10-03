"""Tag-227 skeleton's additive executor-wait clock.

The bounded skeleton fixes c=1 and extend_slots=phase_window. Its run-level
extension is applied to executor phases only; challenger deadlines stay fixed.
"""

from dataclasses import dataclass


@dataclass
class LoadClock:
    phase_window: int
    waiting_e: int = 0
    extension_total: int = 0

    @staticmethod
    def _u64(value: int) -> int:
        if not 0 <= value <= (1 << 64) - 1:
            raise OverflowError("u64 load clock overflow")
        return value

    def begin_executor_wait(self, now: int) -> int:
        total = self._u64(self.extension_total + (self.phase_window if self.waiting_e >= 1 else 0))
        if self.waiting_e == (1 << 32) - 1:
            raise OverflowError("u32 executor wait overflow")
        deadline = self._u64(now + self.phase_window)
        self.extension_total = total
        self.waiting_e += 1
        return deadline

    def end_executor_wait(self) -> None:
        if self.waiting_e == 0:
            raise ValueError("no executor wait")
        self.waiting_e -= 1

    def deadline(self, base: int, *, executor_wait: bool) -> int:
        return self._u64(base + (self.extension_total if executor_wait else 0))

    @staticmethod
    def timed_out(now: int, deadline: int) -> bool:
        return now > deadline
