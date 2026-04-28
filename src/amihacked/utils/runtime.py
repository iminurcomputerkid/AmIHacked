from contextlib import contextmanager
from dataclasses import dataclass, field
from time import perf_counter
from typing import Iterator

from amihacked.utils.time import utc_now_iso


@dataclass
class StageTiming:
    name: str
    started_at: str
    ended_at: str | None = None
    elapsed_seconds: float = 0.0
    artifacts: int | None = None
    notes: str | None = None

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "artifacts": self.artifacts,
            "notes": self.notes,
        }


@dataclass
class ScanRuntime:
    started_at: str = field(default_factory=utc_now_iso)
    _started_perf: float = field(default_factory=perf_counter)
    stages: list[StageTiming] = field(default_factory=list)

    @contextmanager
    def stage(self, name: str, notes: str | None = None) -> Iterator[StageTiming]:
        timing = StageTiming(name=name, started_at=utc_now_iso(), notes=notes)
        start = perf_counter()
        try:
            yield timing
        finally:
            timing.ended_at = utc_now_iso()
            timing.elapsed_seconds = perf_counter() - start
            self.stages.append(timing)

    def elapsed_seconds(self) -> float:
        return perf_counter() - self._started_perf

    def as_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "elapsed_seconds": round(self.elapsed_seconds(), 3),
            "stages": [stage.as_dict() for stage in self.stages],
        }


def format_duration(seconds: float) -> str:
    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"

