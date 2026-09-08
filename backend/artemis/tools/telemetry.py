"""1 Hz telemetry sampler.

``docs/roadmap.md`` Phase 4: the system tools read from a sampler cache, not a
fresh poll per call.  ``docs/api.md`` §4: ``telemetry.sample`` is emitted at most
1 Hz and **only while subscribed**, so an unsubscribed idle app does no periodic
work at all (``docs/ui.md`` §4 telemetry store lifecycle).

The sampler therefore has two modes:

* *lazy* — ``snapshot()`` refreshes the cache only when it is older than the
  sample interval.  This is what the read-only tools use.
* *streaming* — ``start()``/``stop()`` runs a single asyncio task that publishes
  samples while at least one subscriber is present.  There is no busy loop and
  no thread.

GPU/VRAM come from ``nvidia-smi`` when present; the sampler never assumes a GPU
and never launches anything the model chose (the argv is a constant here).
"""

from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from ..obs.logging import get_logger

log = get_logger("tools.telemetry")

SAMPLE_INTERVAL_S: float = 1.0
_NVIDIA_TIMEOUT_S: float = 1.5
_CREATE_NO_WINDOW = 0x08000000


@dataclass(slots=True)
class TelemetrySample:
    ts: float = 0.0
    cpu_pct: float = 0.0
    ram_used_mb: int = 0
    ram_total_mb: int = 0
    gpu_pct: Optional[float] = None
    vram_used_mb: Optional[int] = None
    vram_total_mb: Optional[int] = None
    battery_pct: Optional[float] = None
    on_ac: Optional[bool] = None

    def to_event(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("ts", None)
        return payload


class TelemetrySampler:
    """Cached sampler shared by the tools and the ``telemetry.sample`` stream."""

    def __init__(self, *, interval_s: float = SAMPLE_INTERVAL_S) -> None:
        self.interval_s = interval_s
        self._sample = TelemetrySample()
        self._gpu_available: bool | None = None
        self._task: asyncio.Task[None] | None = None
        self._subscribers = 0
        self._publish: Callable[[TelemetrySample], None] | None = None
        self._cpu_primed = False

    # -- sampling ------------------------------------------------------------

    def snapshot(self, *, force: bool = False) -> TelemetrySample:
        now = time.monotonic()
        if not force and self._sample.ts and (now - self._sample.ts) < self.interval_s:
            return self._sample
        self._sample = self._collect(now)
        return self._sample

    def _collect(self, now: float) -> TelemetrySample:
        sample = TelemetrySample(ts=now)
        try:
            import psutil

            if not self._cpu_primed:
                psutil.cpu_percent(interval=None)  # prime the delta
                self._cpu_primed = True
            sample.cpu_pct = float(psutil.cpu_percent(interval=None))
            memory = psutil.virtual_memory()
            sample.ram_used_mb = int((memory.total - memory.available) / 1024 / 1024)
            sample.ram_total_mb = int(memory.total / 1024 / 1024)
            battery = psutil.sensors_battery()
            if battery is not None:
                sample.battery_pct = float(battery.percent)
                sample.on_ac = bool(battery.power_plugged)
        except Exception as exc:  # pragma: no cover - psutil is a dependency
            log.warning("telemetry_psutil_failed", error=str(exc))

        gpu = self._collect_gpu()
        if gpu is not None:
            sample.gpu_pct, sample.vram_used_mb, sample.vram_total_mb = gpu
        return sample

    def _collect_gpu(self) -> tuple[float, int, int] | None:
        if self._gpu_available is False:
            return None
        executable = shutil.which("nvidia-smi")
        if executable is None:
            self._gpu_available = False
            return None
        try:
            completed = subprocess.run(  # noqa: S603 - constant argv, shell=False
                [
                    executable,
                    "--query-gpu=utilization.gpu,memory.used,memory.total",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=_NVIDIA_TIMEOUT_S,
                shell=False,
                creationflags=_CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
        except (OSError, subprocess.SubprocessError):
            self._gpu_available = False
            return None
        if completed.returncode != 0 or not completed.stdout.strip():
            self._gpu_available = False
            return None
        first = completed.stdout.strip().splitlines()[0]
        parts = [part.strip() for part in first.split(",")]
        if len(parts) < 3:
            self._gpu_available = False
            return None
        try:
            self._gpu_available = True
            return float(parts[0]), int(float(parts[1])), int(float(parts[2]))
        except ValueError:
            self._gpu_available = False
            return None

    # -- streaming -----------------------------------------------------------

    def configure(self, publish: Callable[[TelemetrySample], None]) -> None:
        self._publish = publish

    def subscribe(self, *, hz: float = 1.0) -> None:
        self.interval_s = max(SAMPLE_INTERVAL_S, 1.0 / max(hz, 0.01))
        self._subscribers += 1
        self._ensure_task()

    def unsubscribe(self) -> None:
        self._subscribers = max(0, self._subscribers - 1)
        if self._subscribers == 0:
            self.stop()

    def _ensure_task(self) -> None:
        if self._task is not None and not self._task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # pragma: no cover - no loop in sync tests
            return
        self._task = loop.create_task(self._loop())

    async def _loop(self) -> None:
        try:
            while self._subscribers > 0:
                sample = self.snapshot(force=True)
                if self._publish is not None:
                    self._publish(sample)
                await asyncio.sleep(self.interval_s)
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise
        except Exception as exc:  # pragma: no cover - defensive
            log.error("telemetry_loop_failed", error=str(exc))

    def stop(self) -> None:
        self._subscribers = 0
        if self._task is not None:
            self._task.cancel()
            self._task = None

    @property
    def streaming(self) -> bool:
        return self._task is not None and not self._task.done()


def system_info() -> dict[str, Any]:
    """Static host facts.  No command execution, no network."""
    info: dict[str, Any] = {
        "os": f"{platform.system()} {platform.release()}",
        "os_version": platform.version(),
        "machine": platform.machine(),
        "hostname": platform.node(),
        "python": platform.python_version(),
        "cpu_count_logical": os.cpu_count() or 0,
    }
    try:
        import psutil

        info["cpu_count_physical"] = psutil.cpu_count(logical=False) or info["cpu_count_logical"]
        info["ram_total_mb"] = int(psutil.virtual_memory().total / 1024 / 1024)
        info["boot_time"] = float(psutil.boot_time())
    except Exception:  # pragma: no cover - psutil is a dependency
        pass
    processor = platform.processor()
    if processor:
        info["cpu"] = processor
    return info


def disk_usage(paths: list[str] | None = None) -> list[dict[str, Any]]:
    """Usage for fixed local volumes.  Read-only, no path from the model."""
    results: list[dict[str, Any]] = []
    candidates: list[str]
    if paths:
        candidates = paths
    else:
        candidates = []
        try:
            import psutil

            for partition in psutil.disk_partitions(all=False):
                if "cdrom" in partition.opts or not partition.fstype:
                    continue
                candidates.append(partition.mountpoint)
        except Exception:  # pragma: no cover - psutil is a dependency
            candidates = [os.environ.get("SystemDrive", "C:") + "\\"]
    for mount in candidates:
        try:
            usage = shutil.disk_usage(mount)
        except OSError:
            continue
        results.append(
            {
                "volume": mount,
                "total_gb": round(usage.total / 1024**3, 2),
                "used_gb": round(usage.used / 1024**3, 2),
                "free_gb": round(usage.free / 1024**3, 2),
                "used_pct": round(usage.used / usage.total * 100, 1) if usage.total else 0.0,
            }
        )
    return results


#: Process-wide sampler.
sampler = TelemetrySampler()

__all__ = [
    "SAMPLE_INTERVAL_S",
    "TelemetrySample",
    "TelemetrySampler",
    "disk_usage",
    "sampler",
    "system_info",
]
