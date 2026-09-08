"""Read-only system tools (``docs/tools.md`` §6 "System", roadmap Phase 4).

All ``READ_ONLY / ALLOW``, ``INLINE`` or ``THREAD``.  Values come from the 1 Hz
sampler cache, not a fresh poll per call, so a chatty model cannot turn telemetry
into load.  These tools exist to prove the whole pipeline end to end: proposal →
validation → policy → authorization → runtime → result → UI.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..contract import (
    Decision,
    ExecTier,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolResult,
    ToolSpec,
)
from ..telemetry import disk_usage, sampler, system_info


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GetTimeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    utc: bool = Field(default=False, description="Return UTC instead of local time.")


class TimeResult(BaseModel):
    iso: str
    local: str
    timezone_name: str
    unix: float


class SystemInfoResult(BaseModel):
    model_config = ConfigDict(extra="allow")


class CpuResult(BaseModel):
    cpu_pct: float
    cpu_count_logical: int


class MemoryResult(BaseModel):
    ram_used_mb: int
    ram_total_mb: int
    used_pct: float


class GpuResult(BaseModel):
    gpu_pct: float | None = None
    vram_used_mb: int | None = None
    vram_total_mb: int | None = None


class BatteryResult(BaseModel):
    battery_pct: float | None = None
    on_ac: bool | None = None


class DiskResult(BaseModel):
    volumes: list[dict[str, Any]]


def _ok(summary: str, data: dict[str, Any], view: str) -> ToolResult:
    return ToolResult(status="ok", summary=summary, data=data, context_view=view, trust="SYSTEM")


async def _get_time(args: GetTimeArgs, _ctx: ToolContext) -> ToolResult:
    now_utc = datetime.now(timezone.utc)
    local = now_utc.astimezone()
    chosen = now_utc if args.utc else local
    data = {
        "iso": chosen.isoformat(timespec="seconds"),
        "local": local.strftime("%Y-%m-%d %H:%M:%S"),
        "timezone_name": str(local.tzname() or "local"),
        "unix": time.time(),
    }
    return _ok(f"It is {data['local']} ({data['timezone_name']}).", data, data["iso"])


async def _get_system_info(_args: NoArgs, _ctx: ToolContext) -> ToolResult:
    info = system_info()
    view = ", ".join(f"{key}={value}" for key, value in info.items())
    return _ok(f"{info.get('os', 'Windows')} on {info.get('machine', 'x86_64')}.", info, view)


async def _get_cpu_usage(_args: NoArgs, _ctx: ToolContext) -> ToolResult:
    sample = sampler.snapshot()
    info = system_info()
    data = {
        "cpu_pct": round(sample.cpu_pct, 1),
        "cpu_count_logical": int(info.get("cpu_count_logical") or 0),
    }
    return _ok(f"CPU usage is {data['cpu_pct']}%.", data, f"cpu_pct={data['cpu_pct']}")


async def _get_memory_usage(_args: NoArgs, _ctx: ToolContext) -> ToolResult:
    sample = sampler.snapshot()
    total = sample.ram_total_mb or 1
    data = {
        "ram_used_mb": sample.ram_used_mb,
        "ram_total_mb": sample.ram_total_mb,
        "used_pct": round(sample.ram_used_mb / total * 100, 1),
    }
    return _ok(
        f"RAM in use: {sample.ram_used_mb} MB of {sample.ram_total_mb} MB "
        f"({data['used_pct']}%).",
        data,
        f"ram_used_mb={sample.ram_used_mb} ram_total_mb={sample.ram_total_mb}",
    )


async def _get_gpu_usage(_args: NoArgs, _ctx: ToolContext) -> ToolResult:
    sample = sampler.snapshot()
    if sample.gpu_pct is None:
        return ToolResult(
            status="unavailable",
            summary="No supported GPU telemetry source is available on this machine.",
            error_code="CAPABILITY_MISSING",
        )
    data = {
        "gpu_pct": round(sample.gpu_pct, 1),
        "vram_used_mb": sample.vram_used_mb,
        "vram_total_mb": sample.vram_total_mb,
    }
    return _ok(
        f"GPU usage is {data['gpu_pct']}%, VRAM {sample.vram_used_mb}/"
        f"{sample.vram_total_mb} MB.",
        data,
        f"gpu_pct={data['gpu_pct']} vram_used_mb={sample.vram_used_mb}",
    )


async def _get_battery(_args: NoArgs, _ctx: ToolContext) -> ToolResult:
    sample = sampler.snapshot()
    if sample.battery_pct is None:
        return ToolResult(
            status="unavailable",
            summary="This machine reports no battery.",
            error_code="CAPABILITY_MISSING",
        )
    data = {"battery_pct": sample.battery_pct, "on_ac": sample.on_ac}
    state = "on AC power" if sample.on_ac else "on battery"
    return _ok(
        f"Battery at {sample.battery_pct:.0f}%, {state}.",
        data,
        f"battery_pct={sample.battery_pct} on_ac={sample.on_ac}",
    )


async def _get_disk_usage(_args: NoArgs, _ctx: ToolContext) -> ToolResult:
    volumes = disk_usage()
    view = "; ".join(
        f"{item['volume']} {item['free_gb']} GB free of {item['total_gb']} GB"
        for item in volumes
    )
    summary = view.split(";")[0] if volumes else "No local volumes reported."
    return _ok(summary, {"volumes": volumes}, view)


GET_TIME = ToolSpec(
    name="get_time",
    summary="Get the current date and time.",
    args_model=GetTimeArgs,
    returns_model=TimeResult,
    category=ToolCategory.SYSTEM,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.INLINE,
    timeout_s=2.0,
    default_decision=Decision.ALLOW,
    execute=_get_time,
)

GET_SYSTEM_INFO = ToolSpec(
    name="get_system_info",
    summary="Get static information about this computer (OS, CPU model, total RAM).",
    args_model=NoArgs,
    returns_model=SystemInfoResult,
    category=ToolCategory.SYSTEM,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.THREAD,
    timeout_s=5.0,
    default_decision=Decision.ALLOW,
    execute=_get_system_info,
)

GET_CPU_USAGE = ToolSpec(
    name="get_cpu_usage",
    summary="Get current CPU utilisation as a percentage.",
    args_model=NoArgs,
    returns_model=CpuResult,
    category=ToolCategory.SYSTEM,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.INLINE,
    timeout_s=2.0,
    default_decision=Decision.ALLOW,
    execute=_get_cpu_usage,
)

GET_MEMORY_USAGE = ToolSpec(
    name="get_memory_usage",
    summary="Get current RAM usage.",
    args_model=NoArgs,
    returns_model=MemoryResult,
    category=ToolCategory.SYSTEM,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.INLINE,
    timeout_s=2.0,
    default_decision=Decision.ALLOW,
    execute=_get_memory_usage,
)

GET_GPU_USAGE = ToolSpec(
    name="get_gpu_usage",
    summary="Get current GPU and VRAM usage.",
    args_model=NoArgs,
    returns_model=GpuResult,
    category=ToolCategory.SYSTEM,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.INLINE,
    timeout_s=3.0,
    default_decision=Decision.ALLOW,
    execute=_get_gpu_usage,
    requires=frozenset({"gpu"}),
)

GET_BATTERY = ToolSpec(
    name="get_battery",
    summary="Get battery charge level and whether the machine is on AC power.",
    args_model=NoArgs,
    returns_model=BatteryResult,
    category=ToolCategory.SYSTEM,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.INLINE,
    timeout_s=2.0,
    default_decision=Decision.ALLOW,
    execute=_get_battery,
)

GET_DISK_USAGE = ToolSpec(
    name="get_disk_usage",
    summary="Get free and used space for the local drives.",
    args_model=NoArgs,
    returns_model=DiskResult,
    category=ToolCategory.SYSTEM,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.THREAD,
    timeout_s=5.0,
    default_decision=Decision.ALLOW,
    execute=_get_disk_usage,
)

SYSTEM_TOOLS: tuple[ToolSpec, ...] = (
    GET_TIME,
    GET_SYSTEM_INFO,
    GET_CPU_USAGE,
    GET_MEMORY_USAGE,
    GET_GPU_USAGE,
    GET_BATTERY,
    GET_DISK_USAGE,
)

__all__ = ["SYSTEM_TOOLS"]
