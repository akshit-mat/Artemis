"""Tool runtime — the only place a tool body is invoked.

``docs/tools.md`` §4/§5, ADR-008/ADR-009.

Structural guarantees:

* :meth:`ToolRuntime.execute` **cannot be called without an**
  :class:`~artemis.policy.engine.Authorization`, and it re-verifies that
  authorization against ``sha256(canonical_args)`` and the tool identity at the
  door before anything runs.
* ``INLINE`` awaits directly; ``THREAD`` runs in a bounded pool with cooperative
  cancellation; ``SUBPROCESS`` runs a short-lived child assigned to a Windows
  **Job Object** so timeout and cancel are *hard* — the whole process tree dies.
* Exceptions never reach the agent: they are normalised into a
  :class:`~artemis.tools.contract.ToolResult` with a stable ``error_code``.
* An audit-write failure aborts a side-effecting call.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Optional

from ..obs.audit import (
    EVENT_CANCELLED,
    EVENT_COMPLETED,
    EVENT_EXECUTION,
    EVENT_FAILED,
    AuditFailure,
    AuditRecord,
    AuditWriter,
    args_digest,
)
from ..obs.logging import get_logger
from ..policy.engine import Authorization, AuthorizationError, assert_matches
from .contract import (
    CONTEXT_VIEW_TOKEN_CAP,
    SUMMARY_CHAR_CAP,
    CancelToken,
    ToolCancelled,
    ToolContext,
    ToolResult,
    ToolSpec,
    canonical_args_json,
    canonical_hash,
)

log = get_logger("tools.runtime")

#: Bounded thread pool for the ``THREAD`` tier (``docs/tools.md`` §4).
THREAD_POOL_SIZE: int = 8

#: Grace period between a cooperative cancel and the hard tree-kill.
SUBPROCESS_KILL_GRACE_S: float = 0.5

_CREATE_NO_WINDOW = 0x08000000
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_BELOW_NORMAL_PRIORITY_CLASS = 0x00004000


def truncate_summary(text: str) -> str:
    text = " ".join((text or "").split())
    if len(text) <= SUMMARY_CHAR_CAP:
        return text
    return text[: SUMMARY_CHAR_CAP - 1] + "…"


def truncate_context_view(text: str, *, more_note: str | None = None) -> tuple[str, bool]:
    """Trim a context view to the documented token budget.

    Token counting uses the project's calibrated heuristic (``len/3.6``) so this
    stays consistent with the context assembler.
    """
    budget_chars = int(CONTEXT_VIEW_TOKEN_CAP * 3.6)
    if len(text) <= budget_chars:
        return text, False
    cut = text[:budget_chars].rstrip()
    suffix = f"\n…truncated. {more_note}" if more_note else "\n…truncated."
    return cut + suffix, True


# --------------------------------------------------------------------------
# Subprocess tier
# --------------------------------------------------------------------------


class JobObject:
    """Windows Job Object with ``KILL_ON_JOB_CLOSE`` so grandchildren die too."""

    def __init__(self) -> None:
        self._handle: Any = None
        if sys.platform != "win32":  # pragma: no cover - Windows-only product
            return
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        self._kernel32 = kernel32
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            log.warning("job_object_create_failed", error=ctypes.get_last_error())
            return
        self._handle = handle
        self._configure_kill_on_close()

    def _configure_kill_on_close(self) -> None:
        import ctypes
        from ctypes import wintypes

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
        JobObjectExtendedLimitInformation = 9

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        )
        info.BasicLimitInformation.ActiveProcessLimit = 4
        info.ProcessMemoryLimit = 512 * 1024 * 1024
        if not self._kernel32.SetInformationJobObject(
            self._handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):  # pragma: no cover - configuration failure path
            log.warning("job_object_configure_failed", error=ctypes.get_last_error())

    def assign(self, pid: int) -> bool:
        if self._handle is None:
            return False
        import ctypes
        from ctypes import wintypes

        PROCESS_SET_QUOTA = 0x0100
        PROCESS_TERMINATE = 0x0001
        proc = self._kernel32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, False, pid)
        if not proc:
            return False
        try:
            return bool(
                self._kernel32.AssignProcessToJobObject(self._handle, wintypes.HANDLE(proc))
            )
        finally:
            self._kernel32.CloseHandle(wintypes.HANDLE(proc))

    def terminate(self) -> None:
        """Kill every process in the job — the hard cancellation primitive."""
        if self._handle is None:
            return
        from ctypes import wintypes

        self._kernel32.TerminateJobObject(wintypes.HANDLE(self._handle), 1)

    def close(self) -> None:
        if self._handle is None:
            return
        from ctypes import wintypes

        self._kernel32.CloseHandle(wintypes.HANDLE(self._handle))
        self._handle = None


@dataclass(slots=True)
class SubprocessOutcome:
    status: str
    payload: dict[str, Any]
    error_code: Optional[str] = None
    stderr: str = ""


class SubprocessExecutor:
    """Runs a registered worker entry point in a hard-killable child process.

    The child receives only the worker name, the validated canonical arguments
    and the authorization *scope* — no token, no DB path, no config secrets
    (``docs/tools.md`` §4).
    """

    WORKER_MODULE = "artemis.tools.worker"

    def __init__(self, *, python: str | None = None) -> None:
        self.python = python or sys.executable

    def _command(self, worker: str) -> list[str]:
        override = os.environ.get("ARTEMIS_WORKER_CMD")
        if override:
            return [*override.split("\x1f"), worker]
        if getattr(sys, "frozen", False):  # pragma: no cover - packaged build
            return [self.python, "--tool-worker", worker]
        return [self.python, "-s", "-m", self.WORKER_MODULE, worker]

    @staticmethod
    def _worker_pythonpath() -> str:
        entries = [entry for entry in sys.path if entry]
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        backend_root = os.path.dirname(package_root)
        for candidate in (backend_root, package_root):
            if candidate not in entries:
                entries.insert(0, candidate)
        return os.pathsep.join(entries)

    async def run(
        self,
        *,
        worker: str,
        payload: dict[str, Any],
        timeout_s: float,
        cancel_token: CancelToken,
    ) -> SubprocessOutcome:
        job = JobObject()
        creationflags = 0
        if sys.platform == "win32":
            creationflags = (
                _CREATE_NO_WINDOW | _BELOW_NORMAL_PRIORITY_CLASS | _CREATE_BREAKAWAY_FROM_JOB
            )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "PYTHONPATH": self._worker_pythonpath(),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "USERPROFILE": os.environ.get("USERPROFILE", ""),
            "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", ""),
            "APPDATA": os.environ.get("APPDATA", ""),
            "PUBLIC": os.environ.get("PUBLIC", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "ARTEMIS_WORKER": "1",
        }
        # The self-test worker gate is forwarded only when this process already
        # has it set.  ARTEMIS never sets it; the runtime cancellation tests do.
        if os.environ.get("ARTEMIS_SELFTEST") == "1":
            env["ARTEMIS_SELFTEST"] = "1"
        command = self._command(worker)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creationflags,
                env=env,
            )
        except OSError as exc:
            job.close()
            return SubprocessOutcome("error", {}, error_code="WORKER_SPAWN_FAILED", stderr=str(exc))

        assigned = job.assign(process.pid)

        def hard_kill() -> None:
            if assigned:
                job.terminate()
            else:  # pragma: no cover - job assignment failure fallback
                with contextlib.suppress(ProcessLookupError):
                    process.kill()

        cancel_token.on_cancel(hard_kill)

        message = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(message), timeout=timeout_s
            )
        except asyncio.TimeoutError:
            hard_kill()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(process.wait(), timeout=SUBPROCESS_KILL_GRACE_S)
            if process.returncode is None:  # pragma: no cover - belt and braces
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
            job.close()
            return SubprocessOutcome("timeout", {}, error_code="TOOL_TIMEOUT")
        except asyncio.CancelledError:
            hard_kill()
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(process.wait(), timeout=SUBPROCESS_KILL_GRACE_S)
            job.close()
            raise
        finally:
            job_closed = False
            if process.returncode is not None:
                job.close()
                job_closed = True
            if not job_closed and cancel_token.cancelled:
                job.close()

        if cancel_token.cancelled:
            job.close()
            return SubprocessOutcome("cancelled", {}, error_code="CANCELLED")

        text = (stdout or b"").decode("utf-8", "replace").strip()
        err_text = (stderr or b"").decode("utf-8", "replace").strip()[:2000]
        if process.returncode != 0 or not text:
            log.error(
                "worker_crashed",
                worker=worker,
                returncode=process.returncode,
                stderr=err_text[:500],
            )
            return SubprocessOutcome("error", {}, error_code="WORKER_CRASH", stderr=err_text)
        try:
            parsed = json.loads(text.splitlines()[-1])
        except json.JSONDecodeError:
            return SubprocessOutcome("error", {}, error_code="WORKER_PROTOCOL", stderr=err_text)
        if not isinstance(parsed, dict):
            return SubprocessOutcome("error", {}, error_code="WORKER_PROTOCOL", stderr=err_text)
        if parsed.get("ok") is not True:
            return SubprocessOutcome(
                "error",
                parsed.get("data") or {},
                error_code=str(parsed.get("error_code") or "TOOL_ERROR"),
                stderr=str(parsed.get("message") or "")[:500],
            )
        return SubprocessOutcome("ok", parsed.get("data") or {}, stderr=err_text)


# --------------------------------------------------------------------------
# Runtime
# --------------------------------------------------------------------------


class ToolRuntime:
    """Executes a tool under an Authorization, with real timeouts and cancel."""

    def __init__(
        self,
        *,
        audit: AuditWriter | None = None,
        result_store: Any = None,
        thread_pool_size: int = THREAD_POOL_SIZE,
    ) -> None:
        self.audit = audit
        self.result_store = result_store
        self._pool = ThreadPoolExecutor(
            max_workers=thread_pool_size, thread_name_prefix="artemis-tool"
        )
        self.subprocess = SubprocessExecutor()

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    async def execute(
        self,
        spec: ToolSpec,
        args: Any,
        auth: Authorization,
        ctx: ToolContext,
    ) -> ToolResult:
        """Run a tool.  Requires a matching Authorization; fails closed."""
        started = time.perf_counter()
        canonical = canonical_args_json(args)
        digest = args_digest(canonical, redact=("content",))

        # -- the door: re-verify the authorization against these exact args --
        try:
            assert_matches(auth, spec.name, canonical_hash(args), run_id=ctx.run_id)
        except AuthorizationError as exc:
            log.error("authorization_rejected", tool=spec.name, code=str(exc))
            await self._audit(
                AuditRecord(
                    event=EVENT_FAILED,
                    actor="system",
                    run_id=ctx.run_id,
                    tool_name=spec.name,
                    args_digest=digest,
                    decision="DENY",
                    rule_id="runtime.authorization",
                    reason=str(exc),
                    error_code=str(exc),
                    taint=ctx.taint,
                ),
                required=False,
            )
            return ToolResult(
                status="denied",
                summary="Blocked: the authorization did not match this operation.",
                error_code=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        # -- audit before executing; a side effect must not run unaudited ----
        try:
            await self._audit(
                AuditRecord(
                    event=EVENT_EXECUTION,
                    actor="model",
                    run_id=ctx.run_id,
                    tool_name=spec.name,
                    args_digest=digest,
                    resolved_target=auth.resolved_targets[0] if auth.resolved_targets else None,
                    decision=auth.decision.value,
                    rule_id=auth.rule_id,
                    approval_id=auth.approval_id,
                    taint=ctx.taint,
                ),
                required=spec.side_effects,
            )
        except AuditFailure as exc:
            log.error("audit_failure_aborting_tool", tool=spec.name, error=str(exc))
            return ToolResult(
                status="error",
                summary="Blocked: the action could not be recorded in the audit log.",
                error_code="AUDIT_UNAVAILABLE",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        result = await self._dispatch(spec, args, ctx)
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        # ``produces_untrusted_content`` forces UNTRUSTED; a tool may *also*
        # declare UNTRUSTED on its own (``read_more`` inherits its source's
        # trust).  There is deliberately no path that downgrades UNTRUSTED to
        # SYSTEM: that would weaken taint.
        if spec.produces_untrusted_content and result.status == "ok":
            result.trust = "UNTRUSTED"
        result.summary = truncate_summary(result.summary)

        if not result.result_id:
            result.result_id = f"res_{uuid.uuid4().hex[:12]}"
        if self.result_store is not None:
            with contextlib.suppress(Exception):
                await self.result_store.save(result, spec=spec, ctx=ctx)

        event = {
            "ok": EVENT_COMPLETED,
            "cancelled": EVENT_CANCELLED,
        }.get(result.status, EVENT_FAILED)
        await self._audit(
            AuditRecord(
                event=event,
                actor="model",
                run_id=ctx.run_id,
                tool_name=spec.name,
                args_digest=digest,
                resolved_target=auth.resolved_targets[0] if auth.resolved_targets else None,
                decision=auth.decision.value,
                rule_id=auth.rule_id,
                approval_id=auth.approval_id,
                outcome=result.status,
                duration_ms=result.duration_ms,
                error_code=result.error_code,
                taint=ctx.taint,
            ),
            required=False,
        )
        return result

    # -- tiers ---------------------------------------------------------------

    async def _dispatch(self, spec: ToolSpec, args: Any, ctx: ToolContext) -> ToolResult:
        try:
            if ctx.cancel_token.cancelled:
                return ToolResult(
                    status="cancelled",
                    summary="Cancelled before the tool started.",
                    error_code="CANCELLED",
                )
            coro = self._run_tier(spec, args, ctx)
            return await asyncio.wait_for(coro, timeout=spec.timeout_s)
        except asyncio.TimeoutError:
            ctx.cancel_token.cancel()
            log.warning("tool_timeout", tool=spec.name, timeout_s=spec.timeout_s)
            return ToolResult(
                status="timeout",
                summary=f"The tool exceeded its {spec.timeout_s:g}s limit and was stopped.",
                error_code="TOOL_TIMEOUT",
            )
        except (ToolCancelled, asyncio.CancelledError):
            ctx.cancel_token.cancel()
            return ToolResult(
                status="cancelled",
                summary="Cancelled. Any work already committed is reported as completed.",
                error_code="CANCELLED",
            )
        except Exception as exc:  # noqa: BLE001 - tools never raise to the agent
            log.error("tool_exception", tool=spec.name, error=str(exc), exc_info=True)
            return ToolResult(
                status="error",
                summary="The tool failed. See the ARTEMIS log for details.",
                error_code="TOOL_ERROR",
            )

    async def _run_tier(self, spec: ToolSpec, args: Any, ctx: ToolContext) -> ToolResult:
        if spec.tier.value == "INLINE":
            return await spec.execute(args, ctx)
        if spec.tier.value == "THREAD":
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                self._pool, lambda: asyncio.run(_isolated(spec, args, ctx))
            )
        # SUBPROCESS: the tool body itself decides what to hand the worker.
        return await spec.execute(args, ctx)

    # -- audit ---------------------------------------------------------------

    async def _audit(self, record: AuditRecord, *, required: bool) -> None:
        if self.audit is None:
            return
        await self.audit.record(record, required=required)


async def _isolated(spec: ToolSpec, args: Any, ctx: ToolContext) -> ToolResult:
    """Run a THREAD-tier coroutine on its own loop inside the worker thread."""
    return await spec.execute(args, ctx)


#: Shared executor used by ``SUBPROCESS``-tier tool bodies.  One instance so the
#: process-spawn policy (Job Object, no window, below-normal priority, minimal
#: environment) is defined in exactly one place.
SUBPROCESS_EXECUTOR = SubprocessExecutor()


async def run_worker(
    *,
    worker: str,
    payload: dict[str, Any],
    timeout_s: float,
    cancel_token: CancelToken,
) -> SubprocessOutcome:
    """Entry point for ``SUBPROCESS``-tier tools."""
    return await SUBPROCESS_EXECUTOR.run(
        worker=worker, payload=payload, timeout_s=timeout_s, cancel_token=cancel_token
    )


__all__ = [
    "JobObject",
    "SUBPROCESS_EXECUTOR",
    "SUBPROCESS_KILL_GRACE_S",
    "SubprocessExecutor",
    "SubprocessOutcome",
    "THREAD_POOL_SIZE",
    "ToolRuntime",
    "run_worker",
    "truncate_context_view",
    "truncate_summary",
]
