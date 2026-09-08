"""Tool mediator — the single path from a model proposal to an executed tool.

This is where ``docs/tools.md`` §7, ``docs/agent.md`` §2 and ``docs/security.md``
§3/§4 meet.  The order is fixed and there is no other way in:

    proposal → registry lookup → schema validation → path canonicalization
      → policy evaluation → (approval) → Authorization mint → runtime
      → result → taint update → audit → events

Only the *backend* participates in the authority steps.  The frontend can reach
this class in exactly one way — by answering an ``approval.requested`` event with
the server-issued ``approval_id`` — and even then the decision is re-evaluated
and the Authorization is minted here, never supplied by the caller.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from pydantic import ValidationError

from ..obs.audit import (
    EVENT_APPROVAL_REQUESTED,
    EVENT_APPROVAL_RESOLVED,
    EVENT_DECISION,
    EVENT_DENIED,
    EVENT_FS_MUTATION,
    EVENT_GRANT_CREATED,
    EVENT_PROPOSAL,
    EVENT_TAINT_DOWNGRADE,
    AuditRecord,
    AuditWriter,
    args_digest,
)
from ..obs.logging import get_logger
from ..policy.approvals import (
    ApprovalError,
    ApprovalManager,
    scope_options_for,
    scope_to_ttl,
)
from ..policy.engine import (
    Authorization,
    AuthorizationError,
    PolicyDecision,
    PolicyEngine,
    PolicyRequest,
)
from ..policy.fsconfig import FilesystemScope
from ..policy.grants import GrantScope
from ..policy.paths import CanonicalPath, PathRejected
from ..policy.store import PolicyStore, RuleRejected
from ..policy.taint import taint_tracker
from ..tools.contract import (
    ActionPreview,
    CancelToken,
    Decision,
    ResolvedContext,
    RiskLevel,
    ToolContext,
    ToolResult,
    ToolSpec,
    canonical_args_json,
    canonical_hash,
)
from ..tools.registry import REGISTRY, ToolNotFound, ToolRegistry
from ..tools.runtime import ToolRuntime

log = get_logger("agent.tools")


class ToolProposalError(Exception):
    """A proposal that cannot become a call.  Always produces a safe result."""

    def __init__(self, code: str, message: str, *, repairable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.repairable = repairable


@dataclass(slots=True)
class ToolOutcome:
    """What the agent loop needs to know about one tool step."""

    call_id: str
    tool_name: str
    decision: Decision
    rule_id: str
    reason: str
    result: ToolResult
    side_effect: bool = False
    args_hash: str = ""
    approval_id: Optional[str] = None
    tainted_result: bool = False


class ToolMediator:
    """Owns the authority pipeline for one backend process."""

    def __init__(
        self,
        *,
        engine: PolicyEngine,
        runtime: ToolRuntime,
        approvals: ApprovalManager,
        audit: AuditWriter | None,
        store: PolicyStore | None,
        fs_scope: FilesystemScope,
        registry: ToolRegistry | None = None,
        publish: Any = None,
    ) -> None:
        self.engine = engine
        self.runtime = runtime
        self.approvals = approvals
        self.audit = audit
        self.store = store
        self.fs_scope = fs_scope
        self.registry = registry or REGISTRY
        self._publish = publish

    # -- events ---------------------------------------------------------------

    def _emit(self, event_type: str, data: dict[str, Any], session_id: str, run_id: str) -> None:
        if self._publish is None:
            return
        self._publish(event_type, data, session_id, run_id)

    async def _audit(self, record: AuditRecord, *, required: bool = False) -> None:
        if self.audit is None:
            return
        try:
            await self.audit.record(record, required=required)
        except Exception as exc:  # noqa: BLE001 - required=False never raises
            log.error("audit_record_failed", event=record.event, error=str(exc))

    # -- policy inputs --------------------------------------------------------

    async def refresh_policy(self) -> None:
        """Reload rules and grants from the database (fail-open to no grants)."""
        if self.store is None:
            return
        try:
            self.engine.rules = await self.store.load_rules()
        except Exception as exc:  # noqa: BLE001 - unreadable rules must not crash
            log.error("policy_rules_unreadable", error=str(exc))
            self.engine.rules = {}
        try:
            self.engine.grants = await self.store.load_grants()
        except Exception as exc:  # noqa: BLE001 - "treat as no grants"
            log.error("policy_grants_unreadable", error=str(exc))
            self.engine.grants = []

    def effective_decisions(self, *, session_id: str, tainted: bool) -> dict[str, Decision]:
        """Decision per tool for ``GET /v1/tools`` and schema visibility."""
        decisions: dict[str, Decision] = {}
        for spec in self.registry:
            request = PolicyRequest(
                spec=spec,
                args=_placeholder_args(spec),
                run_id="r_probe",
                session_id=session_id,
                tainted=tainted,
                paths=(),
                item_count=1,
            )
            if spec.requires_paths:
                # A pathless probe cannot be evaluated for a path tool; report
                # the clamped default so visibility is honest without pretending
                # to have resolved a target.
                from ..policy.baseline import baseline_ceiling
                from ..tools.contract import decision_min

                ceiling, _rule, _reason = baseline_ceiling(
                    tool_name=spec.name, risk=spec.risk, destructive=spec.destructive
                )
                decisions[spec.name] = decision_min(ceiling, spec.default_decision)
                continue
            decisions[spec.name] = self.engine.evaluate(request).decision
        return decisions

    # -- the pipeline ---------------------------------------------------------

    async def handle_proposal(
        self,
        *,
        tool_name: str,
        raw_args: dict[str, Any],
        run_id: str,
        session_id: str,
        user_turn_text: str,
        model_rationale: str = "",
        side_effect_budget_exceeded: bool = False,
        cancel_token: CancelToken | None = None,
        call_id: str | None = None,
    ) -> ToolOutcome:
        """Validate, authorize and execute one proposed call."""
        call_id = call_id or f"tc_{uuid.uuid4().hex[:12]}"
        cancel_token = cancel_token or CancelToken()
        tainted = taint_tracker.is_tainted(run_id)

        # 1. Registry lookup — an unknown tool is a denial, never an execution.
        spec = self.registry.try_get(tool_name)
        if spec is None:
            return await self._deny_proposal(
                call_id=call_id,
                tool_name=tool_name,
                run_id=run_id,
                session_id=session_id,
                code="UNKNOWN_TOOL",
                reason=f"There is no tool called '{tool_name}'.",
                tainted=tainted,
                repairable=True,
            )
        if not self.registry.is_available(spec):
            missing = ", ".join(sorted(self.registry.missing_capabilities(spec)))
            return await self._deny_proposal(
                call_id=call_id,
                tool_name=tool_name,
                run_id=run_id,
                session_id=session_id,
                code="CAPABILITY_MISSING",
                reason=f"'{tool_name}' is unavailable on this machine (needs {missing}).",
                tainted=tainted,
                status="unavailable",
            )

        # 2. Schema validation — before policy, so policy sees typed values.
        try:
            args = spec.validate_args(raw_args if isinstance(raw_args, dict) else {})
        except ValidationError as exc:
            detail = "; ".join(
                f"{'.'.join(str(part) for part in err['loc'])}: {err['msg']}"
                for err in exc.errors()[:5]
            )
            return await self._deny_proposal(
                call_id=call_id,
                tool_name=tool_name,
                run_id=run_id,
                session_id=session_id,
                code="INVALID_ARGUMENTS",
                reason=f"Invalid arguments for '{tool_name}': {detail}",
                tainted=tainted,
                repairable=True,
            )

        canonical_json = canonical_args_json(args)
        args_hash = canonical_hash(args)
        digest = args_digest(canonical_json, redact=("content",))

        # 3. Path canonicalization — the one and only resolver.
        try:
            resolved_paths, path_list = self._resolve_paths(spec, args)
        except PathRejected as exc:
            return await self._deny_proposal(
                call_id=call_id,
                tool_name=tool_name,
                run_id=run_id,
                session_id=session_id,
                code=exc.code,
                reason=exc.reason,
                tainted=tainted,
                args_digest=digest,
            )

        resolved = ResolvedContext(
            run_id=run_id, session_id=session_id, tainted=tainted, paths=resolved_paths
        )
        preview = self._preview(spec, args, resolved)

        self._emit(
            "tool.requested",
            {
                "call_id": call_id,
                "tool": spec.name,
                "category": spec.category.value,
                "risk": spec.risk.value,
                "args_preview": preview.action_text,
                "targets": preview.targets,
                "item_count": preview.item_count,
                "taint": tainted,
            },
            session_id,
            run_id,
        )
        await self._audit(
            AuditRecord(
                event=EVENT_PROPOSAL,
                actor="model",
                run_id=run_id,
                tool_name=spec.name,
                args_digest=digest,
                resolved_target=preview.targets[0] if preview.targets else None,
                taint=tainted,
            )
        )

        # 4. Policy.
        request = PolicyRequest(
            spec=spec,
            args=args,
            run_id=run_id,
            session_id=session_id,
            tainted=tainted,
            paths=tuple(path_list),
            item_count=max(1, preview.item_count),
            user_turn_text=user_turn_text,
            side_effect_budget_exceeded=side_effect_budget_exceeded,
        )
        decision = self.engine.evaluate(request)
        self._emit(
            "tool.decision",
            {
                "call_id": call_id,
                "decision": decision.decision.value,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
            },
            session_id,
            run_id,
        )
        await self._audit(
            AuditRecord(
                event=EVENT_DECISION,
                actor="system",
                run_id=run_id,
                tool_name=spec.name,
                args_digest=digest,
                resolved_target=preview.targets[0] if preview.targets else None,
                decision=decision.decision.value,
                rule_id=decision.rule_id,
                reason=decision.reason,
                taint=tainted,
            )
        )
        if decision.taint_applied:
            await self._audit(
                AuditRecord(
                    event=EVENT_TAINT_DOWNGRADE,
                    actor="system",
                    run_id=run_id,
                    tool_name=spec.name,
                    args_digest=digest,
                    decision=decision.decision.value,
                    rule_id=decision.rule_id,
                    reason=decision.reason,
                    taint=True,
                )
            )

        approval_id: Optional[str] = None
        if decision.decision is Decision.DENY:
            return await self._denied_by_policy(
                call_id=call_id,
                spec=spec,
                decision=decision,
                run_id=run_id,
                session_id=session_id,
                digest=digest,
                tainted=tainted,
                args_hash=args_hash,
                preview=preview,
            )

        if decision.decision is Decision.ASK:
            outcome = await self._request_approval(
                call_id=call_id,
                spec=spec,
                args=args,
                request=request,
                decision=decision,
                preview=preview,
                run_id=run_id,
                session_id=session_id,
                model_rationale=model_rationale,
                digest=digest,
                args_hash=args_hash,
                tainted=tainted,
            )
            if isinstance(outcome, ToolOutcome):
                return outcome
            approval_id, authorization = outcome
        else:
            authorization = self.engine.mint(request, decision)
            if decision.grant_id and self.store is not None:
                await self.store.record_grant_use(decision.grant_id)

        # 5. Runtime.
        self._emit("tool.started", {"call_id": call_id}, session_id, run_id)
        ctx = ToolContext(
            run_id=run_id,
            session_id=session_id,
            cancel_token=cancel_token,
            authorization=authorization,
            taint=tainted,
            resolved=resolved,
            progress=self._progress_hook(call_id, session_id, run_id),
            logger=log,
        )
        result = await self.runtime.execute(spec, args, authorization, ctx)

        # 6. Taint update — a tool that produced untrusted content taints the run.
        tainted_result = result.trust == "UNTRUSTED" and result.status == "ok"
        if tainted_result:
            source = preview.targets[0] if preview.targets else spec.name
            taint_tracker.mark(run_id, tool_name=spec.name, source=source)

        if spec.side_effects and result.status == "ok":
            await self._audit(
                AuditRecord(
                    event=EVENT_FS_MUTATION if spec.category.value == "files" else EVENT_DECISION,
                    actor="model",
                    run_id=run_id,
                    tool_name=spec.name,
                    args_digest=digest,
                    resolved_target="; ".join(preview.targets[:5]) or None,
                    decision=Decision.ALLOW.value,
                    rule_id=decision.rule_id,
                    approval_id=approval_id,
                    outcome=result.status,
                    duration_ms=result.duration_ms,
                    taint=tainted,
                )
            )

        self._emit(
            "tool.result",
            {
                "call_id": call_id,
                "status": result.status,
                "summary": result.summary,
                "result_id": result.result_id,
                "duration_ms": result.duration_ms,
                "truncated": result.truncated,
                "undo_available": result.undo is not None,
                "error_code": result.error_code,
            },
            session_id,
            run_id,
        )
        return ToolOutcome(
            call_id=call_id,
            tool_name=spec.name,
            decision=Decision.ALLOW,
            rule_id=decision.rule_id,
            reason=decision.reason,
            result=result,
            side_effect=spec.side_effects,
            args_hash=args_hash,
            approval_id=approval_id,
            tainted_result=tainted_result,
        )

    # -- helpers -------------------------------------------------------------

    def _progress_hook(self, call_id: str, session_id: str, run_id: str) -> Any:
        last = {"ts": 0.0}

        def emit(progress: float | None, note: str | None) -> None:
            import time

            now = time.monotonic()
            if now - last["ts"] < 0.5:  # ≤2 Hz (docs/api.md §4)
                return
            last["ts"] = now
            self._emit(
                "tool.progress",
                {"call_id": call_id, "progress": progress, "note": note},
                session_id,
                run_id,
            )

        return emit

    def _resolve_paths(
        self, spec: ToolSpec, args: Any
    ) -> tuple[dict[str, Any], list[CanonicalPath]]:
        if not spec.requires_paths:
            return {}, []
        policy = self.fs_scope.policy
        resolved: dict[str, Any] = {}
        flat: list[CanonicalPath] = []
        must_exist_fields = _must_exist_fields(spec.name)
        for field_name in spec.path_args:
            raw = getattr(args, field_name, None)
            must_exist = field_name in must_exist_fields
            if isinstance(raw, list):
                if len(raw) > self.fs_scope.max_batch_items:
                    raise PathRejected(
                        "FS_BATCH_TOO_LARGE",
                        f"More than {self.fs_scope.max_batch_items} items in one call.",
                    )
                canonical_list = [
                    policy.canonicalize(item, must_exist=must_exist) for item in raw
                ]
                resolved[field_name] = canonical_list
                flat.extend(canonical_list)
            elif isinstance(raw, str):
                canonical = policy.canonicalize(raw, must_exist=must_exist)
                resolved[field_name] = canonical
                flat.append(canonical)
        return resolved, flat

    def _preview(self, spec: ToolSpec, args: Any, resolved: ResolvedContext) -> ActionPreview:
        if spec.preview is not None:
            try:
                return spec.preview(args, resolved)
            except Exception as exc:  # noqa: BLE001 - a preview must never block policy
                log.error("preview_failed", tool=spec.name, error=str(exc))
        targets = []
        for value in resolved.paths.values():
            if isinstance(value, list):
                targets.extend(item.path for item in value)
            else:
                targets.append(value.path)
        return ActionPreview(
            action_text=f"Run {spec.name}",
            targets=targets,
            item_count=max(1, len(targets)),
            reversible=spec.reversible,
            destructive=spec.destructive,
        )

    async def _deny_proposal(
        self,
        *,
        call_id: str,
        tool_name: str,
        run_id: str,
        session_id: str,
        code: str,
        reason: str,
        tainted: bool,
        status: str = "denied",
        repairable: bool = False,
        args_digest: str | None = None,
    ) -> ToolOutcome:
        self._emit(
            "tool.decision",
            {
                "call_id": call_id,
                "decision": "DENY",
                "rule_id": f"validation.{code.lower()}",
                "reason": reason,
            },
            session_id,
            run_id,
        )
        await self._audit(
            AuditRecord(
                event=EVENT_DENIED,
                actor="model",
                run_id=run_id,
                tool_name=tool_name,
                args_digest=args_digest,
                decision="DENY",
                rule_id=f"validation.{code.lower()}",
                reason=reason,
                error_code=code,
                taint=tainted,
            )
        )
        result = ToolResult(status=status, summary=reason, error_code=code)
        result.result_id = f"res_{uuid.uuid4().hex[:12]}"
        self._emit(
            "tool.result",
            {
                "call_id": call_id,
                "status": result.status,
                "summary": result.summary,
                "result_id": result.result_id,
                "duration_ms": 0,
                "truncated": False,
                "undo_available": False,
                "error_code": code,
            },
            session_id,
            run_id,
        )
        return ToolOutcome(
            call_id=call_id,
            tool_name=tool_name,
            decision=Decision.DENY,
            rule_id=f"validation.{code.lower()}",
            reason=reason,
            result=result,
        )

    async def _denied_by_policy(
        self,
        *,
        call_id: str,
        spec: ToolSpec,
        decision: PolicyDecision,
        run_id: str,
        session_id: str,
        digest: str,
        tainted: bool,
        args_hash: str,
        preview: ActionPreview,
    ) -> ToolOutcome:
        await self._audit(
            AuditRecord(
                event=EVENT_DENIED,
                actor="model",
                run_id=run_id,
                tool_name=spec.name,
                args_digest=digest,
                resolved_target=preview.targets[0] if preview.targets else None,
                decision="DENY",
                rule_id=decision.rule_id,
                reason=decision.reason,
                taint=tainted,
            )
        )
        code = _error_code_for(decision.rule_id)
        result = ToolResult(
            status="denied",
            summary=decision.reason,
            error_code=code,
            data={
                "rule_id": decision.rule_id,
                "targets": preview.targets,
                "taint_sources": taint_tracker.sources(run_id) if tainted else [],
            },
        )
        result.result_id = f"res_{uuid.uuid4().hex[:12]}"
        self._emit(
            "tool.result",
            {
                "call_id": call_id,
                "status": "denied",
                "summary": decision.reason,
                "result_id": result.result_id,
                "duration_ms": 0,
                "truncated": False,
                "undo_available": False,
                "error_code": code,
            },
            session_id,
            run_id,
        )
        return ToolOutcome(
            call_id=call_id,
            tool_name=spec.name,
            decision=Decision.DENY,
            rule_id=decision.rule_id,
            reason=decision.reason,
            result=result,
            args_hash=args_hash,
        )

    async def _request_approval(
        self,
        *,
        call_id: str,
        spec: ToolSpec,
        args: Any,
        request: PolicyRequest,
        decision: PolicyDecision,
        preview: ActionPreview,
        run_id: str,
        session_id: str,
        model_rationale: str,
        digest: str,
        args_hash: str,
        tainted: bool,
    ) -> ToolOutcome | tuple[str, Authorization]:
        persistent_allowed = self.engine.mode.allows_persistent_grant(spec) and not tainted
        options = scope_options_for(
            destructive=spec.destructive or preview.destructive,
            reversible=spec.reversible,
            persistent_allowed=persistent_allowed,
        )
        approval = await self.approvals.create(
            run_id=run_id,
            session_id=session_id,
            call_id=call_id,
            tool_name=spec.name,
            args_hash=args_hash,
            risk=spec.risk.value,
            title=_title_for(spec),
            action_text=preview.action_text,
            targets=preview.targets,
            item_count=preview.item_count,
            total_bytes=preview.total_bytes,
            reversible=preview.reversible or spec.reversible,
            destructive=spec.destructive or preview.destructive,
            model_rationale=model_rationale,
            scope_options=options,
        )
        self._emit("approval.requested", approval.to_event(), session_id, run_id)
        await self._audit(
            AuditRecord(
                event=EVENT_APPROVAL_REQUESTED,
                actor="system",
                run_id=run_id,
                tool_name=spec.name,
                args_digest=digest,
                resolved_target=preview.targets[0] if preview.targets else None,
                decision="ASK",
                rule_id=decision.rule_id,
                reason=preview.action_text,
                approval_id=approval.id,
                taint=tainted,
            )
        )

        await self.approvals.wait(approval)
        outcome = approval.outcome or "timeout"
        self._emit(
            "approval.resolved",
            {"approval_id": approval.id, "outcome": outcome, "scope": approval.scope},
            session_id,
            run_id,
        )
        await self._audit(
            AuditRecord(
                event=EVENT_APPROVAL_RESOLVED,
                actor="user",
                run_id=run_id,
                tool_name=spec.name,
                args_digest=digest,
                decision="ALLOW" if outcome == "allowed" else "DENY",
                rule_id=decision.rule_id,
                approval_id=approval.id,
                outcome=outcome,
                taint=tainted,
            )
        )
        if outcome != "allowed":
            code = "APPROVAL_TIMEOUT" if outcome == "timeout" else "POLICY_DENIED"
            summary = (
                "The approval timed out, so nothing was done."
                if outcome == "timeout"
                else "You declined this action."
            )
            result = ToolResult(status="denied", summary=summary, error_code=code)
            result.result_id = f"res_{uuid.uuid4().hex[:12]}"
            self._emit(
                "tool.result",
                {
                    "call_id": call_id,
                    "status": "denied",
                    "summary": summary,
                    "result_id": result.result_id,
                    "duration_ms": 0,
                    "truncated": False,
                    "undo_available": False,
                    "error_code": code,
                },
                session_id,
                run_id,
            )
            return ToolOutcome(
                call_id=call_id,
                tool_name=spec.name,
                decision=Decision.DENY,
                rule_id="policy.approval",
                reason=summary,
                result=result,
                approval_id=approval.id,
                args_hash=args_hash,
            )

        # Redeem the single-use nonce and re-evaluate before minting.
        try:
            await self.approvals.consume(approval.id, tool_name=spec.name, args_hash=args_hash)
        except ApprovalError as exc:
            return await self._deny_proposal(
                call_id=call_id,
                tool_name=spec.name,
                run_id=run_id,
                session_id=session_id,
                code=exc.code,
                reason=str(exc),
                tainted=tainted,
                args_digest=digest,
            )

        # Re-evaluate against the *same* canonical paths, with taint re-read and
        # the user-anchor requirement satisfied by the approval itself.
        fresh_request = PolicyRequest(
            spec=request.spec,
            args=request.args,
            run_id=request.run_id,
            session_id=request.session_id,
            tainted=taint_tracker.is_tainted(run_id),
            paths=request.paths,
            item_count=request.item_count,
            user_turn_text=" ".join(path.path for path in request.paths),
            side_effect_budget_exceeded=False,
        )
        try:
            _promoted, authorization = self.engine.authorize_approved(
                fresh_request, approval_id=approval.id
            )
        except AuthorizationError as exc:
            return await self._deny_proposal(
                call_id=call_id,
                tool_name=spec.name,
                run_id=run_id,
                session_id=session_id,
                code="POLICY_DENIED",
                reason=f"Blocked after approval: {exc}",
                tainted=tainted,
                args_digest=digest,
            )

        if approval.scope and approval.scope != "once":
            await self._create_grant(
                spec=spec,
                request_scope=approval.scope,
                preview=preview,
                session_id=session_id,
                approval_id=approval.id,
                run_id=run_id,
                digest=digest,
            )
        return approval.id, authorization

    async def _create_grant(
        self,
        *,
        spec: ToolSpec,
        request_scope: str,
        preview: ActionPreview,
        session_id: str,
        approval_id: str,
        run_id: str,
        digest: str,
    ) -> None:
        if self.store is None:
            return
        ttl_s, session_bound = scope_to_ttl(request_scope)
        if ttl_s == 0.0 and not session_bound:
            return
        scope = GrantScope.parse(
            {
                "paths": [_scope_root(target) for target in preview.targets] or [],
                "recursive": True,
                "ops": [spec.name],
                "max_items": max(1, preview.item_count),
            }
        )
        try:
            grant = await self.store.create_grant(
                tool_name=spec.name,
                scope=scope,
                risk=spec.risk,
                destructive=spec.destructive,
                ttl_s=ttl_s,
                session_id=session_id if session_bound else None,
                origin_approval_id=approval_id,
            )
        except RuleRejected as exc:
            log.info("grant_refused", tool=spec.name, reason=str(exc))
            return
        self.engine.grants.append(grant)
        await self._audit(
            AuditRecord(
                event=EVENT_GRANT_CREATED,
                actor="user",
                run_id=run_id,
                tool_name=spec.name,
                args_digest=digest,
                decision="ALLOW",
                rule_id="policy.grant",
                reason=f"scope={request_scope}",
                approval_id=approval_id,
            )
        )


def _scope_root(target: str) -> str:
    """A grant covers the *folder* the approved target lives in, not the drive."""
    from pathlib import PureWindowsPath

    pure = PureWindowsPath(target)
    parent = pure.parent
    if len(parent.parts) <= 1:
        return str(pure)
    return str(parent)


def _reuse_paths(decision: PolicyDecision) -> tuple[CanonicalPath, ...]:
    return ()


def _title_for(spec: ToolSpec) -> str:
    return {
        "read_file": "Read a file",
        "write_file": "Write a file",
        "copy_file": "Copy a file",
        "move_file": "Move a file",
        "rename_file": "Rename an item",
        "create_directory": "Create a folder",
        "delete_file": "Delete to Recycle Bin",
        "list_directory": "List a folder",
        "search_files": "Search for files",
    }.get(spec.name, f"Run {spec.name}")


def _error_code_for(rule_id: str) -> str:
    if rule_id == "policy.taint.destructive":
        return "TAINTED_DESTRUCTIVE"
    if rule_id.startswith("baseline."):
        return "POLICY_DENIED"
    return "POLICY_DENIED"


def _must_exist_fields(tool_name: str) -> frozenset[str]:
    return {
        "read_file": frozenset({"path"}),
        "list_directory": frozenset({"path"}),
        "search_files": frozenset({"root"}),
        "copy_file": frozenset({"source"}),
        "move_file": frozenset({"source"}),
        "rename_file": frozenset({"path"}),
        "delete_file": frozenset({"paths"}),
    }.get(tool_name, frozenset())


def _placeholder_args(spec: ToolSpec) -> Any:
    """Best-effort empty args for a visibility probe (never executed)."""
    try:
        return spec.args_model()
    except ValidationError:
        return spec.args_model.model_construct()


__all__ = ["ToolMediator", "ToolOutcome", "ToolProposalError"]
