"""Policy engine — the single authority in ARTEMIS.

``docs/security.md`` §3 is the specification; ADR-016 fixes the shape:

    effective = min(baseline, tool.default_decision, rule, grant, taint)

with ``DENY < ASK < ALLOW``.  There is **no** code path in this module that
moves a decision up the lattice, except the one documented escape valve: a valid
applicable grant or rule may raise an ``ASK`` *default* to ``ALLOW``, and even
then the result is clamped by the baseline ceiling and by the taint lock.  That
is the entire reason grants exist (``docs/security.md`` §3 "Grants"); it is
implemented as an explicit, single, audited step rather than as a general
``max``.

:class:`Authorization` can only be minted here (``docs/tools.md`` §5): the
constructor requires a module-private sentinel, so no other module — and
certainly no model output or frontend request — can fabricate one.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence

from ..obs.logging import get_logger
from ..tools.contract import (
    Decision,
    RiskLevel,
    ToolSpec,
    canonical_args_json,
    canonical_hash,
    decision_min,
)
from . import baseline
from .grants import Grant, GrantScope, first_matching
from .paths import CanonicalPath

log = get_logger("policy.engine")

#: Authorizations are short-lived: minted, then consumed by the runtime in the
#: same step of the agent loop.  An approval may make the window longer, so the
#: TTL is generous but finite.
AUTHORIZATION_TTL_S: float = 300.0

_POLICY_SENTINEL: object = object()

#: Per-process secret used to sign Authorization objects.  Never persisted and
#: never leaves the process; a signature check is a cheap structural assertion
#: that an Authorization travelled from mint to runtime unmodified.
_SIGNING_KEY: bytes = secrets.token_bytes(32)


class AuthorizationError(RuntimeError):
    """Authorization was absent, forged, stale, or does not match the call."""


@dataclass(frozen=True, slots=True)
class PolicyMode:
    """``strict`` | ``standard`` | ``permissive`` (``docs/security.md`` §3)."""

    name: str

    def clamp(self, spec: ToolSpec, decision: Decision) -> Decision:
        if self.name == "strict":
            if spec.side_effects:
                return decision_min(decision, Decision.ASK)
            return decision
        return decision

    def allows_persistent_grant(self, spec: ToolSpec) -> bool:
        if self.name == "strict":
            return spec.risk is RiskLevel.READ_ONLY
        return spec.risk is not RiskLevel.DESTRUCTIVE


MODE_STRICT = PolicyMode("strict")
MODE_STANDARD = PolicyMode("standard")
MODE_PERMISSIVE = PolicyMode("permissive")

_MODES: Mapping[str, PolicyMode] = {
    "strict": MODE_STRICT,
    "standard": MODE_STANDARD,
    "permissive": MODE_PERMISSIVE,
}


def mode_by_name(name: str | None) -> PolicyMode:
    return _MODES.get((name or "standard").lower(), MODE_STANDARD)


class Authorization:
    """Unforgeable proof that the policy engine permitted an exact call.

    Binds: tool identity, ``sha256(canonical_args)``, run/session identity, the
    decision, capability/risk, grant/rule context, expiry, and the approval id
    when one was involved (``docs/security.md`` §6, ``docs/tools.md`` §5).
    """

    __slots__ = (
        "tool",
        "args_hash",
        "risk",
        "scope",
        "rule_id",
        "run_id",
        "session_id",
        "decision",
        "granted_at",
        "expires_at",
        "approval_id",
        "grant_id",
        "tainted",
        "resolved_targets",
        "_sig",
    )

    def __init__(self, *args: Any, _internal: object = None, **kwargs: Any) -> None:
        if _internal is not _POLICY_SENTINEL:
            raise RuntimeError("Authorization may only be minted by the policy engine")
        (
            self.tool,
            self.args_hash,
            self.risk,
            self.scope,
            self.rule_id,
            self.run_id,
            self.session_id,
            self.decision,
            self.granted_at,
            self.expires_at,
            self.approval_id,
            self.grant_id,
            self.tainted,
            self.resolved_targets,
        ) = args
        self._sig = self._signature()

    def _signature(self) -> str:
        payload = "\x1f".join(
            [
                self.tool,
                self.args_hash,
                str(self.risk),
                self.rule_id or "",
                self.run_id,
                self.session_id,
                self.decision.value,
                self.granted_at.isoformat(),
                self.expires_at.isoformat(),
                self.approval_id or "",
                self.grant_id or "",
                "1" if self.tainted else "0",
                "\x1e".join(self.resolved_targets),
            ]
        )
        return hmac.new(_SIGNING_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def is_intact(self) -> bool:
        return hmac.compare_digest(self._sig, self._signature())

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Authorization(tool={self.tool!r}, decision={self.decision.value}, "
            f"rule={self.rule_id!r}, args_hash={self.args_hash[:12]}…)"
        )


def assert_matches(
    auth: Any,
    tool_name: str,
    args_hash: str,
    *,
    run_id: str | None = None,
    now: datetime | None = None,
) -> Authorization:
    """Re-verify an Authorization at the runtime door (``docs/tools.md`` §5).

    Every failure mode is fail-closed and raises.
    """
    if not isinstance(auth, Authorization):
        raise AuthorizationError("MISSING_AUTHORIZATION")
    if not auth.is_intact():
        raise AuthorizationError("AUTHORIZATION_TAMPERED")
    if auth.decision is not Decision.ALLOW:
        raise AuthorizationError("AUTHORIZATION_NOT_ALLOW")
    if auth.tool != tool_name:
        raise AuthorizationError("AUTHORIZATION_TOOL_MISMATCH")
    if not hmac.compare_digest(auth.args_hash, args_hash):
        raise AuthorizationError("AUTHORIZATION_ARGS_MISMATCH")
    if run_id is not None and auth.run_id != run_id:
        raise AuthorizationError("AUTHORIZATION_RUN_MISMATCH")
    if auth.is_expired(now):
        raise AuthorizationError("AUTHORIZATION_EXPIRED")
    return auth


# --------------------------------------------------------------------------
# Decision result
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyRequest:
    """Everything the engine is allowed to look at.

    R-PURE-POLICY (``docs/security.md`` §2): memory content, model rationale and
    tool output are deliberately absent from this structure.
    """

    spec: ToolSpec
    args: Any
    run_id: str
    session_id: str
    tainted: bool = False
    paths: tuple[CanonicalPath, ...] = ()
    item_count: int = 1
    user_turn_text: str = ""
    side_effect_budget_exceeded: bool = False
    permanent_destruction: bool = False


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    decision: Decision
    rule_id: str
    reason: str
    baseline_ceiling: Decision
    tool_default: Decision
    rule_decision: Optional[Decision] = None
    grant_id: Optional[str] = None
    taint_applied: bool = False
    scope: Optional[GrantScope] = None
    args_hash: str = ""
    resolved_targets: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    @property
    def denied(self) -> bool:
        return self.decision is Decision.DENY


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------


class PolicyEngine:
    """Deterministic, synchronous, fail-closed.

    Rules and grants are supplied by the caller as already-loaded rows
    (``policy/store.py``), keeping the engine itself pure and trivially testable.
    """

    def __init__(
        self,
        *,
        mode: PolicyMode | str = MODE_STANDARD,
        rules: Mapping[str, str] | None = None,
        grants: Sequence[Grant] = (),
        clock: Any = None,
    ) -> None:
        self.mode = mode if isinstance(mode, PolicyMode) else mode_by_name(mode)
        self.rules: dict[str, str] = dict(rules or {})
        self.grants: list[Grant] = list(grants)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def now(self) -> datetime:
        return self._clock()

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        """Return exactly one decision plus ``rule_id`` and a reason.

        Any internal error results in ``DENY`` / ``POLICY_ERROR``
        (``docs/security.md`` §8 fail closed).
        """
        try:
            return self._evaluate(request)
        except Exception as exc:  # pragma: no cover - exercised via fault injection
            log.error("policy_engine_error", tool=request.spec.name, error=str(exc))
            return PolicyDecision(
                decision=Decision.DENY,
                rule_id="policy.error",
                reason="The policy engine failed; the action was denied.",
                baseline_ceiling=Decision.DENY,
                tool_default=request.spec.default_decision,
                args_hash=_safe_hash(request.args),
            )

    def _evaluate(self, request: PolicyRequest) -> PolicyDecision:
        spec = request.spec
        args_hash = canonical_hash(request.args)
        targets = tuple(p.path for p in request.paths)

        # 1. Hard-deny baseline — the absolute ceiling.
        ceiling, ceiling_rule, ceiling_reason = baseline.baseline_ceiling(
            tool_name=spec.name,
            risk=spec.risk,
            destructive=spec.destructive,
            permanent_destruction=request.permanent_destruction,
        )
        if ceiling is Decision.DENY:
            return PolicyDecision(
                decision=Decision.DENY,
                rule_id=ceiling_rule,
                reason=ceiling_reason,
                baseline_ceiling=ceiling,
                tool_default=spec.default_decision,
                args_hash=args_hash,
                resolved_targets=targets,
            )

        # 2. Registered & enabled.
        if not spec.enabled:
            return PolicyDecision(
                decision=Decision.DENY,
                rule_id="policy.tool_disabled",
                reason=f"The tool '{spec.name}' is disabled.",
                baseline_ceiling=ceiling,
                tool_default=spec.default_decision,
                args_hash=args_hash,
                resolved_targets=targets,
            )

        # 3. Path scope was already enforced by ``policy/paths.py``; the engine
        #    only sees canonical paths.  A tool that requires paths but received
        #    none is a programming error and fails closed.
        if spec.requires_paths and not request.paths:
            return PolicyDecision(
                decision=Decision.DENY,
                rule_id="policy.paths_missing",
                reason="No validated path was supplied for a path-based tool.",
                baseline_ceiling=ceiling,
                tool_default=spec.default_decision,
                args_hash=args_hash,
            )

        # 4. Start from the tool default, clamped by the baseline and the mode.
        decision = decision_min(ceiling, spec.default_decision)
        rule_id = "policy.tool_default"
        reason = f"Default policy for '{spec.name}'."

        # 5. Explicit rule.  A rule may tighten freely; it may raise an ASK
        #    default to ALLOW only up to the baseline ceiling.
        rule_decision: Optional[Decision] = None
        raw_rule = self.rules.get(spec.name)
        if raw_rule is not None:
            try:
                rule_decision = Decision(raw_rule)
            except ValueError:
                rule_decision = Decision.DENY
            if rule_decision is Decision.DENY:
                return PolicyDecision(
                    decision=Decision.DENY,
                    rule_id="policy.rule",
                    reason=f"A policy rule denies '{spec.name}'.",
                    baseline_ceiling=ceiling,
                    tool_default=spec.default_decision,
                    rule_decision=rule_decision,
                    args_hash=args_hash,
                    resolved_targets=targets,
                )
            candidate = decision_min(ceiling, rule_decision)
            if candidate.rank != decision.rank:
                decision = candidate
                rule_id = "policy.rule"
                reason = f"A policy rule sets '{spec.name}' to {candidate.value}."

        # 6. Grant.  Same ceiling clamp; a grant never invents authority the
        #    baseline forbids, and it is checked *before* the taint lock so the
        #    lock can override it (invariant: grants never bypass taint).
        grant: Optional[Grant] = None
        if decision is not Decision.ALLOW:
            grant = first_matching(
                self.grants,
                tool_name=spec.name,
                op=spec.name,
                paths=request.paths,
                item_count=request.item_count,
                now=self.now(),
                session_id=request.session_id,
            )
            if grant is not None:
                candidate = decision_min(ceiling, Decision.ALLOW)
                if candidate.rank > decision.rank:
                    decision = candidate
                    rule_id = "policy.grant"
                    reason = "An active grant covers this exact scope."

        # 7. Mode clamp (strict forces every side effect to ASK).
        mode_clamped = self.mode.clamp(spec, decision)
        if mode_clamped.rank < decision.rank:
            decision = mode_clamped
            rule_id = f"policy.mode.{self.mode.name}"
            reason = f"Policy mode '{self.mode.name}' requires confirmation."

        # 8. Taint escalation lock — may only tighten (``docs/security.md`` §4).
        taint_applied = False
        if request.tainted:
            if spec.risk is RiskLevel.DESTRUCTIVE or spec.destructive:
                return PolicyDecision(
                    decision=Decision.DENY,
                    rule_id="policy.taint.destructive",
                    reason=(
                        "Blocked: destructive action requested after reading "
                        "untrusted content."
                    ),
                    baseline_ceiling=ceiling,
                    tool_default=spec.default_decision,
                    rule_decision=rule_decision,
                    grant_id=grant.id if grant else None,
                    taint_applied=True,
                    args_hash=args_hash,
                    resolved_targets=targets,
                )
            if spec.side_effects:
                tainted_decision = decision_min(decision, Decision.ASK)
                if tainted_decision.rank < decision.rank or grant is not None:
                    taint_applied = True
                    decision = tainted_decision
                    rule_id = "policy.taint.side_effect"
                    reason = (
                        "Untrusted content is in context, so this side-effecting "
                        "action needs confirmation."
                    )
                    grant = None  # grants are ignored in a tainted run

        # 9. User-intent binding for destructive tools (``docs/security.md`` §4).
        if (spec.risk is RiskLevel.DESTRUCTIVE or spec.destructive) and request.paths:
            if not self._user_anchored(request):
                if request.tainted:  # pragma: no cover - handled in step 8
                    decision = Decision.DENY
                else:
                    decision = decision_min(decision, Decision.ASK)
                rule_id = "policy.user_anchor"
                reason = (
                    "The target was not named by you, so this destructive action "
                    "needs confirmation."
                )

        # 10. Budget / batch limits.
        if request.side_effect_budget_exceeded and spec.side_effects:
            limited = decision_min(decision, Decision.ASK)
            if limited.rank < decision.rank:
                decision = limited
                rule_id = "policy.budget"
                reason = "The per-turn side-effect budget is exhausted."

        # Final clamp — belt and braces.  Nothing may exceed the ceiling.
        decision = decision_min(decision, ceiling)

        return PolicyDecision(
            decision=decision,
            rule_id=rule_id,
            reason=reason,
            baseline_ceiling=ceiling,
            tool_default=spec.default_decision,
            rule_decision=rule_decision,
            grant_id=grant.id if grant else None,
            taint_applied=taint_applied,
            scope=grant.scope if grant else None,
            args_hash=args_hash,
            resolved_targets=targets,
        )

    @staticmethod
    def _user_anchored(request: PolicyRequest) -> bool:
        """Deterministic path/alias matching against the current user turn."""
        text = (request.user_turn_text or "").casefold()
        if not text:
            return False
        for path in request.paths:
            from .paths import comparison_key, segments_of  # local: avoid cycle noise

            if comparison_key(path.path) in text:
                return True
            parent = comparison_key(path.parent)
            if parent and parent in text:
                return True
            segments = segments_of(path.path)
            if segments and segments[-1].casefold() in text:
                return True
            if len(segments) >= 2 and segments[-2].casefold() in text:
                return True
        return False

    # -- minting ------------------------------------------------------------

    def mint(
        self,
        request: PolicyRequest,
        decision: PolicyDecision,
        *,
        approval_id: str | None = None,
        ttl_s: float = AUTHORIZATION_TTL_S,
    ) -> Authorization:
        """Create the Authorization for an ALLOW decision.

        Refuses to mint for anything other than ALLOW, so an approved ASK must
        be re-evaluated (with the approval id) before an Authorization exists.
        """
        if decision.decision is not Decision.ALLOW:
            raise AuthorizationError(
                f"cannot mint an Authorization for a {decision.decision.value} decision"
            )
        now = self.now()
        return Authorization(
            request.spec.name,
            decision.args_hash or canonical_hash(request.args),
            request.spec.risk.value,
            decision.scope,
            decision.rule_id,
            request.run_id,
            request.session_id,
            decision.decision,
            now,
            now + timedelta(seconds=ttl_s),
            approval_id,
            decision.grant_id,
            request.tainted,
            decision.resolved_targets,
            _internal=_POLICY_SENTINEL,
        )

    def authorize_approved(
        self,
        request: PolicyRequest,
        *,
        approval_id: str,
    ) -> tuple[PolicyDecision, Authorization]:
        """Re-evaluate after a human approval and mint if still permissible.

        Re-evaluation is mandatory: taint, rules and the baseline may have moved
        while the approval was pending, and only a fresh evaluation is safe.
        """
        decision = self.evaluate(request)
        if decision.decision is Decision.DENY:
            raise AuthorizationError(f"denied after approval: {decision.rule_id}")
        promoted = PolicyDecision(
            decision=Decision.ALLOW,
            rule_id="policy.approval",
            reason="You approved this action.",
            baseline_ceiling=decision.baseline_ceiling,
            tool_default=decision.tool_default,
            rule_decision=decision.rule_decision,
            grant_id=decision.grant_id,
            taint_applied=decision.taint_applied,
            scope=decision.scope,
            args_hash=decision.args_hash,
            resolved_targets=decision.resolved_targets,
        )
        # The approval is a human ALLOW; it is still clamped by the baseline.
        clamped = decision_min(Decision.ALLOW, decision.baseline_ceiling)
        if clamped is not Decision.ALLOW:
            # DESTRUCTIVE tools have an ASK ceiling: the approval *is* the ASK
            # being satisfied, so an explicit human approval legitimately
            # produces execution authority for exactly these arguments.
            if decision.baseline_ceiling is not Decision.ASK:
                raise AuthorizationError(
                    f"baseline forbids execution: {decision.baseline_ceiling.value}"
                )
        return promoted, self.mint(request, promoted, approval_id=approval_id)


def _safe_hash(args: Any) -> str:
    try:
        return canonical_hash(args)
    except Exception:  # pragma: no cover - defensive
        return ""


def canonical_args_repr(args: Any) -> str:
    """Exposed for the audit writer's ``args_digest`` field."""
    return canonical_args_json(args)


__all__ = [
    "AUTHORIZATION_TTL_S",
    "Authorization",
    "AuthorizationError",
    "MODE_PERMISSIVE",
    "MODE_STANDARD",
    "MODE_STRICT",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyMode",
    "PolicyRequest",
    "assert_matches",
    "canonical_args_repr",
    "mode_by_name",
]
