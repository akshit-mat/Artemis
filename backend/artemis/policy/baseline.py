"""Hard-deny policy baseline — the absolute authority ceiling.

``docs/security.md`` §3 (R-BASELINE) and ADR-016: editable rules and grants live
in SQLite; the non-overridable deny baseline is compiled into this module.  No
config file, database row, UI action, grant, memory or model output may raise it.

The baseline answers exactly one question:

    given a tool identity, its declared risk and its resolved targets, what is
    the **highest** decision that is permitted to exist?

Everything else in the policy engine may only move the decision *down* from
there.  ``policy/engine.py`` applies :func:`baseline_ceiling` first and again as
a final clamp, so no later stage can accidentally exceed it.

This module deliberately has no dependency on the database, the config loader or
the tool registry: it cannot be subverted by import order or by data.
"""

from __future__ import annotations

import re
from typing import Final, Iterable

from ..tools.contract import Decision, RiskLevel

# --------------------------------------------------------------------------
# Forbidden capabilities (``docs/tools.md`` §6, ADR-003)
# --------------------------------------------------------------------------

#: Capability tokens that are permanently forbidden.  A registered tool whose
#: name contains one of these is hard-denied even if someone registers it.
FORBIDDEN_CAPABILITY_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "shell",
        "powershell",
        "pwsh",
        "cmd",
        "command",
        "exec",
        "execute_code",
        "eval",
        "python",
        "subprocess",
        "spawn",
        "script",
        "registry_write",
        "regwrite",
        "service_create",
        "scheduled_task",
        "schtask",
        "elevate",
        "uac",
        "runas",
        "credential",
        "keychain",
        "vault",
        "browser_profile",
        "ssh_key",
        "cloud_key",
        "password_manager",
        "disable_defender",
        "security_software",
        "driver_install",
        "listen_port",
        "process_memory",
        "write_policy",
        "self_update",
        "sql",
    }
)

#: Exact tool names that must never exist.  Belt and braces next to the token
#: scan above, so a rename cannot smuggle one in.
FORBIDDEN_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "run_command",
        "run_shell",
        "run_powershell",
        "run_python",
        "run_script",
        "exec_command",
        "system",
        "eval_expression",
        "delete_file_permanent",
    }
)

#: URL schemes that may never be fetched or handed to the shell.
ALLOWED_URL_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

# --------------------------------------------------------------------------
# Forbidden paths (``docs/security.md`` §5 "Always-denied paths")
# --------------------------------------------------------------------------

#: Absolute prefixes, compared **segment-wise** after canonicalization.
DENIED_ABSOLUTE_PREFIXES: Final[tuple[str, ...]] = (
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
    r"C:\$Recycle.Bin",
    r"C:\System Volume Information",
)

#: Environment-relative prefixes.  ``%VAR%`` is expanded at load time by the
#: path module; unresolvable variables simply produce no rule (fail-closed is
#: preserved because the absolute prefixes above still apply).
DENIED_ENV_PREFIXES: Final[tuple[str, ...]] = (
    r"%APPDATA%\Microsoft\Crypto",
    r"%APPDATA%\Microsoft\Protect",
    r"%APPDATA%\Microsoft\SystemCertificates",
    r"%LOCALAPPDATA%\Microsoft\Credentials",
    r"%LOCALAPPDATA%\Microsoft\Vault",
    r"%USERPROFILE%\.ssh",
    r"%USERPROFILE%\.aws",
    r"%USERPROFILE%\.azure",
    r"%USERPROFILE%\.kube",
    r"%USERPROFILE%\.gnupg",
    r"%USERPROFILE%\.docker",
)

#: Directory names that indicate a browser profile anywhere in the tree
#: (``*\User Data\*``, ``*\Profiles\*``).
DENIED_PATH_SEGMENTS: Final[frozenset[str]] = frozenset(
    {
        "user data",
        "profiles",
        "credentials",
        "protect",
        "vault",
        ".ssh",
        ".aws",
        ".azure",
        ".kube",
        ".gnupg",
    }
)

#: Secret-shaped file names.  Applied to reads *and* writes, name-based.
SECRET_NAME_PATTERNS: Final[tuple[str, ...]] = (
    r".*\.pem$",
    r".*\.key$",
    r".*\.ppk$",
    r".*\.pfx$",
    r".*\.p12$",
    r".*\.kdbx$",
    r".*\.jks$",
    r".*\.keystore$",
    r"id_rsa.*",
    r"id_ed25519.*",
    r"id_dsa.*",
    r"id_ecdsa.*",
    r"\.env(\..*)?$",
    r"\.netrc$",
    r"_netrc$",
    r"\.npmrc$",
    r"\.pypirc$",
    r"\.git-credentials$",
    r".*credentials.*",
    r".*secrets?.*",
    r".*[-_.]token.*",
    r"token.*",
    r".*\.token$",
    r".*password.*",
    r".*\.kwallet$",
)

_SECRET_NAME_RE: Final[tuple[re.Pattern[str], ...]] = tuple(
    re.compile(pattern, re.IGNORECASE) for pattern in SECRET_NAME_PATTERNS
)

#: Reserved DOS device names, rejected in **any** path segment.
RESERVED_DEVICE_NAMES: Final[frozenset[str]] = frozenset(
    {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

#: Maximum accepted raw path length before canonicalization.
MAX_PATH_CHARS: Final[int] = 32_000


def is_secret_shaped_name(name: str) -> bool:
    """True when a file name looks like credential material."""
    lowered = name.lower()
    return any(rx.fullmatch(lowered) or rx.match(lowered) for rx in _SECRET_NAME_RE)


def is_forbidden_capability(tool_name: str) -> bool:
    """True when a tool identity names a permanently forbidden capability."""
    lowered = tool_name.lower()
    if lowered in FORBIDDEN_TOOL_NAMES:
        return True
    parts = set(lowered.split("_"))
    for token in FORBIDDEN_CAPABILITY_TOKENS:
        if token in parts:
            return True
        if "_" in token and token in lowered:
            return True
    return False


# --------------------------------------------------------------------------
# The ceiling
# --------------------------------------------------------------------------


def baseline_ceiling(
    *,
    tool_name: str,
    risk: RiskLevel,
    destructive: bool = False,
    permanent_destruction: bool = False,
) -> tuple[Decision, str, str]:
    """Highest decision the baseline permits for this call.

    Returns ``(decision, rule_id, reason)``.  ``rule_id`` is stable and shows in
    the audit log and in the UI denial card.
    """
    if is_forbidden_capability(tool_name):
        return (
            Decision.DENY,
            "baseline.forbidden_capability",
            "This capability is permanently forbidden by the ARTEMIS baseline.",
        )
    if risk is RiskLevel.FORBIDDEN:
        return (
            Decision.DENY,
            "baseline.forbidden_risk",
            "The tool declares a forbidden risk level.",
        )
    if permanent_destruction:
        return (
            Decision.DENY,
            "baseline.permanent_destruction",
            "Permanent (non-recoverable) destruction is denied by the baseline.",
        )
    if destructive or risk is RiskLevel.DESTRUCTIVE:
        # ADR-010 / security.md §3: "Always" is unavailable for DESTRUCTIVE
        # tools — deleting always asks.  Expressing that as a baseline ceiling
        # means no grant or rule can ever make it ALLOW.
        return (
            Decision.ASK,
            "baseline.destructive_always_asks",
            "Destructive actions always require explicit confirmation.",
        )
    return (Decision.ALLOW, "baseline.ok", "No baseline restriction applies.")


class BaselineViolation(RuntimeError):
    """A rule row or tool registration attempts to shadow the baseline."""


def assert_no_shadowing(
    rules: Iterable[tuple[str, str]],
    tools: Iterable[tuple[str, RiskLevel, bool]],
) -> None:
    """Startup self-test (``docs/security.md`` §3).

    *rules* is ``(tool_name, decision)`` and *tools* is
    ``(tool_name, risk, destructive)``.  Any rule that claims a decision above
    the baseline ceiling for its tool, or any registered tool naming a forbidden
    capability, is a fatal startup condition — the process refuses to start.
    """
    risk_by_tool: dict[str, tuple[RiskLevel, bool]] = {}
    for tool_name, risk, destructive in tools:
        if is_forbidden_capability(tool_name):
            raise BaselineViolation(
                f"registered tool {tool_name!r} names a permanently forbidden capability"
            )
        if risk is RiskLevel.FORBIDDEN:
            raise BaselineViolation(f"registered tool {tool_name!r} declares FORBIDDEN risk")
        risk_by_tool[tool_name] = (risk, destructive)

    for tool_name, decision in rules:
        try:
            wanted = Decision(decision)
        except ValueError as exc:
            raise BaselineViolation(f"rule for {tool_name!r} has invalid decision {decision!r}") from exc
        risk, destructive = risk_by_tool.get(tool_name, (RiskLevel.MODERATE, False))
        ceiling, rule_id, _reason = baseline_ceiling(
            tool_name=tool_name, risk=risk, destructive=destructive
        )
        if wanted.rank > ceiling.rank:
            raise BaselineViolation(
                f"rule for {tool_name!r} requests {wanted.value} but the baseline "
                f"ceiling is {ceiling.value} ({rule_id})"
            )
