"""Policy package — the security authority.

Import order matters only in one respect: :mod:`artemis.policy.baseline` must
never import anything else from the package, so it cannot be subverted.
"""

from .baseline import BaselineViolation, baseline_ceiling
from .engine import (
    Authorization,
    AuthorizationError,
    PolicyDecision,
    PolicyEngine,
    PolicyRequest,
    assert_matches,
)

__all__ = [
    "Authorization",
    "AuthorizationError",
    "BaselineViolation",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRequest",
    "assert_matches",
    "baseline_ceiling",
]
