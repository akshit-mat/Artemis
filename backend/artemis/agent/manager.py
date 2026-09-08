"""Active-run registry: cancellation scopes plus tool cancel tokens.

``docs/agent.md`` §2 Cancellation: ``run.cancel`` must abort the provider stream
*and* cancel a running tool.  A single ``cancel()`` therefore fires both halves —
the anyio scope (model stream) and the :class:`CancelToken` the tool runtime
observes, which for the SUBPROCESS tier terminates the child's process tree.
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

import anyio

from ..obs.logging import get_logger
from ..tools.contract import CancelToken

log = get_logger("agent.manager")


class AgentRunManager:
    """Tracks active runs and their cancellation handles."""

    def __init__(self) -> None:
        self._scopes: Dict[str, anyio.CancelScope] = {}
        self._tokens: Dict[str, CancelToken] = {}

    def register(
        self,
        run_id: str,
        scope: anyio.CancelScope,
        cancel_token: Optional[CancelToken] = None,
    ) -> None:
        self._scopes[run_id] = scope
        if cancel_token is not None:
            self._tokens[run_id] = cancel_token

    def unregister(self, run_id: str) -> None:
        self._scopes.pop(run_id, None)
        self._tokens.pop(run_id, None)

    def cancel(self, run_id: str) -> bool:
        """Cancel a run.  Returns True if the run was found and cancelled."""
        scope = self._scopes.get(run_id)
        token = self._tokens.get(run_id)
        if scope is None and token is None:
            log.warning("cancel_ignored_unknown_run", run_id=run_id)
            return False
        if token is not None:
            token.cancel()
        if scope is not None:
            scope.cancel()
        log.info("run_cancelled", run_id=run_id)
        return True

    def is_active(self, run_id: str) -> bool:
        return run_id in self._scopes or run_id in self._tokens

    def active_runs(self) -> tuple[str, ...]:
        return tuple(self._scopes.keys())


# Global instance for the server lifecycle
run_manager = AgentRunManager()
