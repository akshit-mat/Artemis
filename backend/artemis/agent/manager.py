import anyio
import logging
from typing import Dict

log = logging.getLogger("agent.manager")

class AgentRunManager:
    """Tracks active runs and their cancellation scopes."""
    def __init__(self):
        self._scopes: Dict[str, anyio.CancelScope] = {}

    def register(self, run_id: str, scope: anyio.CancelScope) -> None:
        self._scopes[run_id] = scope

    def unregister(self, run_id: str) -> None:
        self._scopes.pop(run_id, None)

    def cancel(self, run_id: str) -> bool:
        """Cancel a running run. Returns True if run was found and cancelled."""
        scope = self._scopes.get(run_id)
        if scope:
            scope.cancel()
            log.info("run_cancelled", run_id=run_id)
            return True
        log.warning("cancel_ignored_unknown_run", run_id=run_id)
        return False

# Global instance for the server lifecycle
run_manager = AgentRunManager()
