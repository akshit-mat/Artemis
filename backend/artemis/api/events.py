import asyncio
import collections
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable, Dict, List, Optional
from ..obs.logging import get_logger

log = get_logger("events")

class EventBus:
    """Authoritative event bus responsible for sequence numbers, replay history, and publishing."""
    def __init__(self):
        self._seq = 0
        self._history: collections.deque[Dict[str, Any]] = collections.deque(maxlen=500)
        self._subscribers: set[Callable[[Dict[str, Any]], Awaitable[None]]] = set()
        
    def subscribe(self, callback: Callable[[Dict[str, Any]], Awaitable[None]]) -> Callable[[], None]:
        self._subscribers.add(callback)
        def unsubscribe():
            self._subscribers.discard(callback)
        return unsubscribe
        
    def publish(self, event_type: str, data: Dict[str, Any], session_id: str = "s_test", run_id: Optional[str] = None) -> Dict[str, Any]:
        self._seq += 1
        event: Dict[str, Any] = {
            "v": 1,
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "session_id": session_id,
            "data": data
        }
        if run_id:
            event["run_id"] = run_id
            
        self._history.append(event)
        
        for sub in list(self._subscribers):
            asyncio.create_task(self._safe_dispatch(sub, event))
            
        return event

    async def _safe_dispatch(self, sub: Callable[[Dict[str, Any]], Awaitable[None]], event: Dict[str, Any]) -> None:
        try:
            await sub(event)
        except Exception as e:
            log.error("event_dispatch_error", error=str(e))
            self._subscribers.discard(sub)
        
    def get_replay(self, last_seq: int) -> Optional[List[Dict[str, Any]]]:
        """Return events to replay, or None if client_resync_required."""
        if not self._history:
            return []
            
        oldest_seq = self._history[0]["seq"]
        if last_seq < oldest_seq - 1:
            return None # Out of replay window
            
        return [e for e in self._history if e["seq"] > last_seq]
        
    @property
    def current_seq(self) -> int:
        return self._seq

# Global event bus singleton for Phase 1
bus = EventBus()
