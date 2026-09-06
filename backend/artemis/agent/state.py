from enum import IntEnum
from typing import Dict, Any, Optional

class StatePrecedence(IntEnum):
    IDLE = 1
    THINKING = 2
    RESPONDING = 3
    SPEAKING = 4
    LISTENING = 5
    TRANSCRIBING = 6
    SEARCHING = 7
    EXECUTING = 8
    WAITING_FOR_APPROVAL = 9
    ERROR = 10
    OFFLINE = 11

    @classmethod
    def from_str(cls, s: str) -> "StatePrecedence":
        return cls[s.upper()]

class AssistantStateCompute:
    """Pure AssistantState computation. Backend is the sole source."""
    def __init__(self):
        self._states: Dict[str, Dict[str, Any]] = {}

    def set_state(self, key: str, state: str, intensity: float = 1.0, progress: Optional[float] = None, detail: Optional[str] = None, run_id: Optional[str] = None) -> None:
        self._states[key] = {
            "state": state.upper(),
            "intensity": intensity,
            "progress": progress,
            "detail": detail,
            "run_id": run_id
        }

    def clear_state(self, key: str) -> None:
        self._states.pop(key, None)

    def compute(self) -> Dict[str, Any]:
        if not self._states:
            return {"state": "IDLE", "intensity": 0.0, "progress": None, "detail": None, "run_id": None}

        best_state = None
        best_prec = 0

        for v in self._states.values():
            prec = StatePrecedence.from_str(v["state"]).value
            if prec > best_prec:
                best_prec = prec
                best_state = v

        if not best_state:
            return {"state": "IDLE", "intensity": 0.0, "progress": None, "detail": None, "run_id": None}

        return best_state

state_computer = AssistantStateCompute()
