from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class AssistantStateData(BaseModel):
    state: str
    intensity: float

class SessionReadyData(BaseModel):
    last_seq: int
    assistant_state: AssistantStateData
    model: Dict[str, Any]
    pending_approvals: List[Any]

class AgentDeltaData(BaseModel):
    channel: str
    text: str

class AgentMessageData(BaseModel):
    message_id: str
    role: str
    content: str
    finish_reason: str
    steps_used: int
    tokens: Dict[str, int]
    incomplete: Optional[bool] = False

class AgentErrorData(BaseModel):
    code: str
    message: str
    recoverable: bool
    correlation_id: Optional[str] = None

class SystemEchoData(BaseModel):
    echoed_text: str

class WSEnvelope(BaseModel):
    v: int = 1
    seq: Optional[int] = None
    ts: str
    type: str
    session_id: str
    run_id: Optional[str] = None
    data: Dict[str, Any]
