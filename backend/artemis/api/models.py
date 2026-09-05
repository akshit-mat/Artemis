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


class SessionStateResponse(BaseModel):
    """Authoritative session snapshot returned by GET /v1/sessions/{id}/state.

    Used by the frontend to fully resync after a replay gap.
    See ``docs/api.md`` §3 and the ``client.resync_required`` WS event.
    """

    session_id: str
    last_seq: int
    assistant_state: AssistantStateData
    active_run: Optional[str] = None
    pending_approvals: List[Any] = Field(default_factory=list)
    active_task: Optional[str] = None


class ResyncRequiredData(BaseModel):
    """Payload of the ``client.resync_required`` WS event.

    Tells the client the current authoritative sequence so it can call
    GET /v1/sessions/{session_id}/state and restore from there.
    """

    last_seq: int


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


class ChatSendData(BaseModel):
    session_id: str
    text: str
    client_msg_id: Optional[str] = None


class RunCancelData(BaseModel):
    run_id: str
    reason: Optional[str] = None
