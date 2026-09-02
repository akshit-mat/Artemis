import asyncio
import json
from datetime import datetime, timezone
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websockets.exceptions import ConnectionClosedOK

from ..config.settings import settings
from ..obs.logging import log

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.seq = 0

    async def connect(self, websocket: WebSocket):
        await websocket.accept(subprotocol=f"bearer.{settings.auth_token}")
        self.active_connections.append(websocket)
        
        # Send session.ready immediately upon connection
        self.seq += 1
        ready_event = {
            "v": 1,
            "seq": self.seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "session.ready",
            "session_id": "s_test",
            "data": {
                "last_seq": self.seq,
                "assistant_state": {"state": "idle", "intensity": 0},
                "model": {"loaded": False},
                "pending_approvals": []
            }
        }
        await websocket.send_json(ready_event)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_event(self, websocket: WebSocket, event_type: str, data: dict, session_id: str = "s_test"):
        self.seq += 1
        event = {
            "v": 1,
            "seq": self.seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "session_id": session_id,
            "data": data
        }
        await websocket.send_json(event)

manager = ConnectionManager()

def _constant_time_compare(val1: str, val2: str) -> bool:
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

@router.websocket("/events")
async def websocket_endpoint(websocket: WebSocket):
    # WS subprotocol authentication
    expected_subprotocol = f"bearer.{settings.auth_token}"
    client_subprotocols = websocket.scope.get("subprotocols", [])
    
    if expected_subprotocol not in client_subprotocols:
        log.warning("ws_auth_failed", subprotocols=client_subprotocols)
        await websocket.close(code=1008) # Policy Violation
        return

    # Origin validation for WS
    origin = websocket.headers.get("origin")
    if not origin or origin not in ["http://tauri.localhost", "http://localhost:1420"]:
        log.warning("ws_invalid_origin", origin=origin)
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    log.info("ws_client_connected")
    
    try:
        while True:
            text_data = await websocket.receive_text()
            try:
                data = json.loads(text_data)
                msg_type = data.get("type")
                msg_data = data.get("data", {})
                
                # Phase 1 constraint: Replace agent.message echo with system/test echo
                if msg_type == "chat.send":
                    log.info("ws_chat_send_received")
                    await manager.send_event(websocket, "system.echo", {
                        "echoed_text": msg_data.get("text", "")
                    })
                elif msg_type == "client.hello":
                    log.info("ws_client_hello_received")
                else:
                    await manager.send_event(websocket, "agent.error", {
                        "code": "BAD_MESSAGE",
                        "message": f"Unknown type: {msg_type}"
                    })
            except json.JSONDecodeError:
                await websocket.close(code=1003) # Unsupported Data
                break
    except (WebSocketDisconnect, ConnectionClosedOK):
        manager.disconnect(websocket)
        log.info("ws_client_disconnected")
    except Exception as e:
        log.error("ws_error", error=str(e))
        manager.disconnect(websocket)
