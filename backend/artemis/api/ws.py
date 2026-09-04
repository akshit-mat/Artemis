import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from websockets.exceptions import ConnectionClosedOK

from ..obs.logging import get_logger
from ..config.baseline import WS_SUBPROTOCOL
from .events import bus
from .security import OriginVerdict

log = get_logger("ws")
router = APIRouter()

class ClientConnection:
    def __init__(self, websocket: WebSocket):
        self.ws = websocket
        self.queue = asyncio.Queue(maxsize=1000)
        
    async def push_event(self, event: Dict[str, Any]) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            # Backpressure handling per api.md
            items = []
            while not self.queue.empty():
                items.append(self.queue.get_nowait())
                
            dropped = False
            for drop_types in [("telemetry.sample", "voice.level"), ("agent.delta",)]:
                for i in range(len(items)):
                    if items[i].get("type") in drop_types:
                        items.pop(i)
                        dropped = True
                        break
                if dropped:
                    break

            for item in items:
                self.queue.put_nowait(item)
                
            try:
                self.queue.put_nowait(event)
            except asyncio.QueueFull:
                log.error("ws_queue_full_critical_events_disconnecting")
                # If we cannot drop any non-critical events, we MUST disconnect rather than silently dropping critical events.
                await self.ws.close(code=1011)

    async def sender_loop(self) -> None:
        try:
            while True:
                event = await self.queue.get()
                await self.ws.send_json(event)
                self.queue.task_done()
        except (WebSocketDisconnect, ConnectionClosedOK):
            pass
        except Exception as e:
            log.error("ws_sender_error", error=str(e))

@router.websocket("/events")
async def websocket_endpoint(websocket: WebSocket):
    app_state = websocket.app.state
    auth_token = app_state.auth_token
    policy = app_state.policy
    
    # 1. Host Validation
    host = websocket.headers.get("host")
    if not policy.check_host(host):
        log.warning("ws_invalid_host_rejected", host=host)
        await websocket.close(code=1008)
        return

    # 2. Origin Validation
    if policy.requires_origin(websocket.url.path):
        origin = websocket.headers.get("origin")
        verdict = policy.check_origin(origin)
        if verdict == OriginVerdict.REJECTED or verdict == OriginVerdict.MISSING:
            log.warning("ws_invalid_origin_rejected", origin=origin)
            await websocket.close(code=1008)
            return

    # 3. Token Authentication
    client_subprotocols = websocket.scope.get("subprotocols", [])
    if not auth_token.verify_subprotocols(client_subprotocols):
        log.warning("ws_auth_failed")
        await websocket.close(code=1008) # Policy Violation
        return

    await websocket.accept(subprotocol=WS_SUBPROTOCOL)
    log.info("ws_client_connected")
    
    conn = ClientConnection(websocket)
    
    ready_event = {
        "v": 1,
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "session.ready",
        "session_id": "s_test",
        "data": {
            "last_seq": bus.current_seq,
            "assistant_state": {"state": "idle", "intensity": 0},
            "model": {"loaded": False},
            "pending_approvals": []
        }
    }
    await conn.push_event(ready_event)
    
    sender_task = asyncio.create_task(conn.sender_loop())
    
    async def on_bus_event(event: dict) -> None:
        await conn.push_event(event)
        
    unsubscribe = bus.subscribe(on_bus_event)
    
    try:
        while True:
            text_data = await websocket.receive_text()
            try:
                data = json.loads(text_data)
                msg_type = data.get("type")
                msg_data = data.get("data", {})
                
                if msg_type == "client.hello":
                    last_seq = msg_data.get("last_seq", 0)
                    replay_events = bus.get_replay(last_seq)
                    if replay_events is None:
                        await conn.push_event({
                            "v": 1,
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "type": "client.resync_required",
                            "session_id": "s_test",
                            "data": {"last_seq": bus.current_seq},
                        })
                    else:
                        for e in replay_events:
                            await conn.push_event(e)
                elif msg_type == "chat.send":
                    bus.publish("system.echo", {"echoed_text": msg_data.get("text", "")})
                else:
                    bus.publish("agent.error", {
                        "code": "BAD_MESSAGE",
                        "message": f"Unknown type: {msg_type}",
                        "recoverable": True,
                        "correlation_id": None
                    })
            except json.JSONDecodeError:
                await websocket.close(code=1003) # Unsupported Data
                break
    except (WebSocketDisconnect, ConnectionClosedOK):
        log.info("ws_client_disconnected")
    except Exception as e:
        log.error("ws_error", error=str(e))
    finally:
        unsubscribe()
        sender_task.cancel()
