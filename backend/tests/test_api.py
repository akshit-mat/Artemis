import os
import pytest
from fastapi.testclient import TestClient

# Must set env vars before importing app
TOKEN = "0" * 64
os.environ["ARTEMIS_AUTH_TOKEN"] = TOKEN
os.environ["ARTEMIS_PORT"] = "1234"
os.environ["ARTEMIS_HOST"] = "127.0.0.1"

from artemis.api.main import app, auth_token, policy

client = TestClient(app)

def test_health_unauthenticated():
    response = client.get("/health", headers={"host": "127.0.0.1:1234"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_auth_rejected():
    headers = {"host": "127.0.0.1:1234"}
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"

def test_origin_validation():
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Origin": "http://evil.com",
        "host": "127.0.0.1:1234"
    }
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ORIGIN_REJECTED"

def test_origin_allowed():
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Origin": "http://tauri.localhost",
        "host": "127.0.0.1:1234"
    }
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 404

def test_ws_connection_and_echo():
    # Since lifespan is required to open the DB, we must use TestClient with context manager
    with TestClient(app) as client_context:
        headers = {
            "Origin": "http://tauri.localhost",
            "host": "127.0.0.1:1234"
        }
        subprotocols = ["artemis.v1", f"bearer.{TOKEN}"]
        with client_context.websocket_connect("/v1/events", headers=headers, subprotocols=subprotocols) as websocket:
            # First message should be session.ready (connection-specific, not on the event bus history)
            data = websocket.receive_json()
            assert data["type"] == "session.ready"
            assert data["data"]["last_seq"] == 0
            
            # Test echo
            websocket.send_json({"type": "chat.send", "data": {"text": "hello"}})
            response = websocket.receive_json()
            assert response["type"] == "system.echo"
            assert response["data"]["echoed_text"] == "hello"
            assert response["seq"] == 1

def test_ws_security_validation():
    with TestClient(app) as client_context:
        valid_headers = {
            "Origin": "http://tauri.localhost",
            "host": "127.0.0.1:1234"
        }
        subprotocols = ["artemis.v1", f"bearer.{TOKEN}"]
        
        # Valid connection
        with client_context.websocket_connect("/v1/events", headers=dict(valid_headers), subprotocols=subprotocols) as websocket:
            assert websocket.receive_json()["type"] == "session.ready"
            websocket.close()

        # Invalid Origin
        invalid_origin = dict(valid_headers)
        invalid_origin["Origin"] = "http://evil.com"
        from starlette.websockets import WebSocketDisconnect
        with pytest.raises(WebSocketDisconnect):
            with client_context.websocket_connect("/v1/events", headers=invalid_origin, subprotocols=subprotocols) as websocket:
                websocket.receive_json()
                
        # Missing Origin
        missing_origin = dict(valid_headers)
        del missing_origin["Origin"]
        with pytest.raises(WebSocketDisconnect):
            with client_context.websocket_connect("/v1/events", headers=missing_origin, subprotocols=subprotocols) as websocket:
                websocket.receive_json()
                
        # Invalid Host
        invalid_host = dict(valid_headers)
        invalid_host["host"] = "evil.com"
        with pytest.raises(WebSocketDisconnect):
            with client_context.websocket_connect("/v1/events", headers=invalid_host, subprotocols=subprotocols) as websocket:
                websocket.receive_json()

        # Invalid Auth
        with TestClient(app) as fresh_client:
            invalid_auth_subs = ["artemis.v1", "bearer.WRONG"]
            with pytest.raises(WebSocketDisconnect):
                with fresh_client.websocket_connect("/v1/events", headers=dict(valid_headers), subprotocols=invalid_auth_subs) as websocket:
                    websocket.receive_json()

def test_no_token_leak_in_logs(capsys, caplog):
    import logging
    from starlette.websockets import WebSocketDisconnect
    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as client_context:
            headers = {
                "Origin": "http://tauri.localhost",
                "host": "127.0.0.1:1234"
            }
            # Failing auth path
            failed_subprotocols = ["artemis.v1", f"bearer.{TOKEN}WRONG"]
            with pytest.raises(WebSocketDisconnect):
                with client_context.websocket_connect("/v1/events", headers=dict(headers), subprotocols=failed_subprotocols) as websocket:
                    websocket.receive_json()
    
    captured = capsys.readouterr()
    assert TOKEN not in captured.out
    assert TOKEN not in captured.err
    for record in caplog.records:
        assert TOKEN not in record.getMessage()
