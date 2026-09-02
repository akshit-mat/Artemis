import pytest
from fastapi.testclient import TestClient
from artemis.api.main import app
from artemis.config.settings import settings

client = TestClient(app)

def test_health_unauthenticated():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_auth_rejected():
    response = client.get("/v1/some-path")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"

def test_origin_validation():
    headers = {
        "Authorization": f"Bearer {settings.auth_token}",
        "Origin": "http://evil.com"
    }
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ORIGIN_REJECTED"

def test_origin_allowed():
    headers = {
        "Authorization": f"Bearer {settings.auth_token}",
        "Origin": "http://tauri.localhost"
    }
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 404

def test_ws_connection_and_echo():
    headers = {
        "Origin": "http://tauri.localhost"
    }
    subprotocols = [f"bearer.{settings.auth_token}"]
    with client.websocket_connect("/v1/events", headers=headers, subprotocols=subprotocols) as websocket:
        # First message should be session.ready
        data = websocket.receive_json()
        assert data["type"] == "session.ready"
        assert data["seq"] == 1
        
        # Test echo
        websocket.send_json({"type": "chat.send", "data": {"text": "hello"}})
        response = websocket.receive_json()
        assert response["type"] == "system.echo"
        assert response["data"]["echoed_text"] == "hello"
        assert response["seq"] == 2
