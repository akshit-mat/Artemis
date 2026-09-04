import os
import pytest
from fastapi.testclient import TestClient

# Must set env vars before importing app
TOKEN = "0" * 64
os.environ["ARTEMIS_AUTH_TOKEN"] = TOKEN
os.environ["ARTEMIS_PORT"] = "1234"
os.environ["ARTEMIS_HOST"] = "127.0.0.1"

from artemis.api.main import app, auth_token, policy
from artemis.api.security import TransportPolicy

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

VALID_HEADERS = {
    "host": "127.0.0.1:1234",
    "Origin": "http://tauri.localhost",
    "Authorization": f"Bearer {TOKEN}",
}

client = TestClient(app)


# ---------------------------------------------------------------------------
# Health / unauthenticated
# ---------------------------------------------------------------------------

def test_health_unauthenticated():
    response = client.get("/health", headers={"host": "127.0.0.1:1234"})
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def test_auth_rejected():
    headers = {"host": "127.0.0.1:1234"}
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_origin_validation():
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Origin": "http://evil.com",
        "host": "127.0.0.1:1234",
    }
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ORIGIN_REJECTED"


def test_origin_allowed():
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Origin": "http://tauri.localhost",
        "host": "127.0.0.1:1234",
    }
    response = client.get("/v1/some-path", headers=headers)
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Production transport policy rejects testserver (regression)
# ---------------------------------------------------------------------------

def test_production_policy_rejects_testserver():
    """The production TransportPolicy must not allow 'testserver'.

    Regression guard for the Phase 1 gap where for_testing() was used in
    production code, allowing an internal test-only host into production.
    """
    prod_policy = TransportPolicy.for_binding("127.0.0.1", 1234, dev_mode=False)
    assert not prod_policy.check_host("testserver"), (
        "Production policy must not accept 'testserver' as a valid Host"
    )
    assert prod_policy.check_host("127.0.0.1:1234"), (
        "Production policy must accept the actual bound host:port"
    )


# ---------------------------------------------------------------------------
# HTTP body size limit (api.md §1: ≤ 1 MiB)
# ---------------------------------------------------------------------------

def test_body_limit_below_max():
    """Requests at or below 1 MiB must be accepted."""
    headers = {**VALID_HEADERS, "content-type": "application/json"}
    body = b'{"text": "' + b"a" * 100 + b'"}'
    headers["content-length"] = str(len(body))
    response = client.post("/v1/some-path", content=body, headers=headers)
    # 404 is expected (endpoint doesn't exist), but NOT 413
    assert response.status_code != 413


def test_body_limit_exact_boundary():
    """A body of exactly MAX_HTTP_BODY_BYTES must be accepted."""
    from artemis.config.baseline import MAX_HTTP_BODY_BYTES
    headers = {**VALID_HEADERS, "content-type": "application/octet-stream"}
    headers["content-length"] = str(MAX_HTTP_BODY_BYTES)
    response = client.post("/v1/some-path", content=b"x" * MAX_HTTP_BODY_BYTES, headers=headers)
    assert response.status_code != 413


def test_body_limit_above_max():
    """A body exceeding the limit must be rejected with 413 PAYLOAD_TOO_LARGE."""
    from artemis.config.baseline import MAX_HTTP_BODY_BYTES
    headers = {**VALID_HEADERS, "content-type": "application/octet-stream"}
    oversized = MAX_HTTP_BODY_BYTES + 1
    headers["content-length"] = str(oversized)
    response = client.post("/v1/some-path", headers=headers)
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


# ---------------------------------------------------------------------------
# Session state endpoint — GET /v1/sessions/{id}/state
# ---------------------------------------------------------------------------

def test_session_state_returns_ok():
    """GET /v1/sessions/s_test/state must return authoritative state."""
    with TestClient(app) as c:
        response = c.get(
            "/v1/sessions/s_test/state",
            headers=dict(VALID_HEADERS),
        )
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == "s_test"
    assert "last_seq" in data
    assert isinstance(data["last_seq"], int)
    assert "assistant_state" in data
    assert "state" in data["assistant_state"]
    assert "intensity" in data["assistant_state"]


def test_session_state_not_found():
    """An unknown session_id must return 404 with NOT_FOUND error code."""
    with TestClient(app) as c:
        response = c.get(
            "/v1/sessions/nonexistent-session/state",
            headers=dict(VALID_HEADERS),
        )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_session_state_requires_auth():
    """GET /v1/sessions/{id}/state must reject unauthenticated requests."""
    with TestClient(app) as c:
        headers_no_auth = {
            "host": "127.0.0.1:1234",
            "Origin": "http://tauri.localhost",
        }
        response = c.get("/v1/sessions/s_test/state", headers=headers_no_auth)
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# WebSocket tests
# ---------------------------------------------------------------------------

def test_ws_connection_and_echo():
    with TestClient(app) as client_context:
        headers = {
            "Origin": "http://tauri.localhost",
            "host": "127.0.0.1:1234",
        }
        subprotocols = ["artemis.v1", f"bearer.{TOKEN}"]
        with client_context.websocket_connect(
            "/v1/events", headers=headers, subprotocols=subprotocols
        ) as websocket:
            data = websocket.receive_json()
            assert data["type"] == "session.ready"
            assert data["data"]["last_seq"] == 0

            websocket.send_json({"type": "chat.send", "data": {"text": "hello"}})
            response = websocket.receive_json()
            assert response["type"] == "system.echo"
            assert response["data"]["echoed_text"] == "hello"
            assert response["seq"] == 1


def test_ws_security_validation():
    with TestClient(app) as client_context:
        valid_headers = {
            "Origin": "http://tauri.localhost",
            "host": "127.0.0.1:1234",
        }
        subprotocols = ["artemis.v1", f"bearer.{TOKEN}"]

        with client_context.websocket_connect(
            "/v1/events", headers=dict(valid_headers), subprotocols=subprotocols
        ) as websocket:
            assert websocket.receive_json()["type"] == "session.ready"
            websocket.close()

        from starlette.websockets import WebSocketDisconnect

        # Invalid Origin
        bad_origin = {**valid_headers, "Origin": "http://evil.com"}
        with pytest.raises(WebSocketDisconnect):
            with client_context.websocket_connect(
                "/v1/events", headers=bad_origin, subprotocols=subprotocols
            ) as ws:
                ws.receive_json()

        # Missing Origin
        no_origin = {k: v for k, v in valid_headers.items() if k != "Origin"}
        with pytest.raises(WebSocketDisconnect):
            with client_context.websocket_connect(
                "/v1/events", headers=no_origin, subprotocols=subprotocols
            ) as ws:
                ws.receive_json()

        # Invalid Host
        bad_host = {**valid_headers, "host": "evil.com"}
        with pytest.raises(WebSocketDisconnect):
            with client_context.websocket_connect(
                "/v1/events", headers=bad_host, subprotocols=subprotocols
            ) as ws:
                ws.receive_json()

        # Invalid Auth
        with TestClient(app) as fresh_client:
            with pytest.raises(WebSocketDisconnect):
                with fresh_client.websocket_connect(
                    "/v1/events",
                    headers=dict(valid_headers),
                    subprotocols=["artemis.v1", "bearer.WRONG"],
                ) as ws:
                    ws.receive_json()


def test_ws_resync_required_contains_last_seq():
    """client.resync_required must include last_seq so the frontend can call the state endpoint."""
    from artemis.api.events import EventBus

    # A fresh bus with a known seq history
    test_bus = EventBus()
    for i in range(10):
        test_bus.publish("test.event", {"i": i})

    # Publish beyond the replay buffer window to force resync
    replay = test_bus.get_replay(0)  # asking for seq > 0 from the beginning
    assert replay is not None  # within window

    replay_none = test_bus.get_replay(-1)  # simulate out-of-window request
    assert replay_none is None

    # Verify the payload structure
    import asyncio
    from artemis.api.events import bus as global_bus

    # Publish events to give the bus a non-zero seq
    for _ in range(5):
        global_bus.publish("test.filler", {})

    with TestClient(app) as c:
        headers = {"Origin": "http://tauri.localhost", "host": "127.0.0.1:1234"}
        subprotocols = ["artemis.v1", f"bearer.{TOKEN}"]
        with c.websocket_connect("/v1/events", headers=headers, subprotocols=subprotocols) as ws:
            ws.receive_json()  # session.ready

            # Request replay from an impossibly old seq to force resync_required
            ws.send_json({"type": "client.hello", "data": {"last_seq": -1}})
            msg = ws.receive_json()
            assert msg["type"] == "client.resync_required"
            # The payload MUST include last_seq so the frontend knows where to resume
            assert "last_seq" in msg["data"]
            assert isinstance(msg["data"]["last_seq"], int)


def test_no_token_leak_in_logs(capsys, caplog):
    import logging
    from starlette.websockets import WebSocketDisconnect

    with caplog.at_level(logging.DEBUG):
        with TestClient(app) as client_context:
            headers = {
                "Origin": "http://tauri.localhost",
                "host": "127.0.0.1:1234",
            }
            # Failing auth path — raw token appears in the subprotocol list
            failed_subprotocols = ["artemis.v1", f"bearer.{TOKEN}WRONG"]
            with pytest.raises(WebSocketDisconnect):
                with client_context.websocket_connect(
                    "/v1/events",
                    headers=dict(headers),
                    subprotocols=failed_subprotocols,
                ) as websocket:
                    websocket.receive_json()

    captured = capsys.readouterr()
    assert TOKEN not in captured.out
    assert TOKEN not in captured.err
    for record in caplog.records:
        assert TOKEN not in record.getMessage()
