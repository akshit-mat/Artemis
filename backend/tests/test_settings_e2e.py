import pytest
import os
import httpx
import asyncio
from fastapi.testclient import TestClient
from pathlib import Path

os.environ["ARTEMIS_AUTH_TOKEN"] = "a" * 64
os.environ["ARTEMIS_PORT"] = "1234"
from artemis.api.main import app, db, policy, registry, mediator
from artemis.storage.migrations import init_db
from artemis.policy.fsconfig import FilesystemScope
from artemis.tools.runtime import ToolRuntime

client = TestClient(app)

@pytest.mark.anyio
async def test_settings_roots_affect_tool_mediator(tmp_path):
    # Reset DB
    db.open()
    init_db(db)
    
    auth_headers = {"Authorization": "Bearer " + ("a" * 64), "host": "127.0.0.1:1234"}
    tmp_dir = str(tmp_path.resolve())
    
    # 1. Start with root not allowed. Submit write proposal using LIVE mediator.
    # 1. Start with root not allowed. Submit write proposal using LIVE mediator.
    
    # Prove it's rejected
    from artemis.tools.contract import CancelToken
    outcome = await mediator.handle_proposal(
        tool_name="write_file",
        raw_args={"path": os.path.join(tmp_dir, "test.txt"), "content": "hello"},
        run_id="run_1",
        session_id="s_test",
        user_turn_text="",
    )
    assert outcome.result is not None
    assert outcome.result.status == "denied"
    assert "outside the folders artemis is allowed to use" in outcome.result.summary.lower()
    
    # 2. Add root via real API
    response = client.post("/v1/settings/fs/roots", json={"root": tmp_dir, "confirm_risk": True}, headers=auth_headers)
    assert response.status_code == 200, response.json()
    
    # 3. Submit identical proposal using SAME live mediator
    task = asyncio.create_task(
        mediator.handle_proposal(
            tool_name="write_file",
            raw_args={"path": os.path.join(tmp_dir, "test.txt"), "content": "hello"},
            run_id="run_2",
            session_id="s_test",
            user_turn_text="",
        )
    )
    
    # Wait for it to hit the approval barrier (this proves ASK)
    await asyncio.sleep(0.5)
    
    # Assert it's still running (waiting for approval)
    assert not task.done()
    
    # Cancel it so we can proceed
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
        
    # 4. Remove root via real API
    response = client.request("DELETE", "/v1/settings/fs/roots", json={"root": tmp_dir}, headers=auth_headers)
    assert response.status_code == 200, response.json()
    
    # 5. Submit again
    outcome3 = await mediator.handle_proposal(
        tool_name="write_file",
        raw_args={"path": os.path.join(tmp_dir, "test.txt"), "content": "hello"},
        run_id="run_3",
        session_id="s_test",
        user_turn_text="",
    )
    assert outcome3.result is not None
    assert outcome3.result.status == "denied"
    assert "outside the folders artemis is allowed to use" in outcome3.result.summary.lower()
