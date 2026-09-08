
import pytest
import os
import uuid
import asyncio
from pathlib import Path
from fastapi.testclient import TestClient

os.environ['ARTEMIS_AUTH_TOKEN'] = 'a' * 64
os.environ['ARTEMIS_PORT'] = '1234'
from artemis.api.main import app, db, mediator, registry, fs_scope
from artemis.storage.migrations import init_db
from artemis.api.events import bus
from artemis.agent.loop import AgentOrchestrator
from test_agent_tools import FakeProvider, _tool_round, _text_round, model_registry
from artemis.storage.repositories.runs import RunRepository
from artemis.storage.repositories.messages import MessageRepository

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_db():
    db.open()
    init_db(db)
    bus._subscribers.clear()
    yield

@pytest.mark.anyio
async def test_full_agent_orchestrator_approval_path(tmp_path, model_registry):
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    tmp_dir = str(tmp_path.resolve())
    target_file = os.path.join(tmp_dir, 'orchestrator_target.txt')
    
    response = client.post('/v1/settings/fs/roots', json={'root': tmp_dir, 'confirm_risk': True}, headers=auth_headers)
    assert response.status_code == 200, response.json()
    
    queue = asyncio.Queue()
    async def sub(ev):
        await queue.put(ev)
    bus.subscribe(sub)
    
    provider: FakeProvider = model_registry.get_provider('primary')
    provider.scripted_rounds = [
        _tool_round('write_file', {'path': target_file, 'content': 'from the agent'}),
        _text_round('I have written the file.'),
    ]
    
    run_repo = RunRepository(db)
    msg_repo = MessageRepository(db)
    orchestrator = AgentOrchestrator(run_repo, msg_repo, model_registry, session_repo=None, mediator=mediator)
    
    run_id = await orchestrator.handle_chat('s_test', 'Write the file.')
    task = asyncio.create_task(orchestrator.run_conversation(run_id, 's_test'))
    
    approval_id = None
    while True:
        ev = await asyncio.wait_for(queue.get(), timeout=5.0)
        if ev['type'] == 'approval.requested':
            approval_id = ev['data']['approval_id']
            break
            
    response = client.post(f'/v1/approvals/{approval_id}', json={'action': 'allow', 'scope': 'once'}, headers=auth_headers)
    assert response.status_code == 200, response.json()
    
    await asyncio.wait_for(task, timeout=5.0)
    
    assert os.path.exists(target_file)
    with open(target_file, 'r', encoding='utf-8') as f:
        assert f.read() == 'from the agent'
        
