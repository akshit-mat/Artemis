
import pytest
import os
import asyncio
from fastapi.testclient import TestClient

os.environ['ARTEMIS_AUTH_TOKEN'] = 'a' * 64
os.environ['ARTEMIS_PORT'] = '1234'
from artemis.api.main import app, db, mediator
from artemis.storage.migrations import init_db
from artemis.api.events import bus

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_db():
    db.open()
    init_db(db)
    bus._subscribers.clear()
    yield

@pytest.mark.anyio
async def test_taint_escalation_lock(tmp_path):
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    tmp_dir = str(tmp_path.resolve())
    source_file = os.path.join(tmp_dir, 'source.txt')
    target_file = os.path.join(tmp_dir, 'target.txt')
    
    with open(source_file, 'w') as f:
        f.write('untrusted data')
    with open(target_file, 'w') as f:
        f.write('to be deleted')
        
    response = client.post('/v1/settings/fs/roots', json={'root': tmp_dir, 'confirm_risk': True}, headers=auth_headers)
    assert response.status_code == 200, response.json()
    assert tmp_dir in response.json()['allow_roots']
    
    run_id = 'r_taint_test'
    session_id = 's_test'
    
    # 0. Setup queue for approvals
    queue = asyncio.Queue()
    async def sub(ev):
        await queue.put(ev)
    bus.subscribe(sub)
    
    # 1. Read file to taint the run
    task1 = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='read_file',
            raw_args={'path': source_file},
            run_id=run_id,
            session_id=session_id,
            user_turn_text='',
        )
    )
    
    # Check if an approval is requested for read_file
    try:
        while True:
            ev = await asyncio.wait_for(queue.get(), timeout=5.0)
            if ev['type'] == 'approval.requested':
                client.post(f'/v1/approvals/{ev["data"]["approval_id"]}', json={'action': 'allow', 'scope': 'once'}, headers=auth_headers)
                break
    except asyncio.TimeoutError:
        pass
        
    outcome1 = await task1
    assert outcome1.result.trust == 'UNTRUSTED', outcome1.result.model_dump()
    
    # 2. Attempt destructive operation (delete_file) on the SAME run
    task2 = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='delete_file',
            raw_args={'paths': [target_file]},
            run_id=run_id,
            session_id=session_id,
            user_turn_text='',
        )
    )
    outcome2 = await task2
    assert outcome2.result.status == 'denied'
    assert outcome2.result.error_code == 'TAINTED_DESTRUCTIVE'
    
    # 3. Target file must still exist
    assert os.path.exists(target_file)
