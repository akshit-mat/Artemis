
import pytest
import os
import uuid
import asyncio
from pathlib import Path
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
async def test_real_backend_approval_lifecycle(tmp_path):
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    tmp_dir = str(tmp_path.resolve())
    target_file = os.path.join(tmp_dir, 'test.txt')
    
    response = client.post('/v1/settings/fs/roots', json={'root': tmp_dir, 'confirm_risk': True}, headers=auth_headers)
    assert response.status_code == 200, response.json()
    
    queue = asyncio.Queue()
    async def sub(ev):
        await queue.put(ev)
    bus.subscribe(sub)
    
    run_id = f'r_{uuid.uuid4().hex[:12]}'
    session_id = 's_test'
    call_id = f'tc_{uuid.uuid4().hex[:12]}'
    
    task = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='write_file',
            raw_args={'path': target_file, 'content': 'hello world'},
            run_id=run_id,
            session_id=session_id,
            user_turn_text='',
            call_id=call_id
        )
    )
    
    events = []
    approval_id = None
    while True:
        ev = await asyncio.wait_for(queue.get(), timeout=5.0)
        events.append(ev)
        if ev['type'] == 'approval.requested':
            approval_id = ev['data']['approval_id']
            break
            
    assert approval_id is not None
    assert not os.path.exists(target_file)
    
    response = client.post(f'/v1/approvals/{approval_id}', json={'action': 'allow', 'scope': 'once'}, headers=auth_headers)
    assert response.status_code == 200, response.json()
    
    outcome = await asyncio.wait_for(task, timeout=5.0)
    assert outcome.result is not None
    assert outcome.result.status == 'ok'
    
    assert os.path.exists(target_file)
    with open(target_file, 'r', encoding='utf-8') as f:
        assert f.read() == 'hello world'
    
    while True:
        try:
            ev = await asyncio.wait_for(queue.get(), timeout=0.5)
            events.append(ev)
        except asyncio.TimeoutError:
            break
            
    types = [e['type'] for e in events]
    assert 'tool.requested' in types
    assert 'tool.decision' in types
    assert 'approval.resolved' in types
    assert 'tool.started' in types
    assert 'tool.result' in types

@pytest.mark.anyio
async def test_approval_deny(tmp_path):
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    tmp_dir = str(tmp_path.resolve())
    target_file = os.path.join(tmp_dir, 'test2.txt')
    client.post('/v1/settings/fs/roots', json={'root': tmp_dir, 'confirm_risk': True}, headers=auth_headers)
    
    queue = asyncio.Queue()
    async def sub(ev):
        await queue.put(ev)
    bus.subscribe(sub)
    
    task = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='write_file',
            raw_args={'path': target_file, 'content': 'hello world'},
            run_id='r_test2',
            session_id='s_test',
            user_turn_text='',
        )
    )
    
    approval_id = None
    while True:
        ev = await asyncio.wait_for(queue.get(), timeout=5.0)
        if ev['type'] == 'approval.requested':
            approval_id = ev['data']['approval_id']
            break
            
    response = client.post(f'/v1/approvals/{approval_id}', json={'action': 'deny', 'scope': 'once'}, headers=auth_headers)
    assert response.status_code == 200
    
    outcome = await asyncio.wait_for(task, timeout=5.0)
    assert outcome.result is not None
    assert outcome.result.status == 'denied'
    assert not os.path.exists(target_file)

@pytest.mark.anyio
async def test_approval_invalid_id():
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    response = client.post('/v1/approvals/fake_id', json={'action': 'allow', 'scope': 'once'}, headers=auth_headers)
    assert response.status_code == 404

@pytest.mark.anyio
async def test_approval_already_resolved(tmp_path):
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    tmp_dir = str(tmp_path.resolve())
    client.post('/v1/settings/fs/roots', json={'root': tmp_dir, 'confirm_risk': True}, headers=auth_headers)
    
    queue = asyncio.Queue()
    async def sub(ev):
        await queue.put(ev)
    bus.subscribe(sub)
    
    task = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='write_file',
            raw_args={'path': os.path.join(tmp_dir, 'test3.txt'), 'content': 'hello world'},
            run_id='r_test3',
            session_id='s_test',
            user_turn_text='',
        )
    )
    
    approval_id = None
    while True:
        ev = await asyncio.wait_for(queue.get(), timeout=5.0)
        if ev['type'] == 'approval.requested':
            approval_id = ev['data']['approval_id']
            break
            
    response = client.post(f'/v1/approvals/{approval_id}', json={'action': 'allow', 'scope': 'once'}, headers=auth_headers)
    assert response.status_code == 200
    
    response2 = client.post(f'/v1/approvals/{approval_id}', json={'action': 'deny', 'scope': 'once'}, headers=auth_headers)
    assert response2.status_code in (400, 404, 409)
    
    await task

@pytest.mark.anyio
async def test_approval_argument_mutation(tmp_path):
    # D. ARGUMENT MUTATION / TOCTOU
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    tmp_dir = str(tmp_path.resolve())
    target_file = os.path.join(tmp_dir, 'test4.txt')
    client.post('/v1/settings/fs/roots', json={'root': tmp_dir, 'confirm_risk': True}, headers=auth_headers)
    
    queue = asyncio.Queue()
    async def sub(ev):
        await queue.put(ev)
    bus.subscribe(sub)
    
    task = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='write_file',
            raw_args={'path': target_file, 'content': 'hello world'},
            run_id='r_test4',
            session_id='s_test',
            user_turn_text='',
        )
    )
    
    approval_id = None
    while True:
        ev = await asyncio.wait_for(queue.get(), timeout=5.0)
        if ev['type'] == 'approval.requested':
            approval_id = ev['data']['approval_id']
            break
            
    # Resolve approval normally for target_file
    response = client.post(f'/v1/approvals/{approval_id}', json={'action': 'allow', 'scope': 'once'}, headers=auth_headers)
    assert response.status_code == 200
    
    # Wait for execution to finish
    await task
    
    # Now, attempt to use the same run context / mediator to execute a different file
    # This shouldn't be possible without a new approval, but we can verify it's blocked by Authorization hashes
    target_file2 = os.path.join(tmp_dir, 'test_toctou.txt')
    task2 = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='write_file',
            raw_args={'path': target_file2, 'content': 'hello world'},
            run_id='r_test4_2',
            session_id='s_test',
            user_turn_text='',
        )
    )
    
    # It must request a NEW approval, the old one must NOT carry over!
    while True:
        ev = await asyncio.wait_for(queue.get(), timeout=5.0)
        if ev['type'] == 'approval.requested':
            approval_id2 = ev['data']['approval_id']
            assert approval_id2 != approval_id
            break
    
    # Cancel task
    task2.cancel()
    try:
        await task2
    except asyncio.CancelledError:
        pass
    assert not os.path.exists(target_file2)
    
