
import pytest
import os
import asyncio
from pathlib import Path
from fastapi.testclient import TestClient

os.environ['ARTEMIS_AUTH_TOKEN'] = 'a' * 64
os.environ['ARTEMIS_PORT'] = '1234'
from artemis.api.main import app, db, mediator
from artemis.storage.migrations import init_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_db():
    db.open()
    init_db(db)
    yield

@pytest.mark.anyio
async def test_fs_security_e2e(tmp_path):
    auth_headers = {'Authorization': 'Bearer ' + ('a' * 64), 'host': '127.0.0.1:1234'}
    
    base_dir = tmp_path / 'base'
    allowed_dir = base_dir / 'allowed'
    sibling_dir = base_dir / 'allowed_sibling'
    outside_dir = base_dir / 'outside'
    
    os.makedirs(allowed_dir, exist_ok=True)
    os.makedirs(sibling_dir, exist_ok=True)
    os.makedirs(outside_dir, exist_ok=True)
    
    with open(allowed_dir / '..' / 'outside' / 'file.txt', 'w') as f: f.write('x')
    with open(sibling_dir / 'file.txt', 'w') as f: f.write('x')
    
    os.makedirs(allowed_dir / '.git', exist_ok=True)
    with open(allowed_dir / '.git' / 'config', 'w') as f: f.write('x')
    
    client.post('/v1/settings/fs/roots', json={'root': str(allowed_dir), 'confirm_risk': True}, headers=auth_headers)
    
    run_id = 'r_fs_test'
    session_id = 's_test'
    
    # 1. Path traversal (../)
    task1 = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='read_file',
            raw_args={'path': str(allowed_dir / '..' / 'outside' / 'file.txt')},
            run_id=run_id,
            session_id=session_id,
            user_turn_text='',
        )
    )
    outcome1 = await task1
    assert outcome1.result.status == 'denied'
    assert outcome1.result.error_code == 'PATH_OUT_OF_SCOPE'
    
    # 2. Sibling prefix attack
    task2 = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='read_file',
            raw_args={'path': str(sibling_dir / 'file.txt')},
            run_id=run_id,
            session_id=session_id,
            user_turn_text='',
        )
    )
    outcome2 = await task2
    assert outcome2.result.status == 'denied'
    assert outcome2.result.error_code == 'PATH_OUT_OF_SCOPE'
    
    # 3. Protected path (secret-shaped)
    with open(allowed_dir / 'id_rsa', 'w') as f: f.write('x')
    task3 = asyncio.create_task(
        mediator.handle_proposal(
            tool_name='read_file',
            raw_args={'path': str(allowed_dir / 'id_rsa')},
            run_id=run_id,
            session_id=session_id,
            user_turn_text='',
        )
    )
    outcome3 = await task3
    assert outcome3.result.status == 'denied'
    assert outcome3.result.error_code == 'PATH_DENIED'
    
    # 4. Junction escape
    import subprocess
    junction_path = allowed_dir / 'escape'
    try:
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction_path), str(outside_dir)], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        pass # Skip if we cannot create junction
    else:
        task4 = asyncio.create_task(
            mediator.handle_proposal(
                tool_name='read_file',
                raw_args={'path': str(junction_path / 'file.txt')},
                run_id=run_id,
                session_id=session_id,
                user_turn_text='',
            )
        )
        outcome4 = await task4
        assert outcome4.result.status == 'denied'
        assert outcome4.result.error_code == 'PATH_OUT_OF_SCOPE'
