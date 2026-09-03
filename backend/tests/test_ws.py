import pytest
import asyncio
from artemis.api.events import EventBus

def test_event_bus_publish():
    bus = EventBus()
    event = bus.publish("test.event", {"foo": "bar"})
    assert event["v"] == 1
    assert event["seq"] == 1
    assert event["type"] == "test.event"
    assert event["data"] == {"foo": "bar"}
    
    event2 = bus.publish("test.event2", {"baz": "qux"})
    assert event2["seq"] == 2

@pytest.mark.anyio
async def test_event_bus_subscribe():
    bus = EventBus()
    received = []
    
    async def sub(e):
        received.append(e)
        
    unsub = bus.subscribe(sub)
    
    bus.publish("t1", {})
    bus.publish("t2", {})
    
    await asyncio.sleep(0.01) # Yield to let tasks run
    assert len(received) == 2
    assert received[0]["type"] == "t1"
    
    unsub()
    bus.publish("t3", {})
    await asyncio.sleep(0.01)
    assert len(received) == 2 # Unsubscribed

def test_event_bus_replay():
    bus = EventBus()
    for i in range(600):
        bus.publish("event", {"i": i})
        
    assert bus.current_seq == 600
    
    # Within window (last 500)
    replay = bus.get_replay(500)
    assert replay is not None
    assert len(replay) == 100
    assert replay[0]["seq"] == 501
    
    # Outside window (older than 100)
    replay2 = bus.get_replay(99)
    assert replay2 is None

    # Entire window
    replay3 = bus.get_replay(100)
    assert replay3 is not None
    assert len(replay3) == 500
    assert replay3[0]["seq"] == 101

@pytest.mark.anyio
async def test_ws_backpressure_saturation():
    from artemis.api.ws import ClientConnection
    class MockWS:
        async def send_json(self, data):
            pass
        async def close(self, code):
            self.closed_code = code
            
    ws = MockWS()
    ws.closed_code = None
    conn = ClientConnection(ws)
    
    # Fill the queue with critical events (non-droppable)
    for i in range(1000):
        await conn.push_event({"type": "agent.error", "seq": i})
        
    assert conn.queue.full()
    
    # Attempt to push another critical event. Since no droppable events exist, it should disconnect.
    await conn.push_event({"type": "task.step", "seq": 1000})
    
    assert ws.closed_code == 1011
