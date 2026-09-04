import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { useStore } from '../state/store';
import { connectWs, disconnectWs, __resetSeqForTest } from './ws';

// ── Mock WebSocket ───────────────────────────────────────────────────────────
class MockWebSocket {
  static instances: MockWebSocket[] = [];
  
  url: string;
  protocols: string | string[];
  readyState: number = 1; // OPEN
  
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: ((error: any) => void) | null = null;
  
  send = vi.fn();
  close = vi.fn(() => {
    this.readyState = 3; // CLOSED
    if (this.onclose) this.onclose();
  });

  constructor(url: string, protocols: string | string[]) {
    this.url = url;
    this.protocols = protocols;
    MockWebSocket.instances.push(this);
  }

  // Helper to simulate server sending a message
  simulateMessage(data: any) {
    if (this.onmessage) {
      this.onmessage({ data: JSON.stringify(data) });
    }
  }
}

// ── Test Suite ───────────────────────────────────────────────────────────────
describe('WebSocket Client', () => {
  beforeEach(() => {
    // Reset Zustand store
    useStore.setState({
      wsStatus: 'disconnected',
      eventTimeline: [],
      assistantState: { state: 'idle', intensity: 0 },
    });
    
    // Reset module seq state
    __resetSeqForTest();

    // Setup mocks
    vi.stubGlobal('WebSocket', MockWebSocket);
    vi.stubGlobal('fetch', vi.fn());
    
    // Use fake timers to control reconnect backoff immediately
    vi.useFakeTimers();
    MockWebSocket.instances = [];
  });

  afterEach(() => {
    disconnectWs();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('detects a sequence gap and triggers reconnect-based recovery', () => {
    // 1. Initial connection
    connectWs(1234, 'mock-token');
    
    expect(MockWebSocket.instances.length).toBe(1);
    const ws1 = MockWebSocket.instances[0];
    
    // Simulate connection established
    if (ws1.onopen) ws1.onopen();
    
    // The client should send client.hello with last_seq: 0
    expect(ws1.send).toHaveBeenCalledWith(JSON.stringify({
      type: 'client.hello',
      data: { last_seq: 0 }
    }));
    
    // 2. Server sends session.ready with last_seq: 10
    ws1.simulateMessage({
      type: 'session.ready',
      seq: 10,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {
        last_seq: 10,
        assistant_state: { state: 'idle', intensity: 0 },
        model: {},
        pending_approvals: []
      }
    });
    
    // currentSeq should now be 10. Let's send an event with seq: 11 (valid next sequence)
    ws1.simulateMessage({
      type: 'test.event',
      seq: 11,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {}
    });
    
    // The store should have this event
    expect(useStore.getState().eventTimeline).toHaveLength(2); // test.event + session.ready
    
    // 3. Server sends event with seq: 13 (GAP of seq 12!)
    ws1.simulateMessage({
      type: 'test.gap',
      seq: 13, // Expected 12
      ts: '2023-01-01',
      session_id: 's_1',
      data: {}
    });
    
    // The gap should trigger a ws.close()
    expect(ws1.close).toHaveBeenCalled();
    
    // The event from the gap should NOT be appended to the store (it was dropped)
    expect(useStore.getState().eventTimeline).toHaveLength(2);
    
    // 4. Fast-forward the reconnect timer
    vi.runAllTimers();
    
    // A new WebSocket connection should have been created
    expect(MockWebSocket.instances.length).toBe(2);
    const ws2 = MockWebSocket.instances[1];
    
    if (ws2.onopen) ws2.onopen();
    
    // 5. Verify the client requests replay from the LAST KNOWN valid sequence (11)
    expect(ws2.send).toHaveBeenCalledWith(JSON.stringify({
      type: 'client.hello',
      data: { last_seq: 11 }
    }));
    
    // 6. Server replays the missing event (seq 12)
    ws2.simulateMessage({
      type: 'test.replayed',
      seq: 12,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {}
    });
    
    expect(useStore.getState().eventTimeline).toHaveLength(3);
  });

  it('ignores duplicate and out-of-order events without regressing currentSeq', () => {
    connectWs(1234, 'mock-token');
    const ws = MockWebSocket.instances[0];
    if (ws.onopen) ws.onopen();
    
    // Server sends session.ready with last_seq: 50
    ws.simulateMessage({
      type: 'session.ready',
      seq: 50,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {
        last_seq: 50,
        assistant_state: { state: 'idle', intensity: 0 },
        model: {},
        pending_approvals: []
      }
    });
    
    // Valid next event (51)
    ws.simulateMessage({
      type: 'test.valid',
      seq: 51,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {}
    });
    
    const eventsCount = useStore.getState().eventTimeline.length;
    
    // Duplicate event (51)
    ws.simulateMessage({
      type: 'test.duplicate',
      seq: 51,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {}
    });
    
    // Out of order old event (40)
    ws.simulateMessage({
      type: 'test.old',
      seq: 40,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {}
    });
    
    // Neither should be added, connection should NOT close
    expect(useStore.getState().eventTimeline.length).toBe(eventsCount);
    expect(ws.close).not.toHaveBeenCalled();
    
    // Valid next event (52) is still accepted
    ws.simulateMessage({
      type: 'test.next',
      seq: 52,
      ts: '2023-01-01',
      session_id: 's_1',
      data: {}
    });
    
    expect(useStore.getState().eventTimeline.length).toBe(eventsCount + 1);
  });
});
