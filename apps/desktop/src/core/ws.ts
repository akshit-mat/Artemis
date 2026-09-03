import { useStore } from '../state/store';
import type { components } from '../api/types';

type WSEnvelope = components["schemas"]["WSEnvelope"];
type SessionReadyData = components["schemas"]["SessionReadyData"];
type AssistantStateData = components["schemas"]["AssistantStateData"];

let ws: WebSocket | null = null;
let currentSeq = 0;
let reconnectTimer: any = null;
let reconnectAttempts = 0;
let isIntentionalDisconnect = false;

let backendPort = 0;
let backendToken = '';

export function connectWs(port: number, token: string) {
  backendPort = port;
  backendToken = token;
  isIntentionalDisconnect = false;
  connectInternal();
}

function connectInternal() {
  const store = useStore.getState();
  store.setWsStatus('connecting');

  ws = new WebSocket(`ws://127.0.0.1:${backendPort}/v1/events`, [
    'artemis.v1',
    `bearer.${backendToken}`,
  ]);

  ws.onopen = () => {
    store.setWsStatus('connected');
    reconnectAttempts = 0;
    
    // Send client.hello with the last seen sequence number
    ws?.send(JSON.stringify({
      type: 'client.hello',
      data: { last_seq: currentSeq }
    }));
  };

    ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data) as WSEnvelope;
      
      if (data.seq) {
        if (data.seq <= currentSeq && currentSeq !== 0) {
            console.warn("Out of order sequence received:", data.seq);
        } else if (data.seq > currentSeq + 1 && currentSeq !== 0) {
            console.warn("Sequence gap detected:", currentSeq, "->", data.seq);
            // In a robust implementation, a gap should trigger resync, but for now we accept the replay.
        }
        currentSeq = data.seq;
      }

      store.appendEvent(data);

      if (data.type === 'session.ready') {
        const payload = data.data as unknown as SessionReadyData;
        store.setAssistantState(payload.assistant_state);
        // Note: we could update currentSeq to payload.last_seq here if we wanted
      } else if (data.type === 'agent.state') {
        const payload = data.data as unknown as AssistantStateData;
        store.setAssistantState(payload);
      } else if (data.type === 'client.resync_required') {
        console.warn("Resync required. Fetching full state... (stubbed)");
        // Phase 1 doesn't have a real HTTP resync endpoint yet, so we just reset sequence.
        currentSeq = 0;
      }
    } catch (e) {
      console.error('Failed to parse WS message', e);
    }
  };

  ws.onclose = () => {
    store.setWsStatus('disconnected');
    ws = null;
    
    if (!isIntentionalDisconnect) {
      scheduleReconnect();
    }
  };

  ws.onerror = (error) => {
    store.setWsStatus('error');
    console.error('WS Error:', error);
  };
}

function scheduleReconnect() {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  
  // Exponential backoff: max 30 seconds
  const backoff = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
  reconnectAttempts++;
  
  console.log(`Scheduling reconnect in ${backoff}ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => {
    if (!isIntentionalDisconnect) {
      connectInternal();
    }
  }, backoff);
}

export function sendTestMessage(text: string) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'chat.send',
      data: { text }
    }));
  }
}

export function disconnectWs() {
  isIntentionalDisconnect = true;
  if (reconnectTimer) clearTimeout(reconnectTimer);
  if (ws) {
    ws.close();
    ws = null;
  }
}
