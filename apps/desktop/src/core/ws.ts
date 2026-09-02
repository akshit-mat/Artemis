import { useStore } from '../state/store';

let ws: WebSocket | null = null;
let currentSeq = 0;

export function connectWs(port: number, token: string) {
  const store = useStore.getState();
  store.setWsStatus('connecting');

  ws = new WebSocket(`ws://127.0.0.1:${port}/v1/events`, [
    'artemis.v1',
    `bearer.${token}`,
  ]);

  ws.onopen = () => {
    store.setWsStatus('connected');
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.seq) {
        // Enforce sequence monotonicity conceptually
        if (data.seq <= currentSeq && currentSeq !== 0) {
            console.warn("Out of order sequence received:", data.seq);
        }
        currentSeq = data.seq;
      }

      if (data.type === 'session.ready') {
        store.setLastMessage('session.ready received');
      } else if (data.type === 'system.echo') {
        store.setLastMessage(`Echo: ${data.data.echoed_text}`);
      } else {
        store.setLastMessage(`Received: ${data.type}`);
      }
    } catch (e) {
      console.error('Failed to parse WS message', e);
    }
  };

  ws.onclose = () => {
    store.setWsStatus('disconnected');
    ws = null;
  };

  ws.onerror = (error) => {
    store.setWsStatus('error');
    console.error('WS Error:', error);
  };
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
  if (ws) {
    ws.close();
  }
}
