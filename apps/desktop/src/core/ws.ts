import { useStore } from '../state/store';
import type { components } from '../api/types';

type WSEnvelope = components["schemas"]["WSEnvelope"];
type SessionReadyData = components["schemas"]["SessionReadyData"];
type AssistantStateData = components["schemas"]["AssistantStateData"];
type SessionStateResponse = components["schemas"]["SessionStateResponse"];

let ws: WebSocket | null = null;
let currentSeq = 0;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectAttempts = 0;
let isIntentionalDisconnect = false;
let isResyncing = false;  // prevents concurrent/looping resyncs

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

    // Send client.hello with the last seen sequence number so the server
    // can replay any missed events (api.md §4).
    ws?.send(JSON.stringify({
      type: 'client.hello',
      data: { last_seq: currentSeq },
    }));
  };

  ws.onmessage = (event) => {
    try {
      const envelope = JSON.parse(event.data) as WSEnvelope;

      // ── Sequence tracking ──────────────────────────────────────────────
      if (envelope.seq != null) {
        if (currentSeq !== 0) {
          if (envelope.seq <= currentSeq) {
            // Duplicate or out-of-order — ignore to avoid double-applying.
            console.warn('Ignoring duplicate/out-of-order seq:', envelope.seq, '(current:', currentSeq + ')');
            return;
          }
          if (envelope.seq > currentSeq + 1) {
            // Sequence gap detected! Force a reconnect so the backend replays missed events.
            console.warn('Sequence gap detected:', envelope.seq, '(expected:', currentSeq + 1, ') — forcing reconnect');
            if (ws) {
              ws.close(); // Triggers onclose which schedules a reconnect with the correct currentSeq
            }
            return;
          }
        }
        currentSeq = envelope.seq;
      }

      store.appendEvent(envelope);

      // ── Event dispatch ─────────────────────────────────────────────────
      if (envelope.type === 'session.ready') {
        const payload = envelope.data as unknown as SessionReadyData;
        // Initialise sequence cursor from authoritative last_seq.
        if (payload.last_seq > currentSeq) {
          currentSeq = payload.last_seq;
        }
        store.setAssistantState(payload.assistant_state);

      } else if (envelope.type === 'agent.state') {
        const payload = envelope.data as unknown as AssistantStateData;
        store.setAssistantState(payload);

      } else if (envelope.type === 'client.resync_required') {
        // The server's replay buffer no longer covers our last_seq.
        // Fetch authoritative state from the HTTP endpoint and restore.
        const sessionId = envelope.session_id;
        performResync(sessionId).catch((e) =>
          console.error('Resync failed:', e)
        );
      }
      // Cross-phase invariant (roadmap.md §14.8): unknown event types are
      // tolerated — we log and continue rather than crash.

    } catch (e) {
      console.error('Failed to parse WS message:', e);
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

/**
 * Perform a full resync from GET /v1/sessions/{id}/state.
 *
 * Called when the server signals client.resync_required (api.md §4).
 *
 * Race handling: events arriving over the WebSocket during the HTTP fetch are
 * processed normally because currentSeq is only advanced, never regressed.
 * The guard `isResyncing` prevents concurrent resyncs and avoids feedback loops.
 */
async function performResync(sessionId: string): Promise<void> {
  if (isResyncing) {
    console.warn('Resync already in progress — skipping duplicate trigger');
    return;
  }
  isResyncing = true;

  try {
    console.log(`Resyncing session ${sessionId} from authoritative state...`);

    const response = await fetch(
      `http://127.0.0.1:${backendPort}/v1/sessions/${sessionId}/state`,
      {
        headers: {
          Authorization: `Bearer ${backendToken}`,
          Origin: 'http://tauri.localhost',
        },
      }
    );

    if (!response.ok) {
      // State fetch failed (e.g. 404, 503). Do not regress — keep current seq
      // and let normal WS traffic continue. A subsequent reconnect will retry.
      console.error('Resync state fetch failed with status:', response.status);
      return;
    }

    const state: SessionStateResponse = await response.json();
    const store = useStore.getState();

    // Reconcile authoritative state.
    if (state.assistant_state) {
      store.setAssistantState(state.assistant_state);
    }

    // Advance sequence cursor to the authoritative position. Never regress.
    if (state.last_seq > currentSeq) {
      currentSeq = state.last_seq;
    }

    console.log(`Resync complete. Sequence cursor restored to ${currentSeq}`);

  } catch (e) {
    // Network error reaching the state endpoint. Log and continue — the WS
    // connection is still alive; normal events will keep arriving.
    console.error('Resync HTTP request failed:', e);
  } finally {
    isResyncing = false;
  }
}

function scheduleReconnect() {
  if (reconnectTimer) clearTimeout(reconnectTimer);

  // Exponential backoff capped at 30 s (roadmap.md Phase 1 WS client spec).
  const backoff = Math.min(1000 * Math.pow(2, reconnectAttempts), 30_000);
  reconnectAttempts++;

  console.log(`Reconnecting in ${backoff} ms (attempt ${reconnectAttempts})`);
  reconnectTimer = setTimeout(() => {
    if (!isIntentionalDisconnect) {
      connectInternal();
    }
  }, backoff);
}

export function sendChatMessage(sessionId: string, text: string, clientMsgId?: string) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'chat.send',
      data: { session_id: sessionId, text, client_msg_id: clientMsgId },
    }));
  }
}

export function cancelRun(runId: string) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'run.cancel',
      data: { run_id: runId },
    }));
  }
}

export function sendTestMessage(text: string) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type: 'chat.send',
      data: { text },
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

export function __resetSeqForTest() {
  currentSeq = 0;
}
