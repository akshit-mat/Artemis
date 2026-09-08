import { useStore } from '../state/store';
import { bufferDelta } from './deltaBuffer';
import type { components } from '../api/types';

type WSEnvelope = components["schemas"]["WSEnvelope"];
type SessionReadyData = components["schemas"]["SessionReadyData"];
type AssistantStateData = components["schemas"]["AssistantStateData"];
type SessionStateResponse = components["schemas"]["SessionStateResponse"];
type AgentDeltaData = components["schemas"]["AgentDeltaData"];
type AgentMessageData = components["schemas"]["AgentMessageData"];
type ToolRequestedData = components["schemas"]["ToolRequestedData"];
type ToolDecisionData = components["schemas"]["ToolDecisionData"];
type ToolStartedData = components["schemas"]["ToolStartedData"];
type ToolProgressData = components["schemas"]["ToolProgressData"];
type ToolResultData = components["schemas"]["ToolResultData"];
type ApprovalRequestedData = components["schemas"]["ApprovalRequestedData"];
type ApprovalResolvedData = components["schemas"]["ApprovalResolvedData"];

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

      } else if (envelope.type === 'agent.delta') {
        const payload = envelope.data as unknown as AgentDeltaData;
        if (envelope.run_id) {
          bufferDelta(envelope.run_id, payload.channel, payload.text);
        }

      } else if (envelope.type === 'agent.message') {
        const payload = envelope.data as unknown as AgentMessageData;
        store.addCard({
          id: envelope.run_id || payload.message_id,
          type: 'message',
          role: payload.role,
          content: payload.content,
          finish_reason: payload.finish_reason,
        });

      } else if (envelope.type === 'agent.error') {
        // Phase 2 requirement: degraded modes surface a distinct code in the UI banner.
        // The frontend switches on code, never on message (api.md §1).
        const err = envelope.data as unknown as {
          code: string;
          message: string;
          recoverable: boolean;
          correlation_id: string | null;
        };
        store.setLastError(err);

      } else if (envelope.type === 'tool.requested') {
        const payload = envelope.data as unknown as ToolRequestedData;
        store.addCard({
          id: payload.call_id,
          type: 'tool',
          tool_name: payload.tool,
          category: payload.category,
          risk: payload.risk,
          args_preview: payload.args_preview,
          targets: payload.targets,
          item_count: payload.item_count,
          taint: payload.taint,
          tool_state: 'requested',
        });
      } else if (envelope.type === 'tool.decision') {
        const payload = envelope.data as unknown as ToolDecisionData;
        store.updateCard(payload.call_id, {
          type: payload.decision === 'deny' ? 'denial' : 'tool',
          tool_state: payload.decision === 'ask' ? 'waiting_for_approval' : (payload.decision === 'deny' ? 'denied' : 'decision'),
          decision: payload.decision,
          rule_id: payload.rule_id,
          reason: payload.reason,
        });
      } else if (envelope.type === 'approval.requested') {
        const payload = envelope.data as unknown as ApprovalRequestedData;
        store.addCard({
          id: payload.id,
          type: 'approval',
          tool_name: payload.tool_name,
          action_text: payload.action_text,
          targets: payload.targets,
          risk: payload.risk,
          batch_count: payload.batch_count,
        });
      } else if (envelope.type === 'approval.resolved') {
        const payload = envelope.data as unknown as ApprovalResolvedData;
        store.updateCard(payload.id, { decision: payload.decision });
      } else if (envelope.type === 'tool.started') {
        const payload = envelope.data as unknown as ToolStartedData;
        store.updateCard(payload.call_id, { tool_state: 'started' });
      } else if (envelope.type === 'tool.progress') {
        const payload = envelope.data as unknown as ToolProgressData;
        store.updateCard(payload.call_id, { tool_state: 'progress', progress: payload.progress });
      } else if (envelope.type === 'tool.result') {
        const payload = envelope.data as unknown as ToolResultData;
        store.updateCard(payload.call_id, { 
          type: payload.status === 'error' ? 'error' : 'tool',
          tool_state: payload.status === 'error' ? 'error' : 'result',
          status: payload.status,
          summary: payload.summary,
          duration_ms: payload.duration_ms
        });
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
