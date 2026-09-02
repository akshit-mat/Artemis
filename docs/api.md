# ARTEMIS — API & Event Protocol

Base URL: `http://127.0.0.1:<ephemeral>` (port discovered via the Tauri sidecar handshake). All endpoints under `/v1`.

## 1. Transport rules (enforced by middleware, tested in Phase 1)

| Rule | Detail |
|---|---|
| Bind | `127.0.0.1` only, ephemeral port |
| Auth | `Authorization: Bearer <token>` (HTTP); WS subprotocol `["artemis.v1","bearer.<token>"]` — browsers cannot set WS headers |
| Origin | Must be in the allowlist (`http://tauri.localhost`; `http://localhost:1420` in dev builds only). **Missing Origin on WS is rejected.** |
| Host | Validated against `127.0.0.1:<port>` (anti-DNS-rebinding) |
| CORS | Disabled. No wildcards. |
| Errors | Uniform envelope: `{"error":{"code":"POLICY_DENIED","message":"…","detail":{...},"correlation_id":"…"}}` |
| Limits | Request body ≤1 MB; WS text frame ≤256 KB; WS binary (audio) ≤64 KB |

`code` values are stable identifiers (`UNAUTHORIZED`, `ORIGIN_REJECTED`, `MODEL_UNAVAILABLE`, `MODEL_TIMEOUT`, `POLICY_DENIED`, `TAINTED_DESTRUCTIVE`, `PATH_OUT_OF_SCOPE`, `TOOL_TIMEOUT`, `TOOL_ERROR`, `TOOL_CALL_UNPARSEABLE`, `MAX_STEPS`, `REPEATED_TOOL_CALL`, `APPROVAL_TIMEOUT`, `CANCELLED`, `DB_UNAVAILABLE`, `INTERNAL`). The frontend switches on `code`, never on `message`.

## 2. Transport split

**Decision:** one WebSocket for all realtime (server→client events **and** client→server control), HTTP for CRUD and bulk reads.
**Reason:** voice needs binary duplex; adding SSE now guarantees a second transport later. One socket, one ordering guarantee, one reconnect path.
**Alternatives:** SSE + HTTP POST (unidirectional, needs a second channel for audio); HTTP long-poll (worse).
**Tradeoff:** we must implement `seq`/replay ourselves — ~80 lines, and worth it.

Chat is initiated **over the WS** (`chat.send`), not via HTTP, so a single ordering domain covers request and response. `POST /v1/chat` exists as a non-streaming path for tests and scripting.

## 3. HTTP endpoints

```
GET    /health                          → {status, version, model:{loaded,name}, db:"ok", uptime_s}
                                          (unauthenticated; liveness only, no detail leakage)

GET    /v1/config                       → resolved config (secrets omitted)
PATCH  /v1/config                       → partial update; may only tighten policy-relevant keys
GET    /v1/models                       → registry + health + capabilities
POST   /v1/models/select                {role, model_id}

POST   /v1/sessions                     → {session_id}
GET    /v1/sessions                     ?limit&cursor
GET    /v1/sessions/{id}/messages       ?before&limit   (cursor pagination)
GET    /v1/sessions/{id}/state          → full snapshot for resync: {assistant_state, active_run, pending_approvals, active_task, last_seq}
DELETE /v1/sessions/{id}
PATCH  /v1/sessions/{id}                {title?, sensitive?}

POST   /v1/chat                         {session_id, text}  → non-streaming final message (tests/scripts)

GET    /v1/tools                        → visible tools + risk + effective decision (DENY tools omitted)
GET    /v1/results/{result_id}          ?offset&limit  → full tool result (paged)

GET    /v1/policy/rules                 → rules + mode + baseline (read-only baseline shown for transparency)
PUT    /v1/policy/rules/{tool_name}     {decision}     (tighten-only; loosening past baseline → 403)
GET    /v1/policy/grants                → active grants with scope, uses, last_used_at
DELETE /v1/policy/grants/{id}           → revoke
GET    /v1/audit                        ?from&to&decision&tool&limit&cursor

GET    /v1/memories                     ?kind&status&q&limit&cursor
POST   /v1/memories                     {kind, key?, value}       (source=USER_EXPLICIT)
PATCH  /v1/memories/{id}                {value?, pinned?, sensitive?}   (creates supersede chain)
DELETE /v1/memories/{id}
POST   /v1/memories/{id}/resolve        {action:"confirm"|"dismiss"}
GET    /v1/memories/export              → application/json attachment
POST   /v1/memories/purge               {confirm:"DELETE ALL MEMORIES"}

GET    /v1/tasks                        ?status&limit
GET    /v1/tasks/{id}                   → task + steps + logs
POST   /v1/tasks/{id}/approve           {approval_id, outcome, scope}
POST   /v1/tasks/{id}/cancel

GET    /v1/telemetry/snapshot           → one sample (for the panel's first paint)
```

Idempotency: `POST /v1/chat` and `chat.send` accept `client_msg_id`; duplicates return the original run.

## 4. WebSocket protocol

`WS /v1/events`

### Envelope (every frame, both directions)

```jsonc
{
  "v": 1,
  "seq": 1042,                       // server→client only: monotonic per connection
  "ts": "2026-09-02T09:14:22.481Z",
  "type": "agent.delta",
  "run_id": "r_01J...",              // when applicable
  "session_id": "s_01J...",
  "data": { }
}
```

Client sends `{"v":1,"type":"...","data":{...}}` (no `seq`).

On connect the server sends `session.ready{last_seq, assistant_state, model, pending_approvals[]}`. On reconnect the client sends `client.hello{last_seq}`; the server replays from its 500-event ring buffer or replies `client.resync_required` → the client calls `GET /v1/sessions/{id}/state`.

### Server → client events

| Type | `data` |
|---|---|
| `session.ready` | `{last_seq, assistant_state, model, pending_approvals[]}` |
| `agent.state` | `{state, intensity, progress?, detail?, run_id?}` — the single source of `AssistantState` |
| `agent.delta` | `{channel:"content"\|"reasoning", text}` — coalesced ~30 ms server-side |
| `agent.message` | `{message_id, role, content, finish_reason, steps_used, tokens:{in,out}, incomplete?}` |
| `agent.error` | `{code, message, recoverable, correlation_id}` |
| `tool.requested` | `{call_id, tool, category, risk, args_preview, taint}` |
| `tool.decision` | `{call_id, decision, rule_id, reason}` |
| `tool.started` | `{call_id}` |
| `tool.progress` | `{call_id, progress?, note?}` (≤2 Hz) |
| `tool.result` | `{call_id, status, summary, result_id, duration_ms, truncated, undo_available}` |
| `approval.requested` | `{approval_id, call_id?, task_id?, title, action_text, targets[], item_count, total_bytes?, risk, reversible, model_rationale, scope_options[], expires_at}` |
| `approval.resolved` | `{approval_id, outcome:"allowed"\|"denied"\|"timeout", scope?}` |
| `task.created` / `task.updated` | `{task_id, title, status, progress_pct, step_count}` |
| `task.step` | `{task_id, step_id, idx, status, title, error?}` |
| `memory.updated` | `{op, memory_id, kind, summary}` |
| `model.status` | `{role, provider, model, loaded, error?}` |
| `voice.state` | `{state, mode}` |
| `voice.level` | `{rms}` (≤20 Hz, only while capturing) |
| `voice.partial` / `voice.final` | `{text, confidence?}` |
| `telemetry.sample` | `{cpu_pct, ram_used_mb, ram_total_mb, gpu_pct, vram_used_mb, vram_total_mb, battery_pct, on_ac}` (≤1 Hz, only while subscribed) |

`action_text` in `approval.requested` is **generated by the backend from validated arguments**. `model_rationale` is a separate field precisely so the UI cannot conflate them. This field separation is a security control, not a convenience.

### Client → server messages

| Type | `data` |
|---|---|
| `client.hello` | `{last_seq}` |
| `chat.send` | `{session_id, text, client_msg_id}` |
| `run.cancel` | `{run_id, reason?}` |
| `approval.respond` | `{approval_id, outcome:"allow"\|"deny", scope:"once"\|"session"\|"1h"\|"always"}` |
| `telemetry.subscribe` | `{enabled, hz}` (hz ≤1) |
| `voice.start_capture` / `voice.stop_capture` / `voice.barge_in` | `{}` |
| `voice.set_config` | `{voice?, rate?, volume?, mode?}` |
| binary frame | PCM 16 kHz mono f32 audio (Phase 7) |

Unknown `type` → `agent.error{code:"BAD_MESSAGE"}`, connection kept. Malformed envelope → close 1003.

### Backpressure & flow control

- Content deltas coalesced server-side on a ~30 ms tick.
- `tool.progress` and `voice.level` are rate-limited server-side.
- Per-connection outbound queue cap 1 000; on overflow: drop `telemetry.sample` and `voice.level` first, then `agent.delta` (a final `agent.message` always carries the complete text, so dropping deltas is lossless for correctness), and **never** drop `approval.*`, `tool.decision`, `agent.error` or `task.*`.
- Ping/pong every 20 s; dead peer closed after 2 misses.

## 5. Versioning

`v` is the envelope version. Additive fields are non-breaking; the frontend must ignore unknown fields and unknown event types (forward compatibility is required from Phase 1). Breaking changes bump `v` and the URL (`/v2/events`). Event `type` strings are permanent once shipped.

## 6. Security considerations

Recap of what the API layer is responsible for: auth + origin + host validation; approval ids are server-issued single-use nonces (replay rejected and audited); no endpoint accepts a raw filesystem path *from the frontend* for a privileged operation without the same policy evaluation a model-issued call receives — **the human clicking is subject to policy too** (it's how directory-restriction bugs get caught); `/health` is unauthenticated but returns no paths, no config and no session data; error `detail` never contains absolute paths outside allow_roots, stack traces, or token material.

## 7. Failure behaviour

Backend not yet up → the shell retries the handshake for 15 s, then FATAL UI. WS drop mid-run → the run **continues server-side**; on reconnect the client resyncs and sees the outcome (a run must not die because a window was minimized). Approval pending during a disconnect → replayed in `session.ready.pending_approvals`, still governed by its original expiry.

## 8. Testing requirements

Auth/origin/host rejection matrix · unknown event type tolerated in both directions · `seq` monotonicity and gap-triggered resync · replay of an `approval_id` rejected · backpressure drop-priority order · disconnect mid-run then reconnect yields the correct final state · `POST /v1/chat` idempotency by `client_msg_id` · policy applied to frontend-originated privileged requests · schema contract tests generated from the Pydantic models and consumed by the TS types (single source of truth: **Pydantic → OpenAPI/JSON-Schema → generated TS**; never hand-maintain both sides).
