# ARTEMIS — UI Architecture & State Model

Goal: a dynamic desktop assistant surface, not a chat log with a theme. This document defines the **architecture and state model**; concrete visual design is Phase 3+ work.

## 1. Responsibility & boundaries

The frontend renders state, captures intent, and presents approvals. It holds **no authority**: it cannot perform privileged operations, cannot bypass policy, and cannot fabricate approvals (the backend correlates every approval to an `approval_id` it issued).

It renders untrusted content (model text, file names, web excerpts) — therefore: no `dangerouslySetInnerHTML`, markdown rendered through a sanitizing renderer with a strict allowlist, no remote resource loading, a strict CSP in Tauri, and external links opened via the shell (never in the WebView).

---

## 2. Layout model

Three zones, one persistent identity element.

```
┌──────────────────────────────────────────────────────────────┐
│  TITLE / DRAG REGION            state pill    ⌘K    ⚙       │
├───────────────┬──────────────────────────────┬───────────────┤
│               │                              │               │
│  RAIL         │        STAGE                 │  CONTEXT      │
│  (56px)       │  ┌────────────────────────┐  │  PANEL        │
│               │  │        CORE            │  │  (0 / 320 /   │
│  Conversation │  │  (state-driven visual) │  │   420px)      │
│  Tasks        │  └────────────────────────┘  │               │
│  Memory       │                              │  Activity     │
│  Permissions  │      Conversation flow       │  Task detail  │
│  Activity     │      Tool timeline cards     │  Telemetry    │
│  Settings     │      Approval cards          │  Memory info  │
│               │                              │               │
│               ├──────────────────────────────┤               │
│               │  COMPOSER  [text] [mic] [⏹]  │               │
└───────────────┴──────────────────────────────┴───────────────┘
```

- **CORE** — the persistent visual identity. It is *the* state indicator: always present, scaling down to a compact form when the conversation is long. Not decorative — it is the primary status display.
- **STAGE** — conversation, but as a heterogeneous stream of typed cards (message, tool call, approval, task, denial, error), not a text log.
- **CONTEXT PANEL** — collapsible, context-sensitive. Opens automatically for `WAITING_FOR_APPROVAL` and active tasks.
- **RAIL** — mode switching. Deliberately narrow; ARTEMIS is not an app with navigation, it's an assistant with facets.
- **Command palette (⌘K / Ctrl+K)** — the power-user path: switch model, toggle voice, revoke a grant, cancel a run, jump to a memory. Reaching any feature in two keystrokes is worth more than any animation.
- **Compact HUD mode** — a small always-available overlay (global hotkey, frameless, ~420×120, centred top) with just the CORE + a single input. This is how the assistant actually gets used day to day; the full window is for inspection. Same event stream, same stores, different composition.

---

## 3. State model

`AssistantState` is **computed on the backend** and pushed. The frontend never derives it from message flow — divergence between "what the UI thinks" and "what the agent is doing" is the classic bug in this kind of app.

```ts
type AssistantState =
  | 'OFFLINE'              // backend or model unavailable
  | 'IDLE'
  | 'LISTENING'            // mic open, capturing
  | 'TRANSCRIBING'
  | 'THINKING'             // model inference, no content tokens yet
  | 'RESPONDING'           // streaming content
  | 'SEARCHING'            // read-only tool running (incl. web)
  | 'EXECUTING'            // side-effecting tool running
  | 'WAITING_FOR_APPROVAL'
  | 'SPEAKING'
  | 'ERROR';
```

Precedence when several could apply: `OFFLINE > ERROR > WAITING_FOR_APPROVAL > EXECUTING > SEARCHING > TRANSCRIBING > LISTENING > SPEAKING > RESPONDING > THINKING > IDLE`. Encoded once, in the backend, as a pure function of active run/tool/approval/voice records.

Accompanying scalars, so visuals can be continuous rather than discrete:

```ts
interface CoreSignal {
  state: AssistantState;
  intensity: number;    // 0..1 — token rate, tool progress, or mic RMS
  progress?: number;    // 0..1 — task/tool determinate progress
  detail?: string;      // "reading downloads…" — short, human
  runId?: string;
}
```

### Motion contract (state → visual, defined once in a table)

| State | Colour | Motion | Notes |
|---|---|---|---|
| IDLE | cool neutral | slow breathe, 4 s | near-zero CPU |
| LISTENING | cyan | ring reacts to `intensity` (mic RMS) | mic indicator mandatory |
| THINKING | indigo | inward pulse, 1.2 s | |
| RESPONDING | warm white | shimmer scaled by token rate | |
| SEARCHING | teal | orbiting arc | |
| EXECUTING | amber | segmented progress ring | determinate when possible |
| WAITING_FOR_APPROVAL | amber, **static** | **no animation**, high-contrast border | stillness draws attention better than motion, and prevents "click through the pulsing thing" |
| SPEAKING | violet | waveform-driven | |
| ERROR | red | single sharp shake, then still | never loops |
| OFFLINE | desaturated grey | none | |

Rules: motion is derived from `CoreSignal` only — components never animate on their own timers. Every animation respects `prefers-reduced-motion` and a `settings.reducedMotion` override, both of which switch to colour/opacity-only transitions.

**Rendering constraint:** no persistent WebGL/three.js context. The CORE is SVG + CSS transforms + Framer Motion, GPU-composited but shader-free. Reason: the GPU is needed for inference on a 6 GB card, and a WebGL context measurably increases VRAM pressure and battery drain. Animation loop pauses on window blur/minimize and drops to 30 fps on battery.

---

## 4. Store architecture (Zustand)

Zustand over Redux: no boilerplate, selector-level subscriptions (essential for 30–60 events/second streaming without re-rendering the tree), trivially testable.

| Store | Contents |
|---|---|
| `connectionStore` | WS status, reconnect/backoff, last `seq`, backend health, model status |
| `sessionStore` | sessions, active session, card stream, streaming buffer |
| `agentStore` | `CoreSignal`, active `runId`, step counter, cancel affordance |
| `toolStore` | in-flight and recent tool calls, decisions, results |
| `approvalStore` | pending approvals (queue), preview payloads, responses |
| `taskStore` | tasks, steps, progress |
| `memoryStore` | memories, candidates, filters (lazy-loaded) |
| `permissionStore` | rules, grants, mode |
| `telemetryStore` | ring buffer of samples; **subscription is lifecycle-bound to panel visibility** |
| `settingsStore` | config mirror, optimistic updates with rollback |

**Event router** (`core/eventRouter.ts`) is the single WS consumer; it dispatches by `type` into stores. Components never touch the socket.

**Streaming performance:** content deltas accumulate in a ref and flush to the store on `requestAnimationFrame` (≈60 Hz max), not per token. Naive per-delta `setState` at 40 tok/s with markdown re-parsing is the #1 source of jank in this app class.

**Ordering & recovery:** every event carries a monotonic `seq`. A gap triggers a targeted resync (`GET /v1/sessions/{id}/state`) rather than a full reload. On reconnect the client sends `last_seq`; the server replays buffered events (ring buffer of 500) or instructs a resync.

---

## 5. Key surfaces

- **Card stream.** Discriminated-union card types: `message` · `tool` (collapsed one-liner → expandable with args, decision, duration, result preview) · `approval` · `denial` (explicit, with reason and rule) · `task` · `error`. Rendering is a `switch` on `card.kind`; adding a card type touches one file.
- **Approval card.** The most security-critical UI in the product. Requirements: the action string is **backend-generated** from validated args; concrete resolved targets (absolute paths, item counts, total bytes) shown; model rationale in a visually distinct, labelled *"ARTEMIS says"* block that is clearly not the action; scope options (Once / Session / 1 h / Always-where-permitted); destructive actions get a distinct treatment and no "Always" option; a full item list for batches (scrollable, not summarized away); reversibility stated ("→ Recycle Bin, restorable"); keyboard focus trapped, **no default-focused Allow button**, and a 400 ms arm delay on destructive confirms to defeat click-through.
- **Activity & Permissions.** The audit log, in plain language: what ran, what was blocked and why, active grants with usage counts and one-click revoke.
- **Memory panel.** Browse/search/edit/delete/pin, confirm candidates, `origin_quote` provenance, export, purge.
- **Task view.** Plan-before-execute is the whole point: the proposed step list is reviewable and editable (drop steps) *before* approval; then live per-step progress and logs.
- **Telemetry strip.** CPU/RAM/GPU/VRAM/battery sparklines. Off by default; subscribes only while visible.

---

## 6. Events consumed

All of `api.md` §4. The frontend emits only: `chat.send`, `run.cancel`, `approval.respond`, `telemetry.subscribe`, `voice.*`.

## 7. Security considerations

- No privileged operation reachable from the renderer; the Tauri allowlist exposes exactly `get_backend_handle`, window controls, and `shell.open` restricted to `http/https`.
- Strict CSP: `default-src 'self'; connect-src 'self' http://127.0.0.1:*; img-src 'self' data: asset:; script-src 'self'`. No CDNs, no remote fonts — fonts are bundled.
- Untrusted text is never rendered as HTML; markdown allowlist excludes raw HTML, iframes and images by remote URL.
- Approval responses are correlated to a server-issued `approval_id` with a nonce; a replayed or unknown id is rejected and audited.
- The auth token lives in memory only (never `localStorage`).

## 8. Failure behaviour

`OFFLINE` state with a named cause and a concrete remedy button ("Start Ollama", "Retry backend"). Reconnect with exponential backoff + jitter, capped at 10 s, with a visible attempt count. Optimistic user messages are marked *unsent* and retryable, never silently dropped. A stream that ends without a terminal event is marked *incomplete* rather than left spinning (client-side 30 s watchdog on `THINKING`/`RESPONDING`).

## 9. Testing requirements

Store reducers against recorded event fixtures (golden replays for: normal turn, tool turn, approval accept/reject, cancel, error, reconnect-with-gap) · `AssistantState` precedence table · approval card renders only backend-provided action text (assert model rationale cannot occupy the action slot) · reduced-motion produces no transform animations · 500-card stream stays above 50 fps · Playwright golden path from Phase 3.

## 10. Extension points

Additional card kinds · a plugin slot in the CONTEXT PANEL keyed by tool category · themes as CSS variable sets (the motion contract is theme-independent) · multi-window (HUD + inspector) sharing one WS via a `BroadcastChannel`-backed store proxy · localization (all strings via a single `t()` from day one, even if only `en` exists).
