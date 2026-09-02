# ARTEMIS — Roadmap

**Sequencing principle:** a working, secure vertical slice early; then capability, always behind the policy engine.

**Deliberate deviation from the suggested order:** the permission system ships **with** the tool framework (Phase 4), not after it. Shipping tools first would mean the first filesystem tool executes unguarded and authorization has to be retrofitted into every call site. The `Authorization`-object coupling (`tools.md` §5) is only enforceable if policy exists first. Likewise, transport authentication is Phase 1, not a hardening pass — an unauthenticated loopback port that later gains file-delete tools is a privilege-escalation bug waiting for a schedule slip.

Phases are sized for a single coding agent per phase. Each phase must end green on CI (Windows) and leave the app runnable.

---

## Phase 1 — Secure walking skeleton

**Goal:** Tauri shell launches a supervised Python sidecar, authenticated WS round-trip renders in the UI, one CI pipeline.

**Dependencies:** none.

**Deliverables**
- Monorepo per `architecture.md` §11; `uv` + pnpm + Rust toolchain; `scripts/dev.ps1`, `scripts/build.ps1`.
- Rust shell: single-instance, tray, window, token mint, sidecar spawn with `--port 0`, stdout JSON handshake, **Job Object kill-on-close**, health supervision with backoff, `get_backend_handle` command.
- FastAPI core: `/health`, auth + Origin + Host middleware, `WS /v1/events` with the `seq` envelope, event bus, `client.hello`/replay ring buffer.
- SQLite: connection manager (WAL, pragmas, single-writer lock), numbered SQL migrator, `sessions`/`messages`/`settings` tables.
- Config: Pydantic layered loader (defaults → TOML → env), fail-loud validation.
- Logging: structlog JSON to file + console, `run_id` correlation, declarative redaction.
- Frontend: layout shell (rail/stage/context panel), WS client with backoff + resync, event router, Zustand stores, CORE component driven by a hard-coded state cycler, generated TS types from the OpenAPI schema.

**Tests:** auth/origin/host rejection matrix · handshake + sidecar kill on shell exit (no orphan process) · WS `seq` monotonicity, gap → resync · migrator idempotency and forward-only · config validation failures · frontend event-replay fixture.

**Non-goals:** no LLM, no tools, no memory, no voice, no visual polish.

---

## Phase 2 — Model provider & streaming conversation

**Goal:** real conversation with `qwen3:8b` over Ollama, streamed, cancellable, degrading honestly.

**Dependencies:** Phase 1.

**Deliverables**
- `ModelProvider` ABC, `Capabilities`, `Chunk` union, `GenOptions`.
- `OllamaProvider`: streaming, `<think>` → `reasoning` channel separation, `keep_alive`, health probe, `num_ctx` from config, timeout + abort on cancel.
- `FakeProvider` (scriptable) — the backbone of all later agent tests.
- Model registry with `role` mapping; `GET /v1/models`, `POST /v1/models/select`.
- Minimal agent: assemble → stream → persist; `runs` table; `run.cancel`.
- Context assembler v1: tiers 0/2/5 with budget enforcement and per-tier token logging.
- Degraded modes: Ollama offline, model not pulled, GPU/VRAM failure, first-token timeout — each with a distinct `code` and UI banner.

**Tests:** provider contract suite against `FakeProvider` + recorded Ollama fixtures · reasoning never appears in `messages.content` · cancel aborts the HTTP stream within 200 ms · budget never exceeded on a 500-turn synthetic session · each degraded mode surfaces the right `code`.

**Non-goals:** no tools, no summarization, no memory retrieval, no multi-step loop.

---

## Phase 3 — Dynamic assistant state & conversation UX

**Goal:** the interface visibly *is* the assistant — backend-driven states, streamed cards, command palette, HUD.

**Dependencies:** Phase 2.

**Deliverables**
- Backend `AssistantState` computation (pure function + precedence table) and `agent.state` emission with `intensity`.
- Frontend card stream (discriminated union), rAF-coalesced delta rendering, sanitized markdown renderer.
- CORE visual driven solely by `CoreSignal`; motion contract table implemented; `prefers-reduced-motion` and battery paths.
- Command palette (Ctrl+K); compact HUD window with global hotkey; session list; stop/cancel affordance.
- Playwright golden-path E2E.

**Tests:** `AssistantState` precedence exhaustive · 500-card stream ≥50 fps · reduced-motion emits no transform animations · unfocused window pauses the animation loop · idle CPU <1 % measured · markdown sanitizer rejects HTML/script/remote images.

**Non-goals:** no final visual identity, no theming system, no tools.

---

## Phase 4 — Tool framework **and** policy engine (shipped together)

**Goal:** the full controlled loop — model proposes, policy authorizes, runtime executes, UI shows it — proven on read-only system tools.

**Dependencies:** Phase 3.

**Deliverables**
- `ToolSpec` contract, registry (explicit registration), compact schema rendering, capability gating.
- `ToolRuntime` with `INLINE`/`THREAD`/`SUBPROCESS` tiers, per-tool timeouts, hard tree-kill cancellation, result capture, `context_view` truncation + `result_id` + `read_more` tool.
- Policy engine: hard-deny baseline in code, decision lattice (`min`), `policy_rules`/`policy_grants` tables, modes, startup baseline self-test, **`Authorization` minting** and re-verification at the runtime door.
- Taint model: `trust` on context items, run `tainted` flag, escalation lock, user-intent binding scaffold.
- Audit log table + writer with abort-on-audit-failure for side-effecting tools; `GET /v1/audit`.
- Full agent loop: multi-step, tool results, repair loop, loop guard, all guards from `agent.md` §2.
- Tool-call extraction fallback chain + which-path metrics.
- Read-only system tools: `get_time`, `get_system_info`, `get_cpu_usage`, `get_memory_usage`, `get_gpu_usage`, `get_battery`, `get_disk_usage` (1 Hz sampler cache).
- Telemetry strip + visibility-bound subscription.
- UI: tool timeline cards, denial cards, Activity view.

**Tests:** decision lattice exhaustive — **no combination may exceed the baseline** · policy exception → DENY (fail closed) · audit write failure → side-effecting tool not executed · `Authorization` cannot be constructed outside the engine · args mutated after approval → rejected (TOCTOU) · runtime cannot execute without an `Authorization` · subprocess timeout kills the tree · registry meta-test on coherent `ToolSpec` field combinations · all `FakeProvider` agent-loop scenarios from `agent.md` §10 · injected instruction in a tool result cannot cause a side-effecting call to skip ASK.

**Non-goals:** no filesystem tools, no app control, no web, no persistent grants beyond session scope.

---

## Phase 5 — Filesystem tools, path security & approval UX

**Goal:** ARTEMIS safely touches files. This is the phase where a bug is expensive, so path security is gating.

**Dependencies:** Phase 4.

**Deliverables**
- `policy/paths.py`: the full canonicalization pipeline (`security.md` §5) — device names, ADS, UNC, 8.3, junction/symlink resolution via handle, segment-wise containment, deny-list, TOCTOU handle usage.
- `allow_roots` config + settings UI with explicit risk confirmation per added root; `C:\` refused.
- Tools: `search_files`, `list_directory`, `read_file`, `write_file`, `copy_file`, `move_file`, `rename_file`, `create_directory`, `delete_file` (**Recycle Bin default** via `IFileOperation`).
- Batch caps, mandatory previews >10 items, move-manifest undo, recycle-bin restore.
- Approval card: backend-generated `action_text`, resolved targets, counts/bytes, separated model rationale, scope options, no "Always" for destructive, no default-focused Allow, 400 ms arm delay, full batch list.
- Grant store with structural scope containment matching; Permissions panel with revoke.
- Untrusted-content wrapping, delimiter escaping, control/bidi stripping.

**Tests (gating — Phase 6 does not start until all pass):** the ≥200-case path fuzz corpus + Hypothesis, **zero escapes** · junction-swap mid-operation · `C:\Users\bob` vs `C:\Users\bobby` prefix confusion · secret-shaped paths denied on read and write · grant containment (parent/sibling/junction) · every file tool: invalid args, timeout, cancellation, denial · injection scenario: file content requesting deletion → `TAINTED_DESTRUCTIVE` DENY + audit entry · recycle-bin undo round-trip · read of a 2 GB file refused, binary refused.

**Non-goals:** no permanent-delete tool enabled by default, no network drives, no archive/compression tools.

---

## Phase 6 — Memory

**Goal:** ARTEMIS remembers usefully, with provenance and full user control.

**Dependencies:** Phase 5 (needs approvals + audit).

**Deliverables**
- `memories` + FTS5 + `memory_candidates`/`memory_links`; embedding column reserved (NULL).
- Extraction pipeline: post-turn async, `fast`-role model, schema-constrained, rule filter (length, secrets, third parties, sensitive categories), explicit vs inferred routing, corroboration promotion.
- Retrieval: scoring formula, ≤5 items / 400 tokens, sensitive exclusion, provenance quarantine.
- Context assembler v2: tiers 1/3/4/6 complete; rolling summary via `fast` role, async; tool-schema pruning.
- Memory panel: browse/search/edit/delete/pin/confirm/dismiss, `origin_quote` provenance, export, purge.
- `remember`/`forget` tools; `memory.updated` events + non-modal indicator.
- Maintenance/decay job on startup.
- `fast`-role model added to the registry (small model, CPU or shared GPU on demand).

**Tests:** explicit vs inferred routing · promotion thresholds (3 corroborations, 2 distinct days) · explicit supersedes inferred, never the reverse · `REJECTED` stickiness · untrusted provenance blocked from `PROFILE`/`PREFERENCE` · secret-shaped extraction rejected · **memory content cannot alter any policy decision** (explicit adversarial test) · retrieval determinism + budget · export → purge → re-import round-trip · 10 000-memory retrieval <50 ms · sensitive-session extraction skipped.

**Non-goals:** no vector search (Phase 6.5, only if recall is measured inadequate), no cross-device sync, no proactive suggestions.

---

## Phase 7 — Voice

**Goal:** push-to-talk conversation with responsive barge-in, CPU-only, under the latency budget.

**Dependencies:** Phase 6 (for TTS-relevant preferences) — technically only needs Phase 3.

**Deliverables**
- Audio capture/playback in the Rust shell (`cpal`), binary WS frames, device-change handling.
- `VADEngine`/`STTEngine`/`TTSEngine` Protocols + `SileroVAD`, `FasterWhisperSTT` (small int8, CPU, 4 threads), `PiperTTS` (CPU, 2 threads), `FakeSTT`/`FakeTTS`.
- Voice state machine, push-to-talk hotkey, barge-in (<150 ms), unified cancellation.
- Sentence-level TTS pipelining; retrieval started on partial transcript; pre-warm on enable.
- Mic-off default; persistent live-mic indicator (window + tray); no raw-audio persistence.
- Low-confidence transcript → confirm instead of guess; destructive ops from voice always require approval.
- Voice settings: device, voice, rate, volume, mode.

**Tests:** VAD segmentation fixtures (quiet/noisy/music) · `FakeSTT` contract with scripted partials/finals · barge-in cancels TTS **and** the run within 150 ms · end-to-end latency on fixtures within budget +30 % headroom · low-confidence path requires confirmation · destructive voice command requires approval · mic indicator is driven by actual capture state · GPU untouched by the voice path (VRAM assertion) · device unplug mid-capture recovers.

**Non-goals:** no wake word (7.5), no hands-free (7.5), no speaker verification, no GPU STT by default.

---

## Phase 8 — Tasks, application & window control

**Goal:** multi-step work with plan-then-approve, and controlled control of the desktop.

**Dependencies:** Phase 5, Phase 6.

**Deliverables**
- `tasks`/`task_steps`/`task_logs`; two-phase lifecycle; plan-deviation halt; `checkpoint` steps; step/wall-clock caps; `INTERRUPTED` on restart with no auto-resume.
- Task UI: reviewable/editable plan before approval, live per-step progress, logs, cancel.
- Tools: `list_running_apps`, `focus_app`, `open_app` (Start-Menu/`App Paths` allowlist — name only, never a path or argv), `close_app` (graceful first; force-kill separate; system-critical denied), `set_volume`, media transport keys, `set_brightness`, `take_screenshot` (blob, untrusted), `lock_workstation`, power actions (never batchable).
- Parallel read-only tool calls (`max_parallel_tool_calls = 3`).
- The `"Clean up my Downloads folder"` reference scenario, end to end, with undo.

**Tests:** plan deviation halts and re-asks · approval binds to the resolved step list · cancel mid-task reports completed steps truthfully · restart marks `INTERRUPTED` and never auto-resumes · `open_app` cannot be coerced into launching an arbitrary path or passing arguments · system-critical process kill denied · tainted task cannot contain destructive steps · reference scenario undo restores every moved/deleted item.

**Non-goals:** no UI automation / synthetic input, no scheduled or background triggers, no proactive action.

---

## Phase 9 — Web tools

**Goal:** controlled, offline-degrading web access.

**Dependencies:** Phase 5 (subprocess tier + untrusted-content handling).

**Deliverables**
- `search_web`, `open_page` (headless fetch + sanitized text extraction), `open_url_in_browser` (scheme allowlist, hands off to the user's browser).
- Egress control: SSRF blocklist checked **after DNS resolution and on every redirect** (loopback, link-local, RFC1918, `.local`, metadata IPs); redirect cap 3; 2 MB response cap; content-type allowlist; timeout.
- Parsers run only in the `SUBPROCESS` tier; results `UNTRUSTED`; citations with source URLs surfaced in the UI.
- Offline detection → `status:"unavailable"`; the model must state it could not search rather than answering as if it had.

**Tests:** SSRF corpus (raw IPs, decimal/octal/hex IPs, IPv6 loopback, DNS-rebinding fixture, redirect-to-internal, `0.0.0.0`, `169.254.169.254`) — **zero bypasses** · size/timeout caps · HTML sanitizer strips scripts and hidden text · injection in a fetched page cannot escalate a tool call · offline path reports honestly · a page-derived memory is marked `UNTRUSTED`.

**Non-goals:** no browser automation, no authenticated browsing, no cookie/session access, no downloads.

---

## Phase 10 — Vision

**Goal:** "what's on my screen?" via a separate vision model that swaps with the primary model.

**Dependencies:** Phase 8 (screenshot tool), Phase 4 (registry roles).

**Deliverables**
- `VisionProvider` registered under the `vision` role; explicit **load/unload swap** with `primary` (6 GB VRAM cannot hold both) with a user-visible "switching model" state.
- `describe_screen(region?)` / `describe_image(blob_ref)` tools — `MODERATE`, ASK, `produces_untrusted_content=true`. The primary model receives only the resulting **text**.
- Region selection UI; screenshot retention policy; screenshots excluded from exports by default.

**Tests:** swap does not exceed VRAM (assert via `nvidia-smi` sampling) · swap latency reported to the UI · screen-derived text is `UNTRUSTED` and taints the run · a screenshot containing injected instructions cannot trigger a destructive call · screenshot blobs honour retention.

**Non-goals:** no continuous screen monitoring, no OCR-driven automation, no vision in the primary chat path.

---

## Deferred / conditional

| Item | Trigger |
|---|---|
| Phase 6.5 vector retrieval (`sqlite-vec` + `bge-small`, same DB file) | measured retrieval recall inadequate on real usage |
| Phase 7.5 wake word + hands-free | Phase 7 stable and latency budget met |
| Proactive suggestions (from `BEHAVIORAL` memory) | Phase 8 stable; opt-in; suggestion-only, never action |
| Scheduled/background tasks | after proactive suggestions prove trustworthy; opt-in, visible, cancellable |
| Optional cloud provider | only with per-request explicit consent and a hard rule that memories are never transmitted without a separate opt-in |
| Calendar / email / messaging | requires the DPAPI credential broker first |

## Cross-phase invariants (re-verified every phase in CI)

1. No tool executes without an `Authorization` minted by the policy engine.
2. No decision exceeds the hard-deny baseline.
3. Memory never influences a policy decision.
4. Context assembly never exceeds `total_budget_tokens`.
5. Cancellation terminates model streaming and any running tool subprocess.
6. Idle CPU <1 %, idle Python RSS <400 MB.
7. No network egress outside Ollama loopback and explicitly-invoked web tools.
8. Unknown event types are tolerated by both ends.
