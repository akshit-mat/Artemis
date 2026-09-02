# ARTEMIS — Decisions & Risk Register

Part A: architecture decision records. Part B: prioritized risks with the mitigation actually adopted in the docs.

---

# Part A — Decision records

### ADR-001 — Tauri + React frontend, Python FastAPI backend, two processes

**Decision:** Tauri v2 (Rust) shell hosting a React/TS UI; a separate Python 3.11 FastAPI process (`artemis-core`) owning all assistant logic; the WebView talks to Python directly over authenticated loopback.
**Reason:** Python is where local-AI libraries live (Ollama client, faster-whisper, piper, psutil, pywin32). Tauri gives a ~10 MB shell with WebView2 (already on Windows 11) and ~250 MB UI RSS versus Electron's ~500 MB+ — meaningful on a 16 GB machine that must also hold an 8 B model. Routing streams through Rust IPC would make Rust a dumb pipe with re-implemented backpressure.
**Alternatives:** Electron + Node backend (loses the Python AI ecosystem); pure Rust backend (loses it entirely, and `candle`/`whisper-rs` maturity does not justify it); Rust-proxied IPC (complexity, no security gain).
**Tradeoff:** two languages, a sidecar to package, and an open loopback port. Mitigated by ADR-002 and R1.

### ADR-002 — Loopback transport secured by per-launch token + Origin allowlist

**Decision:** bind `127.0.0.1` on an ephemeral port; require a 256-bit per-launch bearer token (WS carries it as a subprotocol, since browsers cannot set WS headers); validate `Origin` and `Host`; no CORS.
**Reason:** a plain localhost port is reachable by any local process **and** by any web page in the user's browser. Once tools can delete files, that is remote privilege escalation. Origin validation is the specific control that stops the browser-mediated path.
**Alternatives:** Unix-domain-socket equivalent (Windows named pipes — better isolation but no browser WS support, forcing a Rust proxy); no auth (unacceptable).
**Tradeoff:** ~120 lines of middleware and a handshake. Does not stop same-user malware — stated explicitly rather than papered over.

### ADR-003 — No `run_command` tool, ever; the action space is a finite enumerated set

**Decision:** every capability is a named, schema-bounded tool. No shell, PowerShell, Python, SQL or JS execution tool exists or will be added.
**Reason:** a single generic execution tool collapses the entire permission system into "trust the model". Enumerated tools make the blast radius statically analysable and make policy expressible.
**Alternatives:** sandboxed shell with a command allowlist (allowlists on shell syntax are famously bypassable — pipes, substitution, encoding).
**Tradeoff:** more tools to write; some user requests are simply not expressible. Correct trade.

### ADR-004 — Hand-written agent loop, no agent framework

**Decision:** an explicit finite state machine in `agent/loop.py`. No LangChain / LlamaIndex / AutoGen / CrewAI.
**Reason:** we need exact control over cancellation scopes, token budgets, taint propagation and the `Authorization` coupling. Frameworks inject prompts we cannot audit, hide the retry/cancel semantics we depend on, and churn dependencies. The loop is ~300 lines.
**Alternatives:** LangGraph (closest fit, still opaque prompt handling and heavy transitive deps).
**Tradeoff:** we implement tool-call parsing and repair ourselves — which we would need to customize anyway for a small local model.

### ADR-005 — Taint-based prompt-injection defence (escalation lock)

**Decision:** context items carry `SYSTEM | USER | UNTRUSTED` trust. Any untrusted item taints the run. In a tainted run, side-effecting tools are forced to ASK (grants ignored) and destructive tools are DENIED. Destructive tools additionally require a user-anchored target.
**Reason:** prompt injection cannot be eliminated by prompting. It *can* be made harmless by making privilege depend on data provenance rather than on model judgement. This converts "read a malicious file → data loss" into a visible, audited, blocked security event.
**Alternatives:** prompt-based defences only (unreliable); dual-LLM sanitization (expensive, still model-dependent); refusing to read untrusted content (kills the product).
**Tradeoff:** occasional friction — a legitimate "read this file then delete it" needs a second user turn. Acceptable, and rare. This is the most important decision in the document.

### ADR-006 — LLM is the sole GPU tenant; other models are CPU or swapped

**Decision:** `qwen3:8b` Q4_K_M holds the GPU (`num_ctx=8192`, flash attention, `q8_0` KV cache, `keep_alive=30m`). Whisper and Piper run CPU-only. A future vision model **swaps with** the primary model, never co-resides. A small `fast`-role model handles summarization/extraction/tool-routing.
**Reason:** 6 GB VRAM. Weights ≈5.0 GB leave ~0.5–1 GB. Loading Whisper on CUDA would evict the LLM and cause multi-second reloads on every turn — far worse UX than slightly slower CPU STT (Whisper `small` int8 ≈0.25–0.4× real-time on this i7).
**Alternatives:** smaller LLM (Qwen3 4B) to free VRAM for GPU STT — kept as a documented config option, not the default; larger `num_ctx` (KV cache blowup, offload to system RAM, latency collapse).
**Tradeoff:** STT adds ~0.7 s; a vision query costs a model swap with a visible "switching" state.

### ADR-007 — SQLite + FTS5 for memory; vector search deferred behind an unchanged interface

**Decision:** one SQLite file, WAL, FTS5 lexical retrieval plus recency/confidence/usage scoring. An `embedding BLOB` column exists from day one but stays NULL. Upgrade path is `sqlite-vec` (a single DLL) in the *same* database file.
**Reason:** target steady state is <500 short memories, where bm25 + recency is competitive, adds zero dependencies, consumes no VRAM, and is debuggable — "why was this retrieved?" has an answer. A vector DB would be a second service for a few hundred rows.
**Alternatives:** Chroma/Qdrant/LanceDB (operational weight, RAM, no benefit at this scale); embeddings in-process from day one (VRAM/CPU cost before the need is proven).
**Tradeoff:** paraphrase recall is weaker. Trigger for the upgrade is measured, not assumed (Phase 6.5).

### ADR-008 — Three-tier tool execution; subprocess tier for anything slow, destructive or parsing untrusted bytes

**Decision:** `INLINE` (async, <100 ms) · `THREAD` (short blocking, <2 s) · `SUBPROCESS` (hard-killable child, JSON over stdio, Job Object, below-normal priority).
**Reason:** Python cannot interrupt a thread blocked in a Win32 call — so without a subprocess tier, "cancel" and "timeout" are *lies* for exactly the operations where they matter. It also contains parser vulnerabilities (HTML/PDF/DOCX) outside the trusted process.
**Alternatives:** threads only (uncancellable, blast radius inside the TCB); a persistent worker daemon (a long-lived privileged process is a worse target and complicates lifecycle).
**Tradeoff:** ~120 ms per-call overhead, mitigated by a 2-interpreter pre-warm pool.

### ADR-009 — Policy engine and tool framework ship in the same phase; `Authorization` is structurally required

**Decision:** Phase 4 delivers both. `ToolRuntime.execute()` requires an `Authorization` object that only the policy engine can mint, re-verified against `sha256(canonical_args)` at execution.
**Reason:** if tools ship first, the first filesystem tool runs unguarded and authorization must be retrofitted into every call site — the classic way permission bypasses get shipped. Making it a required, unforgeable parameter converts "we remembered to check" into "it does not compile otherwise", and closes the approval→execution TOCTOU window.
**Alternatives:** decorator-based checks (forgettable); middleware-style interception (implicit, hard to test).
**Tradeoff:** Phase 4 is the largest phase. Worth it.

### ADR-010 — Recycle Bin is the default deletion mechanism

**Decision:** `delete_file` uses `IFileOperation` → Recycle Bin. Permanent deletion is a distinct, baseline-denied capability requiring both a settings change and per-call approval.
**Reason:** the highest-probability harm in this product is not an attacker, it is a wrong path in a batch operation. Recoverability converts catastrophe into annoyance for near-zero cost.
**Alternatives:** permanent delete with confirmation (irreversible); custom trash directory (surprising, and diverges from Windows behaviour).
**Tradeoff:** disk space; Recycle Bin does not cover network paths (which are disabled by default anyway).

### ADR-011 — Backend is the single source of `AssistantState`

**Decision:** the backend computes `AssistantState` via a pure function with an explicit precedence order and pushes it; the frontend never infers state from message flow.
**Reason:** inferred UI state diverges from reality — stuck spinners, missed approvals, wrong orb. With voice and multi-step tools the number of concurrent conditions makes client-side inference untenable.
**Alternatives:** client-side derivation (bug factory); both (guaranteed disagreement).
**Tradeoff:** one extra event type.

### ADR-012 — One WebSocket for all realtime; HTTP for CRUD; no SSE

**Decision:** `WS /v1/events` carries server→client events and client→server control (including binary audio later). HTTP handles CRUD and bulk reads. Chat is initiated over the WS.
**Reason:** voice requires binary duplex; adding SSE now guarantees a second transport later. One socket means one ordering domain, one reconnect path, one auth path.
**Alternatives:** SSE + POST (needs a second channel for audio); HTTP streaming only (no client→server control).
**Tradeoff:** we implement `seq`/replay/backpressure ourselves (~80 lines).

### ADR-013 — Raw SQL + repositories, no ORM; numbered SQL migrations, no Alembic

**Decision:** parameterized SQL inside `storage/repositories/*.py`; migrations are numbered `.sql` files applied by a small forward-only migrator.
**Reason:** ~16 tables with simple access patterns. An ORM adds lazy-loading surprises, obscures the single-writer discipline WAL requires, and Alembic's autogenerate is noise at this scale. Explicit SQL is also easier for cheaper coding agents to get right than ORM session semantics.
**Alternatives:** SQLModel/SQLAlchemy + Alembic.
**Tradeoff:** more boilerplate; mitigated by keeping all access in repositories.

### ADR-014 — Pydantic models are the single schema source; TS types are generated

**Decision:** Pydantic → OpenAPI/JSON-Schema → generated TypeScript types, committed and CI-verified as up to date.
**Reason:** two hand-maintained copies of ~30 event schemas will drift, and drift in `approval.requested` is a security bug.
**Alternatives:** hand-written TS types; a shared JSON-Schema authored by hand.
**Tradeoff:** a codegen step in CI.

### ADR-015 — `faster-whisper` and Piper behind Protocols; audio I/O in Rust

**Decision:** `faster-whisper` (CTranslate2, int8, CPU) for STT and Piper (ONNX, CPU) for TTS, both behind `STTEngine`/`TTSEngine` Protocols. Capture/playback live in the Rust shell via `cpal`; frames cross the existing WS as binary.
**Reason:** faster-whisper gives whisper.cpp-class performance with a real Python API (no stdio parsing) and trivial device switching. Piper is ~40 MB per voice at ~0.1× real-time on this CPU. Windows audio device handling and low-latency callbacks are materially better in Rust, and it avoids the PortAudio-wheel problem entirely.
**Alternatives:** whisper.cpp via subprocess (parsing, weaker control); `sounddevice` in Python (Windows device-change and latency pain).
**Tradeoff:** the audio path spans two languages — contained behind the Protocols and one WS message type.

### ADR-016 — Policy rules in the database, hard-deny baseline in code

**Decision:** editable rules and grants live in SQLite with an audit trail; the non-overridable deny baseline is compiled into `policy/baseline.py`. Effective decision = `min(baseline, tool default, rule, taint modifier)`. A startup self-test refuses to run if the baseline is shadowed.
**Reason:** the DB gives auditability and UI editing; code gives an immutable floor that no config file, DB row, UI action or model output can raise. Config may only tighten.
**Alternatives:** all in TOML (trivially rewritten, no audit); all in DB (no immutable floor).
**Tradeoff:** changing the baseline requires a release. That is the point.

---

# Part B — Risk register

Ordered by severity. Every CRITICAL and HIGH item has a mitigation already embedded in the documents; the "Status" column names it.

### CRITICAL

**R1 — Loopback backend is a remote-attack surface**
An authenticated-looking local port that can delete files is reachable from any web page the user visits (CSRF / DNS rebinding) and from any local process.
*Status: mitigated.* Per-launch bearer token + Origin allowlist + Host validation + ephemeral loopback port, all Phase 1 with a gating rejection-matrix test (`api.md` §1, ADR-002). Residual: same-user malware — explicitly out of scope and documented rather than hidden.

**R2 — Prompt injection via tool results**
File contents, filenames, web pages and screenshots enter the context; the model will sometimes obey them. Prompt-only defences are not a control.
*Status: mitigated.* Taint model + escalation lock: tainted runs force side-effecting tools to ASK (grants ignored) and DENY destructive tools; destructive targets must be user-anchored (`security.md` §4, ADR-005). Gating test in Phase 4 and Phase 5. Residual: read-only exfiltration-shaped behaviour within allowed scopes — bounded by there being no unrestricted network egress tool.

**R3 — Permission bypass through config, memory, or a forgotten call site**
Three plausible paths: a permissive config/DB row, poisoned memory persuading the model it has rights, or a tool invoked without a policy check.
*Status: mitigated.* (a) Hard-deny baseline in code, `min()` lattice, startup self-test, tighten-only config (ADR-016). (b) R-PURE-POLICY: memory is not an input to authorization, with an explicit adversarial test in Phase 6. (c) `Authorization` object structurally required and re-verified at the runtime door (ADR-009). Residual: a future contributor adding a tool that bypasses the runtime — caught by the registry meta-test and code review.

### HIGH

**R4 — Cancellation and timeouts are unenforceable for blocking Python calls**
A thread stuck in a Win32 file operation cannot be killed. Without a fix, "Stop" is decorative on exactly the long operations users want to stop.
*Status: mitigated.* Three-tier execution with a hard-killable `SUBPROCESS` tier for everything slow, destructive or parsing untrusted bytes (ADR-008). Cancellation propagates to model streaming and the process tree. Committed side effects are reported truthfully, never silently rolled back.

**R5 — 6 GB VRAM contention across LLM / STT / vision**
Naively GPU-loading Whisper or a vision model evicts the LLM and produces multi-second reloads per turn.
*Status: mitigated.* Single-GPU-tenant rule; CPU-only STT/TTS; explicit vision↔primary swap with a visible state; VRAM assertions in Phase 7 and Phase 10 tests (ADR-006). Residual: a 6 GB card genuinely limits simultaneous capability — accepted, with a documented "smaller primary model" config path.

**R6 — Context growth destroying latency and coherence**
Tool schemas, verbatim history and large tool results (a 5 000-file listing) will silently consume the whole window.
*Status: mitigated.* Priority-tiered assembler with per-tier caps, explicit eviction order, logged budget breakdown, a never-exceed invariant test; `context_view` truncation with `result_id` + `read_more`; rolling async summary; ≤5 memories; tool-schema pruning and a `fast`-role tool router from Phase 6; reasoning never re-enters context (`agent.md` §4). Residual: heuristic token counting — absorbed by a 256-token safety margin.

**R7 — Small-model tool-calling unreliability**
Qwen3 8B will emit malformed calls, hallucinated tool names, and `<think>` bleed. Naive handling yields either crashes or invented arguments.
*Status: mitigated.* Provider-level extraction fallback chain (native → constrained JSON → text scan) with which-path metrics as a model-drift signal; strict schema validation; bounded repair loop (2) then honest failure; loop guard on repeated identical calls; unknown tool → DENY; reasoning split into its own channel. Never guess arguments (`agent.md` §3).

**R8 — Approval fatigue collapsing the permission system**
If ARTEMIS asks constantly, the user click-throughs everything and the whole system becomes theatre.
*Status: mitigated.* Read-only tools default ALLOW; structurally-scoped grants (Once / Session / 1 h / Always) so common flows stop asking; **"Always" is unavailable for destructive tools**; batch previews replace per-item prompts; no default-focused Allow button; 400 ms arm delay on destructive confirms; a Permissions panel that makes standing grants visible and revocable (`security.md` §3, `ui.md` §5). Residual: the ASK rate must be measured in real use during Phase 5–8 and defaults tuned; treat a high ASK rate as a design bug, not a user problem.

**R9 — Memory contamination**
Auto-storing inferences produces a confidently wrong self-reinforcing user model; untrusted content could rewrite the profile.
*Status: mitigated.* Explicit vs inferred split; inferred entries are `CANDIDATE` only, needing 3 corroborations across ≥2 distinct days (or user confirmation) for promotion; `BEHAVIORAL` requires explicit confirmation before entering context; explicit always supersedes inferred; `REJECTED` is sticky; untrusted provenance is barred from `PROFILE`/`PREFERENCE`; every memory has `origin_quote` and is editable/deletable; <500 steady-state target with a review prompt instead of silent growth (`memory.md` §4).

### MEDIUM

**R10 — Two-language packaging and Windows sidecar friction**
PyInstaller size (~250 MB with faster-whisper), antivirus false positives on a bundled interpreter, first-run latency, orphaned processes, and slower agent iteration across the boundary.
*Status: partially mitigated.* PyInstaller **onedir** (not onefile) to avoid extraction cost and reduce AV heuristics; Job Object `KILL_ON_JOB_CLOSE` prevents orphans; stdout JSON handshake removes port guessing; `scripts/dev.ps1` runs the backend natively for iteration. Residual: installer size and code-signing are unsolved until a release phase; ML model weights should be downloaded on first use rather than bundled.

**R11 — SQLite concurrency under async**
WAL allows one writer; naive concurrent writes from the API, agent, extraction job and audit writer produce `SQLITE_BUSY` and, worse, an audit write failing under load.
*Status: mitigated.* Single dedicated writer connection behind an `asyncio.Lock`, read pool, all calls off the event loop, `busy_timeout=5000`, repositories as the only access path (ADR-013). Audit-write failure aborts side-effecting tool calls rather than proceeding unaudited.

**R12 — `read_file` / `list_directory` as a data-exfiltration primitive**
Even read-only, these tools can pull sensitive content into a context that a future cloud provider or a compromised web tool might transmit.
*Status: partially mitigated.* Secret-shaped path denial, `allow_roots` restriction, 512 KB read cap, no unrestricted network tool, no cloud provider by default, and a hard rule that memories are never transmitted to a non-local provider without a separate explicit opt-in. Residual: if a cloud provider is ever added, per-request consent and a redaction pass are required — flagged as a gate on that work.

**R13 — Streaming UI performance**
Per-token `setState` with markdown re-parsing janks at 40 tok/s and makes the app feel worse than a terminal.
*Status: mitigated.* Server-side 30 ms delta coalescing, client-side rAF flush from a ref, selector-scoped Zustand subscriptions, virtualized card stream, a 500-card ≥50 fps test (`ui.md` §4).

### LOW

**R14 — Animation competing with inference for GPU/battery**
A persistent WebGL orb increases VRAM pressure and battery drain on a laptop whose GPU is busy generating tokens.
*Status: mitigated.* No persistent WebGL context; SVG/CSS + Framer Motion only; loop pauses on blur/minimize; 30 fps on battery; reduced-motion path (`ui.md` §3).

**R15 — Model replacement drift**
Prompts and tool-call handling silently co-evolve with Qwen3 until swapping models breaks everything.
*Status: mitigated.* Role-based registry in config, prompts keyed by role with per-model overrides, extraction-path metrics as a drift signal, and a gating acceptance test: the Phase 4 tool suite must pass against a second non-Qwen model before Phase 8 begins (`agent.md` §3).

---

## Open questions (decide before the phase that needs them)

| # | Question | Needed by |
|---|---|---|
| 1 | Which `fast`-role model (Qwen3 1.7B vs Llama 3.2 3B) for summarization/extraction/tool-routing, and CPU or on-demand GPU? | Phase 6 |
| 2 | Are ML weights bundled or downloaded on first run (installer size vs offline install)? | Phase 7 |
| 3 | Which web search backend (DuckDuckGo HTML, SearxNG instance, or an API key) given "no cloud dependency by default"? | Phase 9 |
| 4 | Retention defaults for screenshots and audio debug captures. | Phase 8 / 7 |
| 5 | Is code signing in scope for distribution, or is this personal-use-only (affects AV friction and installer work)? | first release |
