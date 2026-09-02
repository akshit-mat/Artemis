# ARTEMIS — Tool System

## 1. Responsibility & boundaries

The tool system is the **only** path from model intent to real-world effect. It owns: the tool contract, the registry, argument validation, execution isolation, timeouts, cancellation, result capture and truncation.

It does **not** decide *whether* an action is allowed — that is the policy engine. `ToolRuntime.execute()` is structurally unable to run without an `Authorization` object minted by the policy engine (see §5).

---

## 2. Tool contract

Every tool is a declarative object. Adding a tool must require **zero** changes to the agent, the policy engine or the UI.

```python
# backend/artemis/tools/contract.py  (illustrative)

class ToolSpec(BaseModel):
    name: str                      # snake_case, stable, versioned by suffix if breaking
    summary: str                    # one line, goes into the prompt
    args_model: type[BaseModel]     # Pydantic → JSON Schema for the model
    returns_model: type[BaseModel]
    category: ToolCategory          # system | apps | files | media | windows | web | memory | vision | meta
    risk: RiskLevel                 # READ_ONLY | LOW | MODERATE | DESTRUCTIVE | FORBIDDEN
    side_effects: bool
    reversible: bool                # true => undo path exists (e.g. recycle bin, move manifest)
    produces_untrusted_content: bool # file contents, web pages, screenshots, other apps' text
    tier: ExecTier                  # INLINE | THREAD | SUBPROCESS
    timeout_s: float                # ≤ 60
    default_decision: Decision      # ALLOW | ASK | DENY  (a *ceiling*, policy may only tighten)
    preview: Callable[[Args, ResolvedContext], ActionPreview] | None
    requires_paths: bool            # triggers path canonicalization + root checks
    execute: Callable[[Args, ToolContext], Awaitable[Result]]
```

Key fields and why they exist:

- **`risk`** drives default policy, UI colouring and the taint escalation lock.
- **`produces_untrusted_content`** is what makes prompt-injection defence automatic: any tool that can bring attacker-controlled text into context marks the run tainted. Forgetting to set it is the highest-value review item for any new tool.
- **`reversible`** decides whether the approval dialog can offer *Undo*, and whether the tool is eligible for a persistent grant.
- **`preview`** must produce the *resolved, concrete* action ("delete 34 files, 1.2 GB, from C:\Users\x\Downloads → Recycle Bin"), never the model's description.
- **`tier`** exists for cancellation and blast radius (§4).

`ToolContext` provides: `run_id`, `cancel_token`, `progress(pct, note)`, `logger`, `authorization`, `taint`, `blob_writer`. It does **not** provide the DB, the model, or the policy engine. Tools are leaves, not orchestrators.

### Result shape

```python
class ToolResult(BaseModel):
    status: Literal["ok","error","timeout","denied","unavailable","cancelled"]
    summary: str                 # ≤200 chars, human + model readable
    data: dict | None            # structured, may be large
    context_view: str            # ≤600 tokens, what actually enters the prompt
    result_id: str               # full result retrievable via read_more / GET /v1/results/{id}
    trust: Literal["SYSTEM","UNTRUSTED"]
    duration_ms: int
    error_code: str | None
    undo: UndoHandle | None
```

Tools **never** raise to the agent. Exceptions are caught by the runtime and converted to `status:"error"` with a stable `error_code`. Stack traces go to logs, not to the model.

---

## 3. Registry

Single in-process registry, populated at startup by explicit imports (no filesystem auto-discovery — plugin scanning is an attack surface and a debugging hazard).

```python
REGISTRY.register(GetCpuUsage, GetBattery, ...)   # explicit list in tools/builtin/__init__.py
```

Registry duties: name uniqueness, JSON-Schema generation, capability gating (a tool may declare `requires={"internet","gpu"}` and is reported `unavailable` rather than failing weirdly), enabled/disabled state from config, and the compact schema rendering used by the context assembler.

**Tool visibility ≠ tool permission.** A `DENY`-policy tool is *not exposed to the model at all* — omitted from the schema list. This saves context and removes the temptation. (Denied-by-taint tools are still listed, because they're allowed in untainted turns; the denial is explained at call time.)

---

## 4. Execution tiers

| Tier | Use for | Mechanism | Cancellable | Timeout enforcement |
|---|---|---|---|---|
| `INLINE` | pure-async, <100 ms (time, telemetry read from cache) | awaited directly | cooperative | soft |
| `THREAD` | short blocking calls <2 s (psutil, small file read) | bounded thread pool (8) | cooperative only | soft — logged if overrun |
| `SUBPROCESS` | anything slow, recursive, destructive, or parsing untrusted content (file search, bulk file ops, screenshot, web fetch, HTML/PDF extraction) | short-lived child process, JSON over stdio | **hard** (tree-kill) | **hard** |

**Why this matters:** Python cannot interrupt a thread blocked in a Win32 call. Without a subprocess tier, "cancel" and "timeout" are lies for exactly the operations where they matter most. Risk **R4**.

Subprocess worker properties:
- Started per call (cost ~120 ms with a pre-warmed interpreter pool of 2; acceptable) — **not** a long-lived privileged daemon.
- Receives only validated args + the authorization scope. No token, no DB path, no config secrets.
- `CREATE_NO_WINDOW`, assigned to a Job Object so grandchildren die with it.
- Memory cap and CPU-priority-below-normal for extraction work.
- Untrusted-content parsers (HTML, PDF, DOCX) run **only** here. A parser RCE then costs an unprivileged child process, not the TCB.

---

## 5. Authorization coupling (structural, not conventional)

```python
# policy/engine.py
class Authorization:
    __slots__ = ("tool","args_hash","scope","rule_id","granted_at","_sig")
    def __init__(self, *_, _internal: object = None):
        if _internal is not _POLICY_SENTINEL:
            raise RuntimeError("Authorization may only be minted by the policy engine")

# tools/runtime.py
async def execute(spec: ToolSpec, args: BaseModel, auth: Authorization, ctx: ToolContext) -> ToolResult:
    assert_matches(auth, spec.name, canonical_hash(args))   # re-verified at the door
    ...
```

Two properties: the runtime cannot be called without an `Authorization`, and the `Authorization` is re-checked against the *exact* arguments at execution time. This defeats TOCTOU-style argument mutation between approval and execution — a real hazard once approvals are asynchronous and user-visible.

---

## 6. Planned catalog (implementation deferred)

`risk` / `default_decision` / notes. `D` = destructive, `U` = produces untrusted content.

**System (Phase 4)** — all `READ_ONLY / ALLOW`, `INLINE|THREAD`
`get_time`, `get_system_info`, `get_cpu_usage`, `get_memory_usage`, `get_gpu_usage`, `get_battery`, `get_disk_usage`.
Values come from a 1 Hz sampler cache, not a fresh poll per call.

**Files (Phase 5)** — all `requires_paths=true`, `SUBPROCESS`
| Tool | Risk | Default | Notes |
|---|---|---|---|
| `search_files` | READ_ONLY | ALLOW | roots-restricted, result-capped (500), no content grep by default |
| `read_file` | READ_ONLY **U** | ASK | size cap 512 KB, text/detected-encoding only, secret-shaped paths hard-denied |
| `write_file` | MODERATE | ASK | create/overwrite; overwrite always previews a diff/size delta |
| `copy_file` / `move_file` / `rename_file` | MODERATE | ASK | batch previews with counts+bytes; move manifest enables undo |
| `delete_file` | DESTRUCTIVE **D** | ASK | **Recycle Bin by default** (`IFileOperation`); permanent delete is a separate hard-denied-by-default tool |
| `create_directory` | LOW | ASK | |
| `list_directory` | READ_ONLY **U** | ALLOW | names are untrusted content (a filename can carry an injection) |

**Applications (Phase 8)**
`list_running_apps` (READ_ONLY/ALLOW) · `focus_app` (LOW/ALLOW) · `open_app` (MODERATE/ASK — **allowlist of known apps resolved from Start Menu shortcuts + registry App Paths; never a raw path or command line from the model**) · `close_app` (MODERATE/ASK, graceful `WM_CLOSE` first, force-kill is a separate ASK, system-critical processes hard-denied).

**Windows / media (Phase 8)**
`set_volume`, `media_play_pause`, `media_next`, `media_prev` (LOW/ALLOW) · `set_brightness` (LOW/ALLOW) · `take_screenshot` (MODERATE **U**/ASK, stored as a blob, never auto-sent anywhere) · `lock_workstation` (MODERATE/ASK) · `sleep`/`shutdown`/`restart` (DESTRUCTIVE/ASK, never batchable).

**Web (Phase 9)** — `SUBPROCESS`, egress-controlled
`search_web` (READ_ONLY **U**/ASK→ALLOW after grant) · `open_page` (READ_ONLY **U**/ASK — headless fetch + sanitized extraction; **not** a browser automation surface) · `open_url_in_browser` (LOW/ASK — hands off to the user's browser, scheme allowlist `http/https` only).

**Meta (Phase 4)**
`read_more(result_id, offset, limit)` (READ_ONLY, inherits the source result's trust) · `remember(...)`/`forget(...)` (Phase 6, MODERATE/ASK-lite, see `memory.md`).

**Permanently forbidden (`risk=FORBIDDEN`, not implemented, hard-denied even if a future tool tries to register the capability):**
arbitrary shell/PowerShell execution · registry write · service/scheduled-task creation · elevation / UAC prompting · credential store, browser profile, SSH/cloud key, or password-manager file access · security-software modification · driver install · network listener creation · arbitrary process memory access · self-modification of ARTEMIS policy tables or its own binaries.

There is no `run_command` tool and there will never be one. Every capability is a *named, schema-bounded* tool. This is the single most important design constraint in ARTEMIS: the model's action space is a finite enumerated set, not a language.

---

## 7. Events

`tool.requested` → `tool.decision` → (`approval.requested`/`approval.resolved`) → `tool.started` → `tool.progress`* → `tool.result`. Emitted for every call including denials, so the UI timeline is complete and the audit trail matches what the user saw.

---

## 8. Security considerations

- Args validated by Pydantic **before** policy evaluation; policy sees typed, canonical values.
- Path canonicalization happens once, in the policy layer, and the **canonical paths are what the tool receives**. Tools never re-resolve user/model-supplied strings. (See `security.md` §5.)
- No tool composes a shell command. No `shell=True`. Process launches use argv lists against resolved executables.
- Result size caps prevent memory exhaustion and context blowup.
- `produces_untrusted_content=true` is mandatory for anything reading external bytes; reviewed on every new tool.
- Batch operations are capped (`max_batch_items`, default 200) and previews are mandatory above 10 items.

## 9. Failure behaviour

Missing capability → `unavailable` with reason. Timeout → tree-kill, `timeout`. Crash in subprocess → `error{WORKER_CRASH}`. Denied → `denied` with `rule_id`. Cancelled → `cancelled` + a statement of what already completed. Partial batch failure → `error` with per-item outcomes in `data` and a truthful `summary` ("moved 12 of 34; 22 failed: access denied").

## 10. Testing requirements

Per tool: happy path · every invalid-arg class · timeout · cancellation · permission denial · (if `requires_paths`) escape attempts from the fuzz corpus · result truncation correctness · `undo` round-trip where claimed. Plus a registry-wide meta-test asserting every tool declares a coherent `(risk, side_effects, reversible, produces_untrusted_content, default_decision)` combination — e.g. `DESTRUCTIVE ⇒ default_decision != ALLOW`, `produces_untrusted_content ⇒ trust=="UNTRUSTED"`.

## 11. Extension points

New category → add to `ToolCategory` + a policy default row. External integrations (calendar, email, smart home) → same contract, plus a credential broker that stores tokens in **Windows DPAPI** (not SQLite) and never exposes them to the model or to tool arguments. Vision → `describe_screen` tool that internally calls the `vision`-role provider; the primary model receives only the resulting text.
