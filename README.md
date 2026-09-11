# ARTEMIS

ARTEMIS is a local-first, security-first AI desktop assistant for Windows. It combines a Tauri desktop application, a Python backend, local model providers, persistent state, and policy-controlled tools.

The core design principle is:

> **The model proposes. Policy decides. The runtime executes.**

ARTEMIS treats model output as untrusted input. Tool calls are validated, authorized, audited, and executed by deterministic application code. There is no unrestricted shell exposed to the model.

## What is included

- **Desktop app:** Tauri v2 shell with a React interface.
- **Backend:** Python 3.11, FastAPI, WebSocket events, SQLite persistence, and a handwritten agent loop.
- **Models:** Provider abstraction with Ollama support and a fake provider for tests.
- **Tools:** Explicitly registered tools with schemas, execution tiers, cancellation, and telemetry.
- **Security:** Policy evaluation, authorization, approval flows, taint tracking, filesystem containment, and fail-closed behavior.
- **Testing:** Python unit/integration tests, frontend tests, and Playwright end-to-end coverage.

## Repository layout

```text
.
├── apps/desktop/   Tauri, React, TypeScript, and frontend tests
├── backend/        Python core, API, agent, policy, tools, storage, and tests
├── docs/           Architecture and subsystem documentation
└── scripts/        Windows development and production build scripts
```

## Development

### Prerequisites

- Windows 11
- Python 3.11+
- [`uv`](https://docs.astral.sh/uv/)
- Node.js and [`pnpm`](https://pnpm.io/)
- Rust and the Tauri v2 prerequisites
- [Ollama](https://ollama.com/) for local model inference

### Run in development mode

From the repository root in PowerShell:

```powershell
.\scripts\dev.ps1
```

The script installs frontend dependencies and starts the Tauri development application. Tauri starts and supervises the Python backend sidecar.

### Build the application

```powershell
.\scripts\build.ps1
```

### Run tests

Backend:

```powershell
cd backend
uv run pytest
```

Frontend:

```powershell
cd apps\desktop
pnpm install
pnpm test
```

## Documentation

The root README is intentionally brief. Detailed design and security decisions are documented in:

- [Architecture](docs/architecture.md) — process topology, trust boundaries, storage, and failure modes
- [Agent](docs/agent.md) — agent loop, context assembly, budgets, and cancellation
- [API](docs/api.md) — HTTP and WebSocket contracts
- [Security](docs/security.md) — threat model, authorization, taint, filesystem rules, and audit
- [Tools](docs/tools.md) — tool contracts, registries, execution tiers, and runtime behavior
- [UI](docs/ui.md) — frontend state, visual precedence, and motion behavior
- [Memory](docs/memory.md) — memory schema, retrieval, and user controls
- [Voice](docs/voice.md) — speech interfaces and resource strategy
- [Roadmap](docs/roadmap.md) — phases, goals, tests, and non-goals
- [Decisions](docs/decisions.md) — architectural decisions and risk register

## Project status

ARTEMIS is under active development. The repository contains working foundations for the desktop shell, backend API, local model integration, streaming conversations, agent execution, policy enforcement, filesystem tools, approvals, and persistence. Security-sensitive features continue to require integration testing and hardening before they should be considered complete.

## License

This project is under active development. See the repository's license file for the applicable licensing terms.
