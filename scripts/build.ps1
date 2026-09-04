$ErrorActionPreference = "Stop"

Write-Host "Building ARTEMIS for production..."

# ── Backend: sync Python dependencies ────────────────────────────────────────
Push-Location backend
Write-Host "[1/3] Syncing Python dependencies..."
uv sync
Pop-Location

# ── Frontend: install and build ───────────────────────────────────────────────
Push-Location apps/desktop
Write-Host "[2/3] Building frontend..."
pnpm install --frozen-lockfile
pnpm run build
Pop-Location

# ── Rust/Tauri: production bundle ─────────────────────────────────────────────
Push-Location apps/desktop
Write-Host "[3/3] Building Tauri desktop bundle..."
pnpm run tauri build
Pop-Location

Write-Host "ARTEMIS build complete."
