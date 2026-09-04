$ErrorActionPreference = "Stop"

Write-Host "Starting ARTEMIS in development mode..."

# Tauri spawns the Python backend sidecar automatically.
# The dev server for the frontend is started by Tauri's beforeDevCommand (pnpm run dev).
Push-Location apps/desktop
pnpm install
pnpm run tauri dev
Pop-Location
