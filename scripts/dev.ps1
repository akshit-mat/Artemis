$ErrorActionPreference = "Stop"

# Set up the Python environment and Tauri concurrently for dev mode
Write-Host "Starting ARTEMIS in development mode..."

# Start Tauri. The Tauri app will automatically spawn the Python backend sidecar.
Push-Location apps/desktop
npm install
npm run tauri dev
Pop-Location
