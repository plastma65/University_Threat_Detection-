#!/usr/bin/env pwsh
# ============================================================================
# University Threat Detection - Windows dev launcher
# PowerShell equivalent of dev.sh. Runs alongside it, does NOT replace.
# ============================================================================
# Usage:
#   .\dev.ps1
#
# Requirements:
#   - Docker Desktop running
#   - Python 3.11+ on PATH
#   - .env exists (copy from .env.example)
# ============================================================================

# Note: NOT using $ErrorActionPreference="Stop" because native commands (docker,
# pip) writing to stderr (warnings) get treated as terminating errors. We rely
# on $LASTEXITCODE checks instead.
$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

$ROOT_DIR = $PSScriptRoot
Set-Location $ROOT_DIR

function Write-Info($msg) { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[ERROR] $msg" -ForegroundColor Red }
function Write-Ok($msg)   { Write-Host "[OK]    $msg" -ForegroundColor Green }

# --- 1. Load .env ---------------------------------------------------------
if (-not (Test-Path .env)) {
    Write-Err ".env not found. Copy .env.example to .env first."
    exit 1
}

Write-Info "Loading environment configuration from .env"
Get-Content .env | Where-Object { $_ -match '^\s*[A-Z]' } | ForEach-Object {
    $name, $value = $_ -split '=', 2
    Set-Item -Path "Env:$name" -Value $value.Trim()
}

foreach ($required in @("DATABASE_URL", "JWT_SECRET_KEY", "POSTGRES_USER", "POSTGRES_DB")) {
    if (-not (Test-Path "Env:$required")) {
        Write-Err "$required is missing from .env"
        exit 1
    }
}

# --- 2. Check docker ------------------------------------------------------
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Err "docker is not installed or not in PATH."
    exit 1
}

& docker info --format '{{.ServerVersion}}' > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker daemon is not running. Start Docker Desktop first."
    exit 1
}

# --- 3. Start infrastructure ---------------------------------------------
Write-Info "Starting infrastructure: postgres, loki, grafana"
& docker compose --env-file .env -f docker/docker-compose.yml up -d postgres loki grafana
if ($LASTEXITCODE -ne 0) {
    Write-Err "docker compose up failed"
    exit 1
}

# --- 4. Wait for postgres ready ------------------------------------------
Write-Info "Waiting for postgres readiness"
$pgReady = $false
for ($i = 0; $i -lt 30; $i++) {
    & docker compose -f docker/docker-compose.yml exec -T postgres pg_isready -U $env:POSTGRES_USER -d $env:POSTGRES_DB > $null 2>&1
    if ($LASTEXITCODE -eq 0) { $pgReady = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $pgReady) {
    Write-Err "Postgres did not become ready within 60 seconds."
    exit 1
}
Write-Ok "Postgres ready"

# --- 5. Python venv -------------------------------------------------------
if (-not (Test-Path .venv)) {
    Write-Info "Creating .venv"
    & python -m venv .venv
}

Write-Info "Activating venv"
& .\.venv\Scripts\Activate.ps1

# --- 6. Install dependencies ---------------------------------------------
Write-Info "Installing dependencies (cached on subsequent runs)"
& python -m pip install -q -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Err "pip install failed"
    exit 1
}

$env:PYTHONPATH = "."

# --- 7. Seed mock alerts -------------------------------------------------
Write-Info "Seeding mock alerts (refreshing database for active time window)"
& python src/tools/generate_mock_alerts.py --reset

# --- 8. ML Inference Loop (Tuan Anh) -------------------------------------
# Uses scripts/run_inference_loop.py — proper CLI, per-cycle logging,
# graceful shutdown. Stop manually: Get-Job InferenceWorker | Stop-Job
Write-Info "Starting ML inference loop (background, 15-min interval)"
$inferenceJob = Start-Job -Name "InferenceWorker" -ScriptBlock {
    param($workDir)
    Set-Location $workDir
    $env:PYTHONPATH = "."
    & .\.venv\Scripts\python.exe scripts/run_inference_loop.py --interval 15
} -ArgumentList $ROOT_DIR
Write-Ok "Inference worker started (Job ID: $($inferenceJob.Id))"

# --- 9. Foreground uvicorn -----------------------------------------------
Write-Info "Starting FastAPI on http://localhost:8000 (Ctrl+C to stop)"
Write-Info "Swagger UI: http://localhost:8000/docs"
Write-Info "Grafana:    http://localhost:3000 (admin / `$env:GRAFANA_PASSWORD)"
Write-Host ""

try {
    & python -m uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
} finally {
    Write-Host ""
    Write-Info "Stopping background inference worker"
    Stop-Job  -Job $inferenceJob -ErrorAction SilentlyContinue
    Remove-Job -Job $inferenceJob -Force -ErrorAction SilentlyContinue

    Write-Info "Docker containers are still running. To stop them:"
    Write-Host "  docker compose -f docker/docker-compose.yml stop      # keep data" -ForegroundColor DarkGray
    Write-Host "  docker compose -f docker/docker-compose.yml down -v   # wipe data" -ForegroundColor DarkGray
}
