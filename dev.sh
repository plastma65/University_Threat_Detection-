#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -f .env ]]; then
  echo "[INFO] Loading environment configuration from .env"
  # Export variables from .env, skipping comments and blank lines
  export $(grep -v '^#' .env | xargs)
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[ERROR] docker is not installed or not in PATH."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[ERROR] docker compose plugin is not available."
  exit 1
fi

echo "[INFO] Starting infrastructure: postgres, loki, grafana"
docker compose -f docker/docker-compose.yml up -d postgres loki grafana

echo "[INFO] Waiting for postgres readiness"
docker compose -f docker/docker-compose.yml exec -T postgres pg_isready -U "${POSTGRES_USER:-analyst}" -d "${POSTGRES_DB:-threat_detection}" >/dev/null

if [[ ! -d .venv ]]; then
  echo "[INFO] Creating .venv"
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "[INFO] Installing dependencies"
pip install -r requirements.txt

export PYTHONPATH=.

echo "[INFO] Seeding mock alerts (refreshing database for active time window)"
python src/tools/generate_mock_alerts.py --reset

echo "[INFO] Starting ML inference worker (background)"
(
  while true; do
    python src/ml_engine/inference_job.py || true
    sleep 60
  done
) &
WORKER_PID=$!
trap 'echo "[INFO] Stopping ML inference worker"; kill ${WORKER_PID} >/dev/null 2>&1 || true' EXIT INT TERM

echo "[INFO] Starting API on http://127.0.0.1:8000"
exec python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
