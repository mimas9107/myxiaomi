#!/bin/bash

set -euo pipefail

export PATH="/home/mimas/.local/bin:$PATH"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
PY_BIN="${PROJECT_ROOT}/.venv/bin/python"
UV_BIN="/home/mimas/.local/bin/uv"
export UV_CACHE_DIR="${UV_CACHE_DIR:-${PROJECT_ROOT}/.uv-cache}"
PORT="${VACUUMD_PORT:-8000}"
LOG_FILE="${VACUUMD_LOG_FILE:-/tmp/myxiaomi.log}"
PID_FILE="${VACUUMD_PID_FILE:-/tmp/vacuumd.pid}"
MODE="${1:-daemon}"

cd "${PROJECT_ROOT}"

# 載入本地 .env（若存在）
if [ -f ".env" ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

# 啟動前檢查必要環境變數
if [ -z "${VACUUM_ROBOT_S5_TOKEN:-}" ]; then
  echo "Error: VACUUM_ROBOT_S5_TOKEN is not set."
  echo "Please export it first or define it in .env."
  exit 1
fi

if [ ! -x "${PY_BIN}" ]; then
  echo "Error: project venv python not found at ${PY_BIN}"
  echo "Please create the venv first (e.g. with uv sync)."
  exit 1
fi

if [ "${MODE}" != "daemon" ] && [ "${MODE}" != "--foreground" ]; then
  echo "Usage: ./start-server.sh [daemon|--foreground]"
  exit 1
fi

# 釋放埠號
echo "Cleaning up port ${PORT}..."
fuser -k "${PORT}/tcp" || true

SERVER_CMD=(
  "${UV_BIN}" run --python "${PY_BIN}"
  python -m uvicorn vacuumd.api.main:app --host 0.0.0.0 --port "${PORT}"
)

# 啟動 API 伺服器
if [ "${MODE}" = "--foreground" ]; then
  echo "Starting Vacuumd Server in foreground on port ${PORT}..."
  exec "${SERVER_CMD[@]}"
fi

echo "Starting Vacuumd Server in background on port ${PORT}..."
nohup "${SERVER_CMD[@]}" > "${LOG_FILE}" 2>&1 < /dev/null &
PID=$!
echo "${PID}" > "${PID_FILE}"
echo "Vacuumd started (PID=${PID})"
echo "Log file: ${LOG_FILE}"
echo "PID file: ${PID_FILE}"
