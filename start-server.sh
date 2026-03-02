#!/bin/bash

set -euo pipefail

export PATH="/home/mimas/.local/bin:$PATH"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
PY_BIN="${PROJECT_ROOT}/.venv/bin/python"
export UV_CACHE_DIR="${UV_CACHE_DIR:-${PROJECT_ROOT}/.uv-cache}"

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

# 釋放 8000 埠號
echo "Cleaning up port 8000..."
fuser -k 8000/tcp || true

# 啟動 API 伺服器
echo "Starting Vacuumd Server..."
/home/mimas/.local/bin/uv run --python "${PY_BIN}" \
  python -m uvicorn vacuumd.api.main:app --host 0.0.0.0 --port 8000
