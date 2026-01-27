#!/bin/bash

# 釋放 8000 埠號
echo "Cleaning up port 8000..."
fuser -k 8000/tcp || true

# 啟動 API 伺服器
echo "Starting Vacuumd Server..."
uv run uvicorn vacuumd.api.main:app --host 0.0.0.0 --port 8000
