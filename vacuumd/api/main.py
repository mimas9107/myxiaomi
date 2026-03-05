from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from vacuumd.api.routes import devices, control, schedules
from vacuumd.config.settings import settings
from vacuumd.scheduler.engine import automation
from vacuumd.controller.cloud_faker import cloud_faker
import os
import time
import logging

# 設定系統日誌 — 全域使用 UTC ISO8601 時間戳
_log_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
_log_formatter.converter = time.gmtime  # 強制使用 UTC 時間
_log_handler = logging.StreamHandler()
_log_handler.setFormatter(_log_formatter)
logging.root.handlers = [_log_handler]
logging.root.setLevel(logging.INFO)
logger = logging.getLogger(__name__)

# 初始化 FastAPI 應用程式
app = FastAPI(
    title="Vacuumd LAN Controller API",
    description="小米/石頭掃地機器人區域網路控制 API 服務",
)


@app.on_event("startup")
async def startup_event():
    """
    應用程式啟動時的初始化邏輯：
    1. 啟動自動化排程引擎 (Automation Engine)。
    2. 從設定檔載入並註冊排程任務。
    """
    automation.start()
    cloud_faker.start()

    loaded = 0
    for schedule in settings.schedules:
        if not schedule.enabled:
            continue
        try:
            automation.add_cleaning_job(
                task_id=schedule.task_id,
                device_id=schedule.device_id,
                cron=schedule.cron,
                est_duration=schedule.est_duration,
                zones=schedule.zones,
            )
            loaded += 1
        except Exception as exc:
            logger.error(
                "排程任務載入失敗: task_id=%s cron=%s error=%s",
                schedule.task_id,
                schedule.cron,
                exc,
            )
    logger.info("系統啟動成功：排程引擎已運行，已載入 %s 筆排程任務。", loaded)


@app.on_event("shutdown")
async def shutdown_event():
    """應用程式關閉時的安全停止邏輯。"""
    automation.scheduler.shutdown()
    logger.info("系統關閉：排程引擎已安全停止。")


# 載入 API 路由模組
app.include_router(devices.router, prefix="/v1/devices", tags=["設備管理"])
app.include_router(control.router, prefix="/v1/control", tags=["清掃控制"])
app.include_router(schedules.router, prefix="/v1/schedules", tags=["排程管理"])

# 設定靜態資源路徑 (用於提供 JS/CSS 等資源)
view_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "view")
app.mount(
    "/static", StaticFiles(directory=os.path.join(view_dir, "static")), name="static"
)


@app.get("/")
async def root():
    """首頁：直接回傳控制面板 HTML。"""
    return FileResponse(os.path.join(view_dir, "index.html"))


@app.get("/health")
async def health():
    """健康檢查接口：提供基本的系統狀態資訊。"""
    return {
        "project": "vacuumd",
        "status": "online",
        "devices_configured": len(settings.devices),
    }
