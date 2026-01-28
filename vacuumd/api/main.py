from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from vacuumd.api.routes import devices, control
from vacuumd.config.settings import settings
from vacuumd.scheduler.engine import automation
import os
import logging

# 設定系統日誌
logging.basicConfig(level=logging.INFO)
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
    2. 設定初始的清掃任務 (Demo 範例)。
    """
    automation.start()

    # 範例任務：每天 13:00 自動執行一次清掃
    # 注意：device_id 必須對應 config.yaml 中的設定
    automation.add_cleaning_job(
        task_id="daily_clean", device_id="robot_s5", cron="00 13 * * *", est_duration=40
    )
    logger.info("系統啟動成功：排程引擎已運行並載入初始任務。")


@app.on_event("shutdown")
async def shutdown_event():
    """應用程式關閉時的安全停止邏輯。"""
    automation.scheduler.shutdown()
    logger.info("系統關閉：排程引擎已安全停止。")


# 載入 API 路由模組
app.include_router(devices.router, prefix="/v1/devices", tags=["設備管理"])
app.include_router(control.router, prefix="/v1/control", tags=["清掃控制"])

# 設定靜態資源路徑 (用於提供 Web 控制介面)
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "view")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def root():
    """首頁：直接回傳控制面板 HTML。"""
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/health")
async def health():
    """健康檢查接口：提供基本的系統狀態資訊。"""
    return {
        "project": "vacuumd",
        "status": "online",
        "devices_configured": len(settings.devices),
    }
