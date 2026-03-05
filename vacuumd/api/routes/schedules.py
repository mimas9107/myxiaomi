from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from vacuumd.scheduler.engine import automation
from vacuumd.config.settings import settings

router = APIRouter()


class ScheduleCreateRequest(BaseModel):
    """新增排程的請求結構。cron 時間依 server.timezone 設定解讀。"""

    task_id: str
    device_id: str
    cron: str = Field(
        ..., description="標準 5 欄 crontab (分 時 日 月 週)，依 server.timezone 解讀"
    )
    est_duration: int = Field(default=40, description="預估清掃時長 (分鐘)")
    zones: Optional[List[int]] = Field(
        default=None, description="分區 ID 列表，若為空則執行全屋清掃"
    )


@router.get("/")
async def list_schedules():
    """列出目前所有排程任務及下次觸發時間（含 UTC 與使用者時區）。"""
    jobs = automation.list_jobs()
    return {
        "timezone": settings.server.timezone,
        "schedules": jobs,
    }


@router.post("/")
async def create_schedule(req: ScheduleCreateRequest):
    """
    新增一個排程任務。cron 時間依 config.yaml 中 server.timezone 設定解讀。
    例如 timezone 為 Asia/Taipei 時，cron "0 13 * * *" 代表台北時間 13:00。
    """
    # 檢查 device_id 是否存在
    from vacuumd.controller.manager import manager

    try:
        manager.get_device(req.device_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Device '{req.device_id}' not found",
        )

    try:
        automation.add_cleaning_job(
            task_id=req.task_id,
            device_id=req.device_id,
            cron=req.cron,
            est_duration=req.est_duration,
            zones=req.zones,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"排程建立失敗: {e}")

    return {
        "status": "success",
        "message": f"排程 '{req.task_id}' 已建立 (cron: {req.cron}, timezone: {settings.server.timezone})",
    }


@router.delete("/{task_id}")
async def delete_schedule(task_id: str):
    """移除指定的排程任務。"""
    removed = automation.remove_cleaning_job(task_id)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"排程 '{task_id}' 不存在或已被移除",
        )
    return {
        "status": "success",
        "message": f"排程 '{task_id}' 已移除",
    }
