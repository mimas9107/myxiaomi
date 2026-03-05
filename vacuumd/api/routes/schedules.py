from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from vacuumd.scheduler.engine import automation
from vacuumd.config.settings import settings, save_schedules, ScheduleConfig

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
    # 1. 檢查 task_id 是否已存在
    if any(s.task_id == req.task_id for s in settings.schedules):
        raise HTTPException(status_code=400, detail=f"排程 ID '{req.task_id}' 已存在")

    # 2. 檢查 device_id 是否存在
    from vacuumd.controller.manager import manager
    try:
        manager.get_device(req.device_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Device '{req.device_id}' not found",
        )

    try:
        # 3. 更新引擎
        automation.add_cleaning_job(
            task_id=req.task_id,
            device_id=req.device_id,
            cron=req.cron,
            est_duration=req.est_duration,
            zones=req.zones,
        )

        # 4. 更新設定物件並儲存到檔案
        new_schedule = ScheduleConfig(
            task_id=req.task_id,
            device_id=req.device_id,
            cron=req.cron,
            est_duration=req.est_duration,
            zones=req.zones or []
        )
        settings.schedules.append(new_schedule)
        save_schedules(settings.schedules)

    except Exception as e:
        # 發生錯誤時嘗試從引擎移除，維持一致性
        automation.remove_cleaning_job(req.task_id)
        raise HTTPException(status_code=400, detail=f"排程建立失敗: {e}")

    return {
        "status": "success",
        "message": f"排程 '{req.task_id}' 已建立並成功儲存 (cron: {req.cron}, timezone: {settings.server.timezone})",
    }


@router.put("/{task_id}")
async def update_schedule(task_id: str, req: ScheduleCreateRequest):
    """更新現有的排程任務。"""
    # 1. 檢查 task_id 是否存在
    old_schedule = next((s for s in settings.schedules if s.task_id == task_id), None)
    if not old_schedule:
        raise HTTPException(status_code=404, detail=f"找不到排程 ID '{task_id}'")

    # 2. 檢查 device_id 是否存在
    from vacuumd.controller.manager import manager
    try:
        manager.get_device(req.device_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail=f"Device '{req.device_id}' not found",
        )

    try:
        # 3. 更新引擎 (replace_existing=True 會處理更新)
        automation.add_cleaning_job(
            task_id=task_id,  # 即使 req.task_id 不同，我們也以 URL 為主
            device_id=req.device_id,
            cron=req.cron,
            est_duration=req.est_duration,
            zones=req.zones,
        )

        # 4. 更新設定物件
        # 如果使用者想改 task_id，建議先刪除再新增，這裡我們鎖定 URL 的 task_id
        old_schedule.device_id = req.device_id
        old_schedule.cron = req.cron
        old_schedule.est_duration = req.est_duration
        old_schedule.zones = req.zones or []
        
        # 5. 儲存到檔案
        save_schedules(settings.schedules)

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"排程更新失敗: {e}")

    return {
        "status": "success",
        "message": f"排程 '{task_id}' 已更新並成功儲存",
    }


@router.delete("/{task_id}")
async def delete_schedule(task_id: str):
    """移除指定的排程任務。"""
    # 1. 從引擎移除
    removed = automation.remove_cleaning_job(task_id)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"排程 '{task_id}' 不存在或已被移除",
        )

    # 2. 從設定物件移除並持久化
    settings.schedules = [s for s in settings.schedules if s.task_id != task_id]
    save_schedules(settings.schedules)

    return {
        "status": "success",
        "message": f"排程 '{task_id}' 已移除並更新設定檔",
    }
