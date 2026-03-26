from fastapi import APIRouter, HTTPException
from vacuumd.config.settings import settings
from vacuumd.controller.charging_watchdog import (
    charging_watchdog,
    init_charging_watchdog,
)

router = APIRouter()


@router.get("/status")
async def get_watchdog_status(device_id: str = None):
    """查看看門狗狀態"""
    if device_id is None:
        device_id = settings.devices[0].id if settings.devices else None

    if not device_id:
        raise HTTPException(status_code=400, detail="No device configured")

    if charging_watchdog is None:
        init_charging_watchdog()

    return charging_watchdog.get_status(device_id)


@router.get("/history")
async def get_watchdog_history(limit: int = 50, device_id: str = None):
    """查看觸發歷史"""
    if device_id is None:
        device_id = settings.devices[0].id if settings.devices else None

    if not device_id:
        raise HTTPException(status_code=400, detail="No device configured")

    if charging_watchdog is None:
        init_charging_watchdog()

    return charging_watchdog.get_history(limit)


@router.post("/test")
async def test_watchdog_home(device_id: str = None):
    """測試回充指令"""
    if device_id is None:
        device_id = settings.devices[0].id if settings.devices else None

    if not device_id:
        raise HTTPException(status_code=400, detail="No device configured")

    if charging_watchdog is None:
        init_charging_watchdog()

    success = charging_watchdog.test_home(device_id)
    if success:
        return {"status": "ok", "message": "Test home command sent"}
    else:
        raise HTTPException(status_code=500, detail="Failed to send home command")


@router.post("/pause")
async def pause_watchdog():
    """暫停看門狗"""
    if charging_watchdog is None:
        init_charging_watchdog()

    charging_watchdog.pause()
    return {"status": "ok", "message": "Watchdog paused"}


@router.post("/resume")
async def resume_watchdog():
    """恢復看門狗"""
    if charging_watchdog is None:
        init_charging_watchdog()

    charging_watchdog.resume()
    return {"status": "ok", "message": "Watchdog resumed"}
