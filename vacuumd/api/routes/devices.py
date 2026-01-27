from fastapi import APIRouter, HTTPException
from vacuumd.controller.manager import manager
from typing import List

router = APIRouter()


@router.get("/")
async def list_devices():
    return manager.list_devices()


@router.get("/{device_id}/status")
async def get_device_status(device_id: str):
    try:
        controller = manager.get_device(device_id)
        return controller.status()
    except KeyError:
        raise HTTPException(status_code=404, detail="Device not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{device_id}/maps")
async def get_device_maps(device_id: str):
    try:
        controller = manager.get_device(device_id)
        return {"maps": controller.get_maps().map_list}
    except KeyError:
        raise HTTPException(status_code=404, detail="Device not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{device_id}/rooms")
async def get_device_rooms(device_id: str):
    try:
        controller = manager.get_device(device_id)
        return {"rooms": controller.get_room_mapping()}
    except KeyError:
        raise HTTPException(status_code=404, detail="Device not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
