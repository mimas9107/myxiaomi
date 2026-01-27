from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from vacuumd.controller.manager import manager

router = APIRouter()


class CommandRequest(BaseModel):
    device_id: str
    command: str
    params: dict = {}


@router.post("/execute")
async def execute_command(req: CommandRequest):
    try:
        controller = manager.get_device(req.device_id)

        if req.command == "start":
            controller.start()
        elif req.command == "pause":
            controller.pause()
        elif req.command == "home":
            controller.home()
        elif req.command == "find":
            controller.find()
        elif req.command == "fanspeed":
            speed = req.params.get("speed")
            if speed is None:
                raise HTTPException(status_code=400, detail="Speed parameter required")
            controller.set_fan_speed(int(speed))
        elif req.command == "segment_clean":
            segments = req.params.get("segments")
            if not isinstance(segments, list):
                raise HTTPException(status_code=400, detail="Segments list required")
            controller.segment_clean(segments)
        elif req.command == "zoned_clean":
            zones = req.params.get("zones")
            if not isinstance(zones, list):
                raise HTTPException(status_code=400, detail="Zones list required")
            controller.zoned_clean(zones)
        elif req.command == "get_maps":
            return {"status": "success", "data": controller.get_maps().map_list}
        elif req.command == "get_rooms":
            return {"status": "success", "data": controller.get_room_mapping()}
        else:
            raise HTTPException(
                status_code=400, detail=f"Unknown command: {req.command}"
            )

        return {"status": "success", "message": f"Command '{req.command}' sent"}
    except KeyError:
        raise HTTPException(status_code=404, detail="Device not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
