from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import timedelta


class VacuumState(BaseModel):
    state: str
    battery: int
    fanspeed: int
    cleaning_since: str  # Format: "H:MM:SS"
    cleaned_area: float  # in m2
    is_on_charger: bool
    is_reachable: bool = True  # 新增：標記設備在 LAN 是否可連線
    water_box_attached: Optional[bool] = False
    error: Optional[str] = None

    @classmethod
    def from_miio(cls, status: Any, reachable: bool = True):
        """
        Convert python-miio status object to our internal VacuumState model.
        """
        if not reachable or status is None:
            return cls(
                state="Offline/Busy" if reachable else "Unreachable",
                battery=0,
                fanspeed=0,
                cleaning_since="0:00:00",
                cleaned_area=0.0,
                is_on_charger=False,
                is_reachable=reachable,
                error="Device busy or unreachable in LAN"
                if reachable
                else "Heartbeat failed",
            )

        state_str = str(status.state)
        return cls(
            state=state_str,
            battery=status.battery,
            fanspeed=status.fanspeed,
            cleaning_since=str(status.clean_time),
            cleaned_area=status.clean_area,
            is_on_charger="Charging" in state_str
            or "docked" in state_str.lower()
            or "charger" in state_str.lower()
            and "disconnected" not in state_str.lower(),
            water_box_attached=getattr(status, "water_box_attached", False),
            error=getattr(status, "error", None),
        )
