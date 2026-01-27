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
    water_box_attached: Optional[bool] = False
    error: Optional[str] = None

    @classmethod
    def from_miio(cls, status: Any):
        """
        Convert python-miio status object to our internal VacuumState model.
        """
        # miio status object for S5 typically has state, battery, fanspeed, etc.
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
