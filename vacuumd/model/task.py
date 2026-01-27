from pydantic import BaseModel
from typing import Optional


class ScheduledTask(BaseModel):
    id: str
    device_id: str
    cron: str  # e.g., "0 13 * * *" for 13:00 every day
    name: str
    enabled: bool = True
    estimated_duration_mins: int = 40  # Default estimation
