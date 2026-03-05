from pydantic import BaseModel, Field
from typing import Optional, List


class ScheduledTask(BaseModel):
    id: str
    device_id: str
    cron: str  # 標準 5 欄 crontab (依 server.timezone 設定解讀)
    name: str
    enabled: bool = True
    estimated_duration_mins: int = 40  # Default estimation
    zones: Optional[List[int]] = Field(
        default=None, description="分區 ID 列表，若為空則執行全屋清掃"
    )
