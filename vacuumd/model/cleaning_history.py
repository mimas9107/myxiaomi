from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field


RunEventType = Literal[
    "started",
    "skipped",
    "failed",
    "completed",
    "incomplete",
    "unknown_end",
]

RunStatus = Literal["completed", "failed", "skipped", "incomplete", "unknown_end"]


class RunEvent(BaseModel):
    run_id: str
    task_id: str
    device_id: str
    zones: List[int] = Field(default_factory=list)
    event_type: RunEventType
    ts_utc: datetime
    reason: Optional[str] = None

    @classmethod
    def now(
        cls,
        run_id: str,
        task_id: str,
        device_id: str,
        zones: Optional[List[int]],
        event_type: RunEventType,
        reason: Optional[str] = None,
    ) -> "RunEvent":
        return cls(
            run_id=run_id,
            task_id=task_id,
            device_id=device_id,
            zones=zones or [],
            event_type=event_type,
            ts_utc=datetime.now(timezone.utc),
            reason=reason,
        )


class RunRecord(BaseModel):
    run_id: str
    task_id: str
    device_id: str
    zones: List[int] = Field(default_factory=list)

    started_at_utc: datetime
    ended_at_utc: datetime
    duration_sec: int = 0

    area_delta_m2: float = 0.0
    battery_delta_pct: int = 0

    status: RunStatus
    is_estimated: bool = False
    meta: Dict[str, str] = Field(default_factory=dict)
