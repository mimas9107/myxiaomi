from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime


class WatchdogState(str, Enum):
    """看門狗運作狀態"""

    IDLE = "Idle"
    MONITORING = "Monitoring"
    TRIGGERED = "Triggered"
    COOLDOWN = "Cooldown"
    PAUSED = "Paused"


class TriggerReason(str, Enum):
    """觸發原因"""

    STATE_CODE_9 = "state_code_9"
    ERROR_CODE_13 = "error_code_13"
    STATE_CODE_2 = "state_code_2"
    BATTERY_STAGNANT = "battery_stagnant"
    BATTERY_DECREASING = "battery_decreasing"
    STATE_OSCILLATION = "state_oscillation"


class SuppressReason(str, Enum):
    """抑制原因"""

    SCHEDULE_WINDOW = "schedule_window"
    CLEANING_ACTIVE = "cleaning_active"
    RETURNING = "returning"
    POST_CLEANING_GRACE = "post_cleaning_grace"
    POST_TRIGGER_COOLDOWN = "post_trigger_cooldown"
    READ_FAILED = "read_failed"


class TriggerHistory(BaseModel):
    """觸發歷史記錄"""

    timestamp_utc: str
    reason: TriggerReason
    battery_start: Optional[int] = None
    battery_end: Optional[int] = None
    state_code: Optional[int] = None
    error_code: Optional[int] = None
    action: str = "home"
    success: bool
    device_id: str


class VacuumStatusSnapshot(BaseModel):
    """Vacuum 狀態快照"""

    battery: int
    state: str
    state_code: Optional[int] = None
    error_code: Optional[int] = None
    is_on_charger: bool
    is_reachable: bool


class WatchdogStatus(BaseModel):
    """看門狗狀態回應"""

    enabled: bool
    state: WatchdogState
    last_check_utc: Optional[str] = None
    next_check_in_seconds: int = 0
    cooldown_remaining_seconds: int = 0
    is_suppressed: bool = False
    suppress_reason: Optional[SuppressReason] = None
    current_status: Optional[VacuumStatusSnapshot] = None
    device_id: str


class WatchdogHistory(BaseModel):
    """看門狗觸發歷史回應"""

    triggers: List[TriggerHistory] = Field(default_factory=list)


class WatchdogConfig(BaseModel):
    """看門狗配置"""

    enabled: bool = True
    check_interval_seconds: int = 60
    confirmation_count: int = 2
    suppress_window_start: str = ":00"
    suppress_window_end: str = ":35"
    post_cleaning_grace_minutes: int = 10
    post_trigger_cooldown_minutes: int = 15
    battery_stagnant_window_minutes: int = 15
    min_reliable_battery: int = 5
    oscillation_threshold: int = 3
    oscillation_window_minutes: int = 5
    daily_start_hour: int = 7
    daily_end_hour: int = 22
