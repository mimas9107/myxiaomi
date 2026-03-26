import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from vacuumd.config.settings import Settings

from vacuumd.controller.manager import manager
from vacuumd.model.watchdog_state import (
    WatchdogState,
    TriggerReason,
    SuppressReason,
    TriggerHistory,
    WatchdogStatus,
    WatchdogHistory,
    VacuumStatusSnapshot,
    WatchdogConfig,
)
from vacuumd.model.robot_state import VacuumState

logger = logging.getLogger(__name__)

STATE_CODE_CHARGING = 8
STATE_CODE_CHARGING_PROBLEM = 9
STATE_CODE_CHARGER_DISCONNECTED = 2
ERROR_CODE_CHARGING_FAULT = 13

CLEANING_STATE_CODES = {5, 11, 17, 18}
RETURNING_STATE_CODES = {6, 15}


class BatteryTracker:
    """追蹤電量變化趨勢"""

    def __init__(self, window_minutes: int = 15):
        self.window = window_minutes * 60
        self.history: List[Tuple[float, int]] = []

    def record(self, battery: int) -> None:
        now = time.monotonic()
        self.history = [(ts, bat) for ts, bat in self.history if now - ts < self.window]
        self.history.append((now, battery))

    def is_stagnant(self, min_samples: int = 3) -> bool:
        """電量是否停滯（窗口內無變化）"""
        if len(self.history) < min_samples:
            return False
        batteries = [bat for _, bat in self.history]
        return len(set(batteries)) == 1

    def is_decreasing(self) -> bool:
        """電量是否下降"""
        if len(self.history) < 2:
            return False
        return self.history[-1][1] < self.history[0][1]

    def get_start_battery(self) -> Optional[int]:
        """取得窗口起始電量"""
        if not self.history:
            return None
        return self.history[0][1]

    def get_current_battery(self) -> Optional[int]:
        """取得目前電量"""
        if not self.history:
            return None
        return self.history[-1][1]

    def clear(self) -> None:
        self.history.clear()


class StateOscillationTracker:
    """追蹤狀態切換頻率"""

    def __init__(self, window_minutes: int = 5, threshold: int = 3):
        self.window = window_minutes * 60
        self.threshold = threshold
        self.transitions: List[Tuple[float, str]] = []

    def record(self, state: str) -> None:
        now = time.monotonic()
        self.transitions = [
            (ts, s) for ts, s in self.transitions if now - ts < self.window
        ]
        if not self.transitions or self.transitions[-1][1] != state:
            self.transitions.append((now, state))

    def is_oscillating(self) -> bool:
        """是否在窗口內發生足夠多次狀態切換"""
        return len(self.transitions) >= self.threshold

    def clear(self) -> None:
        self.transitions.clear()


class ChargingWatchdog:
    """
    充電座看門狗，監控掃地機器人充電狀態並在異常時觸發回充。
    """

    def __init__(
        self,
        config: Optional[WatchdogConfig] = None,
    ):
        self.config = config or WatchdogConfig()
        self._state = WatchdogState.IDLE
        self._last_check_time: Optional[float] = None
        self._last_check_utc: Optional[datetime] = None
        self._last_cleaning_end_time: Optional[float] = None
        self._cooldown_end_time: Optional[float] = None

        self._battery_trackers: Dict[str, BatteryTracker] = {}
        self._state_trackers: Dict[str, StateOscillationTracker] = {}
        self._confirmation_counts: Dict[str, int] = {}

        self._trigger_history: List[TriggerHistory] = []

        from vacuumd.config.settings import settings

        for device in settings.devices:
            self._battery_trackers[device.id] = BatteryTracker(
                self.config.battery_stagnant_window_minutes
            )
            self._state_trackers[device.id] = StateOscillationTracker(
                self.config.oscillation_window_minutes,
                self.config.oscillation_threshold,
            )
            self._confirmation_counts[device.id] = 0

    @property
    def state(self) -> WatchdogState:
        return self._state

    def check(self, device_id: str) -> Tuple[bool, Optional[str]]:
        """
        執行一次檢查，回傳 (是否觸發, 觸發原因)。
        """
        self._last_check_time = time.monotonic()
        self._last_check_utc = datetime.now(timezone.utc)

        controller = manager.get_device(device_id)

        suppress_reason = self._should_suppress(device_id)
        if suppress_reason:
            logger.debug(
                f"[CHARGING_WATCHDOG] [{device_id}] 抑制中: {suppress_reason.value}"
            )
            self._state = WatchdogState.MONITORING
            return False, None

        try:
            status = controller.status()
        except Exception as exc:
            logger.warning(f"[CHARGING_WATCHDOG] [{device_id}] 狀態讀取失敗: {exc}")
            self._state = WatchdogState.MONITORING
            return False, None

        state_code = status.state_code
        error_code = status.error_code

        battery = status.battery
        state_str = status.state

        if battery < self.config.min_reliable_battery:
            logger.debug(
                f"[CHARGING_WATCHDOG] [{device_id}] 電量過低 ({battery}%)，視為讀取失敗"
            )
            self._state = WatchdogState.MONITORING
            return False, None

        battery_tracker = self._battery_trackers[device_id]
        state_tracker = self._state_trackers[device_id]

        battery_tracker.record(battery)
        state_tracker.record(state_str)

        logger.debug(
            f"[CHARGING_WATCHDOG] [{device_id}] state={state_str} state_code={state_code} battery={battery}% is_on_charger={status.is_on_charger}"
        )

        layer1_trigger, layer1_reason = self._check_layer1_fault(state_code, error_code)
        if layer1_trigger and layer1_reason:
            self._trigger_home(
                device_id, layer1_reason, battery, battery, state_code, error_code
            )
            return True, layer1_reason

        layer2_trigger, layer2_reason = self._check_layer2_battery(
            device_id, battery_tracker, state_str
        )
        if layer2_trigger and layer2_reason:
            self._confirmation_counts[device_id] += 1
            if self._confirmation_counts[device_id] >= self.config.confirmation_count:
                start_bat = battery_tracker.get_start_battery() or battery
                self._trigger_home(
                    device_id, layer2_reason, start_bat, battery, state_code, error_code
                )
                self._confirmation_counts[device_id] = 0
                return True, layer2_reason
            else:
                logger.info(
                    f"[CHARGING_WATCHDOG] [{device_id}] 確認 {self._confirmation_counts[device_id]}/{self.config.confirmation_count}: {layer2_reason}"
                )
        else:
            self._confirmation_counts[device_id] = 0

        self._state = WatchdogState.MONITORING
        return False, None

    def _should_suppress(self, device_id: str) -> Optional[SuppressReason]:
        """檢查是否應該抑制偵測"""
        now = datetime.now(timezone.utc)
        now_ts = time.monotonic()

        if not self.config.enabled:
            return SuppressReason.SCHEDULE_WINDOW

        local_now = datetime.now()
        current_hour = local_now.hour
        if (
            current_hour < self.config.daily_start_hour
            or current_hour >= self.config.daily_end_hour
        ):
            return SuppressReason.SCHEDULE_WINDOW

        minute = now.minute
        if 0 <= minute <= 35:
            return SuppressReason.SCHEDULE_WINDOW

        if self._cooldown_end_time and now_ts < self._cooldown_end_time:
            return SuppressReason.POST_TRIGGER_COOLDOWN

        if self._last_cleaning_end_time:
            grace_end = self._last_cleaning_end_time + (
                self.config.post_cleaning_grace_minutes * 60
            )
            if now_ts < grace_end:
                return SuppressReason.POST_CLEANING_GRACE

        return None

    def _check_layer1_fault(
        self, state_code: Optional[int], error_code: Optional[int]
    ) -> Tuple[bool, Optional[TriggerReason]]:
        """Layer 1: 錯誤碼偵測"""
        if state_code == STATE_CODE_CHARGING_PROBLEM:
            return True, TriggerReason.STATE_CODE_9
        if error_code == ERROR_CODE_CHARGING_FAULT:
            return True, TriggerReason.ERROR_CODE_13
        if state_code == STATE_CODE_CHARGER_DISCONNECTED:
            return True, TriggerReason.STATE_CODE_2
        return False, None

    def _check_layer2_battery(
        self, device_id: str, tracker: BatteryTracker, state_str: str
    ) -> Tuple[bool, Optional[TriggerReason]]:
        """Layer 2: 電量變化偵測"""
        if "Charging" not in state_str and "charging" not in state_str.lower():
            return False, None

        if tracker.is_stagnant(self.config.confirmation_count + 1):
            return True, TriggerReason.BATTERY_STAGNANT
        if tracker.is_decreasing():
            return True, TriggerReason.BATTERY_DECREASING

        state_tracker = self._state_trackers[device_id]
        if state_tracker.is_oscillating():
            return True, TriggerReason.STATE_OSCILLATION

        return False, None

    def _trigger_home(
        self,
        device_id: str,
        reason: TriggerReason,
        battery_start: int,
        battery_end: int,
        state_code: Optional[int] = None,
        error_code: Optional[int] = None,
    ) -> bool:
        """觸發回充指令"""
        try:
            controller = manager.get_device(device_id)
            controller.home()

            time.sleep(2)

            status = controller.status()
            new_state_code = getattr(status, "state_code", None)
            new_error_code = getattr(status, "error_code", None)

            if new_state_code in {6, 15} or new_error_code == 0:
                logger.info(
                    f"[CHARGING_WATCHDOG] [{device_id}] 回充指令已接受，正在返回"
                )
                cooldown_duration = self.config.post_trigger_cooldown_minutes * 60
                self._cooldown_end_time = time.monotonic() + cooldown_duration
                self._state = WatchdogState.COOLDOWN
            else:
                logger.warning(
                    f"[CHARGING_WATCHDOG] [{device_id}] 回充未成功回應，state_code={new_state_code} error_code={new_error_code}，不進入冷卻期"
                )
                self._state = WatchdogState.MONITORING

            history = TriggerHistory(
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                reason=reason,
                battery_start=battery_start,
                battery_end=battery_end,
                state_code=state_code,
                error_code=error_code,
                action="home",
                success=True,
                device_id=device_id,
            )
            self._trigger_history.append(history)

            logger.warning(
                f"[CHARGING_WATCHDOG] [{device_id}] 觸發回充: {reason.value} "
                f"(battery: {battery_start}%→{battery_end}%, state_code={state_code})"
            )

            return True

        except Exception as exc:
            history = TriggerHistory(
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                reason=reason,
                battery_start=battery_start,
                battery_end=battery_end,
                state_code=state_code,
                error_code=error_code,
                action="home",
                success=False,
                device_id=device_id,
            )
            self._trigger_history.append(history)

            logger.error(f"[CHARGING_WATCHDOG] [{device_id}] 觸發失敗: {exc}")
            self._state = WatchdogState.MONITORING
            return False

    def on_cleaning_started(self, device_id: str) -> None:
        """清掃開始時的回調"""
        logger.info(f"[CHARGING_WATCHDOG] [{device_id}] 清掃開始，重置追蹤器")

    def on_cleaning_ended(self, device_id: str) -> None:
        """清掃結束時的回調"""
        logger.info(f"[CHARGING_WATCHDOG] [{device_id}] 清掃結束，啟動寬限期")
        self._last_cleaning_end_time = time.monotonic()
        self._battery_trackers[device_id].clear()
        self._state_trackers[device_id].clear()
        self._confirmation_counts[device_id] = 0

    def get_status(self, device_id: str) -> WatchdogStatus:
        """取得看門狗狀態"""
        suppress_reason = self._should_suppress(device_id)

        cooldown_remaining = 0
        if self._cooldown_end_time:
            remaining = self._cooldown_end_time - time.monotonic()
            cooldown_remaining = max(0, int(remaining))

        next_check = self.config.check_interval_seconds
        if self._last_check_time:
            elapsed = time.monotonic() - self._last_check_time
            next_check = max(0, self.config.check_interval_seconds - int(elapsed))

        current_status = None
        try:
            controller = manager.get_device(device_id)
            status = controller.status()
            current_status = VacuumStatusSnapshot(
                battery=status.battery,
                state=status.state,
                state_code=getattr(status, "state_code", None),
                error_code=getattr(status, "error_code", None),
                is_on_charger=status.is_on_charger,
                is_reachable=status.is_reachable,
            )
        except Exception:
            pass

        return WatchdogStatus(
            enabled=self.config.enabled,
            state=self._state,
            last_check_utc=self._last_check_utc.isoformat()
            if self._last_check_utc
            else None,
            next_check_in_seconds=next_check,
            cooldown_remaining_seconds=cooldown_remaining,
            is_suppressed=suppress_reason is not None,
            suppress_reason=suppress_reason,
            current_status=current_status,
            device_id=device_id,
        )

    def get_history(self, limit: int = 50) -> WatchdogHistory:
        """取得觸發歷史"""
        return WatchdogHistory(triggers=self._trigger_history[-limit:])

    def pause(self) -> None:
        """暫停看門狗"""
        self.config.enabled = False
        self._state = WatchdogState.PAUSED
        logger.info("[CHARGING_WATCHDOG] 看門狗已暫停")

    def resume(self) -> None:
        """恢復看門狗"""
        self.config.enabled = True
        self._state = WatchdogState.IDLE
        logger.info("[CHARGING_WATCHDOG] 看門狗已恢復")

    def test_home(self, device_id: str) -> bool:
        """測試回充指令"""
        try:
            controller = manager.get_device(device_id)
            controller.home()
            logger.info(f"[CHARGING_WATCHDOG] [{device_id}] 測試回充成功")
            return True
        except Exception as exc:
            logger.error(f"[CHARGING_WATCHDOG] [{device_id}] 測試回充失敗: {exc}")
            return False


charging_watchdog: Optional["ChargingWatchdog"] = None


def init_charging_watchdog(config: Optional[WatchdogConfig] = None):
    global charging_watchdog
    if config is None:
        from vacuumd.config.settings import settings

        config = WatchdogConfig(
            enabled=settings.watchdog.enabled,
            check_interval_seconds=settings.watchdog.check_interval_seconds,
            confirmation_count=settings.watchdog.confirmation_count,
            suppress_window_start=settings.watchdog.suppress_window_start,
            suppress_window_end=settings.watchdog.suppress_window_end,
            post_cleaning_grace_minutes=settings.watchdog.post_cleaning_grace_minutes,
            post_trigger_cooldown_minutes=settings.watchdog.post_trigger_cooldown_minutes,
            battery_stagnant_window_minutes=settings.watchdog.battery_stagnant_window_minutes,
            min_reliable_battery=settings.watchdog.min_reliable_battery,
            oscillation_threshold=settings.watchdog.oscillation_threshold,
            oscillation_window_minutes=settings.watchdog.oscillation_window_minutes,
            daily_start_hour=settings.watchdog.daily_start_hour,
            daily_end_hour=settings.watchdog.daily_end_hour,
        )
    charging_watchdog = ChargingWatchdog(config)
