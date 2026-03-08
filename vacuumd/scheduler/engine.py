import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from vacuumd.config.settings import get_user_tz, settings
from vacuumd.controller.history_store import history_store
from vacuumd.controller.manager import manager
from vacuumd.model.cleaning_history import RunEvent, RunRecord

logger = logging.getLogger(__name__)
SYSTEM_JOB_RECONCILE_ID = "_reconcile_active_runs"
SYSTEM_JOB_FALLBACK_PREFIX = "_fallback_guard_"


class AutomationEngine:
    """
    自動化排程引擎，負責管理定時清掃任務並處理任務衝突。
    使用 APScheduler 作為底層排程工具。

    cron 時間依 config.yaml 中 server.timezone 設定解讀，
    內部時間戳一律使用 UTC。
    """

    def __init__(self):
        self._user_tz: ZoneInfo = get_user_tz()
        self.scheduler = BackgroundScheduler(timezone=self._user_tz)

        # 儲存格式: device_id -> {start_ts: 開始時間戳, est_end_ts: 預估結束時間戳}
        self.last_run_info: Dict[str, Dict[str, float]] = {}

        # 追蹤「已成功啟動但尚未完成」的執行實例
        # key: device_id
        self.active_runs: Dict[str, Dict[str, Any]] = {}

    def start(self):
        """啟動排程器。"""
        recovered = history_store.close_open_runs_as_unknown_end()
        if recovered > 0:
            logger.warning("啟動時補記 %s 筆 unknown_end 歷史紀錄", recovered)

        self.scheduler.start()
        self.scheduler.add_job(
            self._reconcile_active_runs,
            "interval",
            seconds=45,
            id=SYSTEM_JOB_RECONCILE_ID,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )

        now_utc = datetime.now(timezone.utc)
        now_local = now_utc.astimezone(self._user_tz)
        logger.info(
            "自動化引擎已啟動。時區設定: %s | 當前 UTC: %s | 當地: %s",
            self._user_tz,
            now_utc.strftime("%Y-%m-%dT%H:%M:%S UTC"),
            now_local.strftime("%Y-%m-%dT%H:%M:%S %Z"),
        )

    def add_cleaning_job(
        self,
        task_id: str,
        device_id: str,
        cron: str,
        est_duration: int,
        zones: Optional[List[int]] = None,
    ):
        """
        新增一個定時清掃任務。
        :param task_id: 任務唯一識別碼
        :param device_id: 機器人 ID
        :param cron: Cron 格式時間設定 (標準 5 欄: 分 時 日 月 週，依使用者時區解讀)
        :param est_duration: 預估清掃時長 (分鐘)
        :param zones: 分區 ID 列表，若為空或 None 則執行全屋清掃
        """
        trigger = CronTrigger.from_crontab(cron, timezone=self._user_tz)
        self.scheduler.add_job(
            self._smart_clean_job,
            trigger,
            id=task_id,
            args=[task_id, device_id, est_duration, zones or []],
            replace_existing=True,
        )

        zone_info = f" (分區: {zones})" if zones else " (全屋)"
        logger.info(
            "已排程任務 %s 給設備 %s，cron: %s (%s)%s",
            task_id,
            device_id,
            cron,
            self._user_tz,
            zone_info,
        )

    def add_fallback_guard_job(
        self,
        device_id: str,
        cron: str,
        confirm_seconds: int,
        recent_cleaning_minutes: int,
    ) -> None:
        """
        新增備援守門任務：若確認設備持續清掃中，則主動下達回充指令。

        目標情境：外部排程（例如米家 App）已啟動清掃，但本地服務恢復後需接管並終止該次任務。
        """
        job_id = f"{SYSTEM_JOB_FALLBACK_PREFIX}{device_id}"
        safe_confirm_seconds = max(1, int(confirm_seconds))
        safe_recent_cleaning_minutes = max(1, int(recent_cleaning_minutes))
        trigger = CronTrigger.from_crontab(cron, timezone=self._user_tz)
        self.scheduler.add_job(
            self._fallback_guard_home_job,
            trigger,
            id=job_id,
            args=[device_id, safe_confirm_seconds, safe_recent_cleaning_minutes],
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        logger.info(
            "已註冊備援守門任務：device=%s cron=%s confirm=%ss recent<=%sm (%s)",
            device_id,
            cron,
            safe_confirm_seconds,
            safe_recent_cleaning_minutes,
            self._user_tz,
        )

    def remove_cleaning_job(self, task_id: str) -> bool:
        """
        移除指定的排程任務。
        :param task_id: 任務唯一識別碼
        :return: 是否成功移除
        """
        try:
            self.scheduler.remove_job(task_id)
            logger.info("已移除排程任務: %s", task_id)
            return True
        except Exception:
            logger.warning("移除排程任務失敗 (可能不存在): %s", task_id)
            return False

    def list_jobs(self) -> List[Dict[str, Any]]:
        """
        列出目前所有排程任務及其下次觸發時間。
        回傳的時間同時包含 UTC 與使用者時區格式，並補充 cron 與分區資訊。
        """
        jobs = self.scheduler.get_jobs()
        result = []

        config_map = {s.task_id: s for s in settings.schedules}

        for job in jobs:
            if job.id == SYSTEM_JOB_RECONCILE_ID or job.id.startswith(
                SYSTEM_JOB_FALLBACK_PREFIX
            ):
                continue

            next_run_utc = (
                job.next_run_time.astimezone(timezone.utc) if job.next_run_time else None
            )
            next_run_local = (
                job.next_run_time.astimezone(self._user_tz) if job.next_run_time else None
            )

            cfg = config_map.get(job.id)
            cron_str = cfg.cron if cfg else "--"
            zones = cfg.zones if cfg else []
            device_id = cfg.device_id if cfg else "unknown"
            est_duration = cfg.est_duration if cfg else 40

            result.append(
                {
                    "task_id": job.id,
                    "device_id": device_id,
                    "cron": cron_str,
                    "zones": zones,
                    "est_duration": est_duration,
                    "next_run_utc": next_run_utc.isoformat() if next_run_utc else None,
                    "next_run_local": next_run_local.isoformat() if next_run_local else None,
                    "timezone": str(self._user_tz),
                }
            )
        return result

    def _is_cleaning_state(self, state: str) -> bool:
        normalized = (state or "").lower()
        return "clean" in normalized or "return" in normalized

    def _is_actively_cleaning_state(self, state: str) -> bool:
        """僅判定「正在掃地」，不包含 returning。"""
        normalized = (state or "").lower()
        return "clean" in normalized

    def _fallback_guard_home_job(
        self,
        device_id: str,
        confirm_seconds: int,
        recent_cleaning_minutes: int,
    ) -> None:
        """
        備援守門：
        1) 先檢查是否在掃地
        2) 等待 confirm_seconds
        3) 再確認一次仍在掃地才送回充
        """
        now = datetime.now(timezone.utc)
        logger.info(
            "執行備援守門檢查：device=%s UTC=%s",
            device_id,
            now.strftime("%Y-%m-%dT%H:%M:%S"),
        )

        try:
            if device_id in self.active_runs:
                logger.info(
                    "備援守門略過：device=%s 目前有本地 active run，避免誤停",
                    device_id,
                )
                return

            controller = manager.get_device(device_id)
            first_status = controller.status()
            if not self._is_actively_cleaning_state(first_status.state):
                logger.info(
                    "備援守門略過：device=%s 初次狀態=%s",
                    device_id,
                    first_status.state,
                )
                return

            recent_threshold_sec = recent_cleaning_minutes * 60
            first_clean_time_sec = self._parse_clean_time_to_sec(first_status.cleaning_since)
            if first_clean_time_sec > recent_threshold_sec:
                logger.info(
                    "備援守門略過：device=%s 初次清掃時長=%ss 超過門檻=%ss",
                    device_id,
                    first_clean_time_sec,
                    recent_threshold_sec,
                )
                return

            logger.warning(
                "備援守門偵測到疑似 fallback 清掃：device=%s state=%s clean_time=%s，%s 秒後再次確認",
                device_id,
                first_status.state,
                first_status.cleaning_since,
                confirm_seconds,
            )
            time.sleep(confirm_seconds)

            second_status = controller.status()
            if not self._is_actively_cleaning_state(second_status.state):
                logger.info(
                    "備援守門二次確認未命中：device=%s 二次狀態=%s，略過回充",
                    device_id,
                    second_status.state,
                )
                return

            second_clean_time_sec = self._parse_clean_time_to_sec(second_status.cleaning_since)
            if second_clean_time_sec > recent_threshold_sec:
                logger.info(
                    "備援守門二次確認略過：device=%s 二次清掃時長=%ss 超過門檻=%ss",
                    device_id,
                    second_clean_time_sec,
                    recent_threshold_sec,
                )
                return

            controller.home()
            logger.warning(
                "備援守門已下達回充：device=%s state=%s clean_time=%s",
                device_id,
                second_status.state,
                second_status.cleaning_since,
            )
        except Exception as exc:
            logger.error("備援守門執行失敗：device=%s error=%s", device_id, exc)

    def _parse_clean_time_to_sec(self, clean_time: str) -> int:
        # 預期格式: H:MM:SS
        try:
            parts = [int(x) for x in clean_time.split(":")]
            if len(parts) != 3:
                return 0
            return (parts[0] * 3600) + (parts[1] * 60) + parts[2]
        except Exception:
            return 0

    def _emit_event(
        self,
        run_id: str,
        task_id: str,
        device_id: str,
        zones: List[int],
        event_type: str,
        reason: Optional[str] = None,
    ) -> None:
        try:
            history_store.append_event(
                RunEvent.now(
                    run_id=run_id,
                    task_id=task_id,
                    device_id=device_id,
                    zones=zones,
                    event_type=event_type,
                    reason=reason,
                )
            )
        except Exception as exc:
            logger.error("寫入排程事件失敗: run_id=%s error=%s", run_id, exc)

    def _smart_clean_job(
        self,
        task_id: str,
        device_id: str,
        est_duration: int,
        zones: Optional[List[int]] = None,
    ):
        """
        核心任務執行邏輯，包含智慧衝突檢測：
        1. 檢查設備目前狀態 (是否已在清掃或回充中？)
        2. 檢查電池電量 (低於 20% 則不啟動)
        3. 檢查任務重疊 (判斷目前時間是否落在前次任務的預估清掃時間內)
        4. 若有指定 zones，則執行分區清掃；否則執行全屋清掃
        """
        zones = zones or []
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()
        now_local = now.astimezone(self._user_tz)
        run_id = f"{task_id}-{int(now_ts)}"

        zone_info = f"分區 {zones}" if zones else "全屋"
        logger.info(
            "嘗試執行排程任務：%s - %s (UTC: %s | %s: %s)",
            device_id,
            zone_info,
            now.strftime("%Y-%m-%dT%H:%M:%S"),
            self._user_tz,
            now_local.strftime("%Y-%m-%dT%H:%M:%S"),
        )

        try:
            controller = manager.get_device(device_id)
            status = controller.status()

            if self._is_cleaning_state(status.state):
                reason = f"任務衝突：設備目前狀態為 {status.state}"
                logger.warning("%s，略過此次排程。", reason)
                self._emit_event(
                    run_id, task_id, device_id, zones, event_type="skipped", reason=reason
                )
                return

            if status.battery < 20:
                reason = f"電量不足：{status.battery}%"
                logger.warning("%s，略過此次排程。", reason)
                self._emit_event(
                    run_id, task_id, device_id, zones, event_type="skipped", reason=reason
                )
                return

            if device_id in self.last_run_info:
                last_est_end_ts = self.last_run_info[device_id]["est_end_ts"]
                if now_ts < last_est_end_ts:
                    remaining = (last_est_end_ts - now_ts) / 60
                    reason = f"任務重疊：前次任務預估尚未結束（剩餘 {remaining:.1f} 分鐘）"
                    logger.warning("%s，略過此次排程。", reason)
                    self._emit_event(
                        run_id,
                        task_id,
                        device_id,
                        zones,
                        event_type="skipped",
                        reason=reason,
                    )
                    return

            if zones:
                logger.info("執行分區清掃：%s", zones)
                controller.segment_clean(zones)
            else:
                controller.start()

            est_end_ts = now_ts + (est_duration * 60)
            self.last_run_info[device_id] = {
                "start_ts": now_ts,
                "est_end_ts": est_end_ts,
            }

            self.active_runs[device_id] = {
                "run_id": run_id,
                "task_id": task_id,
                "device_id": device_id,
                "zones": zones,
                "started_at_utc": now.isoformat(),
                "start_ts": now_ts,
                "start_battery": status.battery,
                "start_area": float(status.cleaned_area),
                "start_clean_time_sec": self._parse_clean_time_to_sec(status.cleaning_since),
                "non_cleaning_count": 0,
            }

            self._emit_event(run_id, task_id, device_id, zones, event_type="started")

            est_end_utc = datetime.fromtimestamp(est_end_ts, timezone.utc)
            est_end_local = est_end_utc.astimezone(self._user_tz)
            logger.info(
                "任務成功啟動：%s。預估結束 UTC: %s | %s: %s",
                device_id,
                est_end_utc.strftime("%Y-%m-%dT%H:%M:%S"),
                self._user_tz,
                est_end_local.strftime("%Y-%m-%dT%H:%M:%S"),
            )

        except Exception as e:
            logger.error("執行智慧清掃任務時發生錯誤: %s", e)
            self._emit_event(
                run_id,
                task_id,
                device_id,
                zones,
                event_type="failed",
                reason=str(e),
            )

    def _reconcile_active_runs(self) -> None:
        """背景輪詢執行中 run，判斷是否完成並產生統計紀錄。"""
        if not self.active_runs:
            return

        now = datetime.now(timezone.utc)
        device_ids = list(self.active_runs.keys())

        for device_id in device_ids:
            run = self.active_runs.get(device_id)
            if not run:
                continue

            try:
                controller = manager.get_device(device_id)
                status = controller.status()
            except Exception as exc:
                logger.warning("輪詢執行狀態失敗: device=%s error=%s", device_id, exc)
                continue

            state = status.state or ""
            if self._is_cleaning_state(state):
                run["non_cleaning_count"] = 0
                continue

            # Busy/Unreachable 先延後判定，避免誤判結束
            lower_state = state.lower()
            if "offline" in lower_state or "unreachable" in lower_state or "busy" in lower_state:
                logger.info("設備 %s 目前狀態 %s，暫不判定 run 結束", device_id, state)
                continue

            run["non_cleaning_count"] = int(run.get("non_cleaning_count", 0)) + 1
            if run["non_cleaning_count"] < 2:
                continue

            ended_at_utc = now
            started_at_utc = datetime.fromisoformat(run["started_at_utc"])
            duration_sec = max(0, int((ended_at_utc - started_at_utc).total_seconds()))
            area_delta = max(0.0, float(status.cleaned_area) - float(run.get("start_area", 0.0)))
            battery_delta = max(0, int(run.get("start_battery", 0)) - int(status.battery))
            zones = run.get("zones", [])

            try:
                history_store.append_run_record(
                    RunRecord(
                        run_id=run["run_id"],
                        task_id=run["task_id"],
                        device_id=run["device_id"],
                        zones=zones,
                        started_at_utc=started_at_utc,
                        ended_at_utc=ended_at_utc,
                        duration_sec=duration_sec,
                        area_delta_m2=round(area_delta, 3),
                        battery_delta_pct=battery_delta,
                        status="completed",
                        is_estimated=len(zones) > 1,
                    )
                )
                self._emit_event(
                    run["run_id"],
                    run["task_id"],
                    run["device_id"],
                    zones,
                    event_type="completed",
                )
            except Exception as exc:
                logger.error("寫入執行完成紀錄失敗: run_id=%s error=%s", run["run_id"], exc)

            self.active_runs.pop(device_id, None)
            logger.info(
                "排程任務已完成: run_id=%s device=%s duration=%ss area=%.3fm2 battery=%s%%",
                run["run_id"],
                device_id,
                duration_sec,
                area_delta,
                battery_delta,
            )


automation = AutomationEngine()
