import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from vacuumd.controller.manager import manager
from vacuumd.config.settings import settings, get_user_tz

logger = logging.getLogger(__name__)


class AutomationEngine:
    """
    自動化排程引擎，負責管理定時清掃任務並處理任務衝突。
    使用 APScheduler 作為底層排程工具。

    cron 時間依 config.yaml 中 server.timezone 設定解讀，
    內部時間戳一律使用 UTC。
    """

    def __init__(self):
        self._user_tz: ZoneInfo = get_user_tz()
        # APScheduler 使用使用者時區解讀 cron 觸發時間
        self.scheduler = BackgroundScheduler(timezone=self._user_tz)
        # 記錄設備最後運行的資訊，用於判斷任務重疊
        # 儲存格式: device_id -> {start_ts: 開始時間戳, est_end_ts: 預估結束時間戳}
        self.last_run_info: Dict[str, Dict[str, float]] = {}

    def start(self):
        """啟動排程器。"""
        self.scheduler.start()
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
            args=[device_id, est_duration, zones or []],
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
        回傳的時間同時包含 UTC 與使用者時區格式。
        """
        jobs = self.scheduler.get_jobs()
        result = []
        for job in jobs:
            next_run_utc = (
                job.next_run_time.astimezone(timezone.utc) if job.next_run_time else None
            )
            next_run_local = (
                job.next_run_time.astimezone(self._user_tz)
                if job.next_run_time
                else None
            )
            result.append(
                {
                    "task_id": job.id,
                    "next_run_utc": (
                        next_run_utc.isoformat() if next_run_utc else None
                    ),
                    "next_run_local": (
                        next_run_local.isoformat() if next_run_local else None
                    ),
                    "timezone": str(self._user_tz),
                }
            )
        return result

    def _smart_clean_job(
        self, device_id: str, est_duration: int, zones: Optional[List[int]] = None
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

            # 1. 衝突檢查：是否已經在運作？
            if "Cleaning" in status.state or "Returning" in status.state:
                logger.warning(
                    "任務衝突：設備 %s 目前狀態為 %s，略過此次排程。",
                    device_id,
                    status.state,
                )
                return

            # 2. 電量檢查
            if status.battery < 20:
                logger.warning(
                    "電量不足：%s 電量僅剩 %s%%，略過此次排程。",
                    device_id,
                    status.battery,
                )
                return

            # 3. 智慧判定：是否與前一次任務的預估時間重疊？
            if device_id in self.last_run_info:
                last_est_end_ts = self.last_run_info[device_id]["est_end_ts"]
                if now_ts < last_est_end_ts:
                    remaining = (last_est_end_ts - now_ts) / 60
                    logger.warning(
                        "任務重疊：前次任務預估尚未結束 (預計還剩 %.1f 分鐘)，略過此次排程。",
                        remaining,
                    )
                    return

            # 4. 執行啟動指令 (分區 or 全屋)
            if zones:
                # 分區清掃模式
                logger.info("執行分區清掃：%s", zones)
                controller.segment_clean(zones)
            else:
                # 全屋清掃模式
                controller.start()

            # 5. 更新預估運行時間記錄
            est_end_ts = now_ts + (est_duration * 60)
            self.last_run_info[device_id] = {
                "start_ts": now_ts,
                "est_end_ts": est_end_ts,
            }

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


# 全域自動化引擎實例
automation = AutomationEngine()
