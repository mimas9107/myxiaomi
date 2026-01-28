import logging
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from vacuumd.controller.manager import manager
from vacuumd.config.settings import settings

logger = logging.getLogger(__name__)


class AutomationEngine:
    """
    自動化排程引擎，負責管理定時清掃任務並處理任務衝突。
    使用 APScheduler 作為底層排程工具。
    """

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        # 記錄設備最後運行的資訊，用於判斷任務重疊
        # 儲存格式: device_id -> {start_ts: 開始時間戳, est_end_ts: 預估結束時間戳}
        self.last_run_info = {}

    def start(self):
        """啟動排程器。"""
        self.scheduler.start()
        logger.info("自動化引擎已啟動。")

    def add_cleaning_job(
        self, task_id: str, device_id: str, cron: str, est_duration: int
    ):
        """
        新增一個定時清掃任務。
        :param task_id: 任務唯一識別碼
        :param device_id: 機器人 ID
        :param cron: Cron 格式時間設定 (目前僅支援簡單的 分 時 格式)
        :param est_duration: 預估清掃時長 (分鐘)
        """
        self.scheduler.add_job(
            self._smart_clean_job,
            "cron",
            id=task_id,
            args=[device_id, est_duration],
            hour=cron.split()[1],
            minute=cron.split()[0],
        )
        logger.info(f"已排程任務 {task_id} 給設備 {device_id}，時間設定：{cron}")

    def _smart_clean_job(self, device_id: str, est_duration: int):
        """
        核心任務執行邏輯，包含智慧衝突檢測：
        1. 檢查設備目前狀態 (是否已在清掃或回充中？)
        2. 檢查電池電量 (低於 20% 則不啟動)
        3. 檢查任務重疊 (判斷目前時間是否落在前次任務的預估清掃時間內)
        """
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()

        logger.info(f"嘗試執行排程任務：{device_id} (時間: {now.isoformat()})")

        try:
            controller = manager.get_device(device_id)
            status = controller.status()

            # 1. 衝突檢查：是否已經在運作？
            if "Cleaning" in status.state or "Returning" in status.state:
                logger.warning(
                    f"任務衝突：設備 {device_id} 目前狀態為 {status.state}，略過此次排程。"
                )
                return

            # 2. 電量檢查
            if status.battery < 20:
                logger.warning(
                    f"電量不足：{device_id} 電量僅剩 {status.battery}%，略過此次排程。"
                )
                return

            # 3. 智慧判定：是否與前一次任務的預估時間重疊？
            if device_id in self.last_run_info:
                last_est_end_ts = self.last_run_info[device_id]["est_end_ts"]
                if now_ts < last_est_end_ts:
                    remaining = (last_est_end_ts - now_ts) / 60
                    logger.warning(
                        f"任務重疊：前次任務預估尚未結束 (預計還剩 {remaining:.1f} 分鐘)，略過此次排程。"
                    )
                    return

            # 4. 執行啟動指令
            controller.start()

            # 5. 更新預估運行時間記錄
            est_end_ts = now_ts + (est_duration * 60)
            self.last_run_info[device_id] = {
                "start_ts": now_ts,
                "est_end_ts": est_end_ts,
            }

            readable_end = datetime.fromtimestamp(est_end_ts, timezone.utc).isoformat()
            logger.info(f"任務成功啟動：{device_id}。預估結束時間: {readable_end}")

        except Exception as e:
            logger.error(f"執行智慧清掃任務時發生錯誤: {e}")


# 全域自動化引擎實例
automation = AutomationEngine()
