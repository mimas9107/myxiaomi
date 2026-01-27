import logging
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.background import BackgroundScheduler
from vacuumd.controller.manager import manager
from vacuumd.config.settings import settings

logger = logging.getLogger(__name__)


class AutomationEngine:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        # Storing as timestamps (float) for maximum compatibility
        self.last_run_info = {}  # device_id -> {start_ts, est_end_ts}

    def start(self):
        self.scheduler.start()
        logger.info("Automation Engine started.")

    def add_cleaning_job(
        self, task_id: str, device_id: str, cron: str, est_duration: int
    ):
        self.scheduler.add_job(
            self._smart_clean_job,
            "cron",
            id=task_id,
            args=[device_id, est_duration],
            hour=cron.split()[1],  # Simple parsing for demo
            minute=cron.split()[0],
        )
        logger.info(f"Scheduled task {task_id} for device {device_id} at {cron}")

    def _smart_clean_job(self, device_id: str, est_duration: int):
        """
        The core logic for conflict resolution and smart cleaning.
        Uses timezone-aware UTC time for internal logic.
        Checks for:
        1. Device current state (is it already cleaning?)
        2. Battery level (is it enough to start?)
        3. Task overlap (is it too soon after the last run?)
        """
        now = datetime.now(timezone.utc)
        now_ts = now.timestamp()

        logger.info(
            f"Attempting to start scheduled task for {device_id} at {now.isoformat()}"
        )

        try:
            controller = manager.get_device(device_id)
            status = controller.status()

            # 1. Conflict Check: Is it already cleaning?
            if "Cleaning" in status.state or "Returning" in status.state:
                logger.warning(
                    f"CONFLICT: Device {device_id} is currently {status.state}. Skipping scheduled task."
                )
                return

            # 2. Battery Check
            if status.battery < 20:
                logger.warning(
                    f"LOW BATTERY: {status.battery}% for {device_id}. Skipping task."
                )
                return

            # 3. Decision Logic: Overlap with previous task estimation?
            if device_id in self.last_run_info:
                last_est_end_ts = self.last_run_info[device_id]["est_end_ts"]
                if now_ts < last_est_end_ts:
                    remaining = (last_est_end_ts - now_ts) / 60
                    logger.warning(
                        f"OVERLAP: Previous task still in estimated duration. "
                        f"Est. {remaining:.1f} mins remaining. Skipping."
                    )
                    return

            # 4. Execute
            controller.start()

            # 5. Record Estimation
            est_end_ts = now_ts + (est_duration * 60)
            self.last_run_info[device_id] = {
                "start_ts": now_ts,
                "est_end_ts": est_end_ts,
            }

            readable_end = datetime.fromtimestamp(est_end_ts, timezone.utc).isoformat()
            logger.info(
                f"SUCCESS: Scheduled task started for {device_id}. Est. finish: {readable_end}"
            )

        except Exception as e:
            logger.error(f"Error in smart_clean_job: {e}")


# Global Engine Instance
automation = AutomationEngine()
