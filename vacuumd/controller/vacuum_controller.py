import logging
import time
from typing import Optional, Dict
from miio import RoborockVacuum
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
from cachetools import TTLCache
from vacuumd.model.robot_state import VacuumState
from vacuumd.config.settings import settings

logger = logging.getLogger(__name__)


class VacuumController:
    """
    Enhanced controller for Roborock/Xiaomi Vacuum Robots with retry and caching.
    """

    def __init__(
        self, ip: str, token: str, name: str = "Vacuum", device_id: str = None
    ):
        self.ip = ip
        self.token = token
        self.name = name
        self.device_id = device_id
        self.device = RoborockVacuum(ip, token)
        # Cache for status to avoid frequent UDP requests (TTL from settings)
        self._status_cache = TTLCache(maxsize=1, ttl=settings.server.cache_ttl)
        self._cache_key = f"{ip}_status"

    def get_room_mapping(self):
        """Get mapping of segment IDs to room names."""
        # 1. 優先從本地配置獲取 (解決舊版韌體無法讀取房間列表的問題)
        if self.device_id:
            for dev_cfg in settings.devices:
                if dev_cfg.id == self.device_id and dev_cfg.room_mapping:
                    return [[int(k), v] for k, v in dev_cfg.room_mapping.items()]

        # 2. 如果配置中沒有，嘗試從機器人獲取
        try:
            rooms = self._safe_call("get_room_mapping")
            if not rooms:
                segments = self._safe_call("get_segment_status")
                if segments:
                    return [[s, f"Segment {s}"] for s in segments]
            return rooms
        except Exception as e:
            logger.warning(f"Device does not support room mapping: {e}")
            return []

    def segment_clean(self, segment_ids: list[int]):
        """Clean specific rooms by their segment IDs."""
        if hasattr(self.device, "segment_clean"):
            return self._safe_call("segment_clean", segment_ids)
        return self._safe_call("app_segment_clean", segment_ids)

    def zoned_clean(self, zones: list[list[int]]):
        """
        Clean specific zones.
        Each zone is [x1, y1, x2, y2, iterations].
        Coordinates are usually 15000-35000.
        """
        if hasattr(self.device, "zoned_clean"):
            return self._safe_call("zoned_clean", zones)
        return self._safe_call("app_zoned_clean", zones)
