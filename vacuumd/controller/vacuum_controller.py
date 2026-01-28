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
    增強型掃地機器人控制器，封裝了 python-miio 的底層操作。
    提供了自動重試 (Tenacity) 與狀態快取 (Cachetools) 機制，以提升穩定性。
    """

    def __init__(
        self, ip: str, token: str, name: str = "Vacuum", device_id: str = None
    ):
        self.ip = ip
        self.token = token
        self.name = name
        self.device_id = device_id
        self.device = RoborockVacuum(ip, token)
        # 狀態快取，避免過於頻繁的 UDP 請求導致機器人無響應 (TTL 來自設定檔)
        self._status_cache = TTLCache(maxsize=1, ttl=settings.server.cache_ttl)
        self._cache_key = f"{ip}_status"

    def get_room_mapping(self):
        """獲取房間編號與名稱的映射關係。"""
        # 1. 優先從本地配置獲取 (解決部分舊版韌體或 S5 機器人無法透過 API 讀取房間名稱的問題)
        if self.device_id:
            for dev_cfg in settings.devices:
                if dev_cfg.id == self.device_id and dev_cfg.room_mapping:
                    return [[int(k), v] for k, v in dev_cfg.room_mapping.items()]

        # 2. 如果配置中沒有，嘗試從機器人 API 獲取
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
        """指定房間清掃 (透過 Segment ID)。"""
        if hasattr(self.device, "segment_clean"):
            return self._safe_call("segment_clean", segment_ids)
        return self._safe_call("app_segment_clean", segment_ids)

    def zoned_clean(self, zones: list[list[int]]):
        """
        指定區域清掃。
        每個區域格式為 [x1, y1, x2, y2, 清掃次數]。
        Roborock 座標通常在 15000-35000 之間。
        """
        if hasattr(self.device, "zoned_clean"):
            return self._safe_call("zoned_clean", zones)
        return self._safe_call("app_zoned_clean", zones)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
    )
    def _safe_call(self, method_name: str, *args, **kwargs):
        """帶有自動重試機制的底層 API 呼叫方法。"""
        method = getattr(self.device, method_name)
        return method(*args, **kwargs)

    def status(self) -> VacuumState:
        """獲取機器人目前狀態 (包含快取檢查)。"""
        if self._cache_key in self._status_cache:
            return self._status_cache[self._cache_key]

        raw_status = self._safe_call("status")
        state = VacuumState.from_miio(raw_status)
        self._status_cache[self._cache_key] = state
        return state

    def start(self):
        """啟動清掃任務。"""
        return self._safe_call("start")

    def pause(self):
        """暫停清掃。"""
        return self._safe_call("pause")

    def home(self):
        """停止清掃並返回充電座。"""
        return self._safe_call("home")

    def find(self):
        """讓機器人發出聲音以供尋找。"""
        return self._safe_call("find")

    def set_fan_speed(self, speed: int):
        """調整吸力強度 (通常範圍為 60-105)。"""
        return self._safe_call("set_fan_speed", speed)

    def get_maps(self):
        """獲取雲端儲存的地圖列表資訊。"""
        return self._safe_call("get_maps")
