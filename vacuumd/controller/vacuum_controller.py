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

    def __init__(self, ip: str, token: str, name: str = "Vacuum"):
        self.ip = ip
        self.token = token
        self.name = name
        self.device = RoborockVacuum(ip, token)
        # Cache for status to avoid frequent UDP requests (TTL from settings)
        self._status_cache = TTLCache(maxsize=1, ttl=settings.server.cache_ttl)
        self._cache_key = f"{ip}_status"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
        reraise=True,
    )
    def _safe_call(self, method_name: str, *args, **kwargs):
        """
        Safely call a miio method with retry logic.
        """
        method = getattr(self.device, method_name)
        logger.debug(f"Calling {method_name} on {self.name} ({self.ip})")
        return method(*args, **kwargs)

    def status(self) -> VacuumState:
        """
        Get robot status with caching.
        Requests status from the physical device and converts it to VacuumState.
        """
        if self._cache_key in self._status_cache:
            return self._status_cache[self._cache_key]

        try:
            raw_status = self._safe_call("status")
            state = VacuumState.from_miio(raw_status)
            self._status_cache[self._cache_key] = state
            return state
        except Exception as e:
            logger.error(f"Failed to get status from {self.name}: {e}")
            raise

    def start(self):
        """Start cleaning."""
        return self._safe_call("start")

    def pause(self):
        """Pause cleaning."""
        return self._safe_call("pause")

    def home(self):
        """Return to dock."""
        return self._safe_call("home")

    def spot(self):
        """Spot cleaning."""
        return self._safe_call("spot")

    def set_fan_speed(self, speed: int):
        """Set fan speed (usually 60-102)."""
        if not (60 <= speed <= 102):
            raise ValueError("Fan speed must be between 60 and 102")
        return self._safe_call("set_fan_speed", speed)

    def find(self):
        """Find the robot (make it sound)."""
        return self._safe_call("find")

    def get_maps(self):
        """Get list of stored maps (floors)."""
        try:
            if hasattr(self.device, "get_maps"):
                return self._safe_call("get_maps")
            return None
        except Exception as e:
            logger.warning(f"Device does not support get_maps: {e}")
            return None

    def get_room_mapping(self):
        """Get mapping of segment IDs to room names."""
        try:
            return self._safe_call("get_room_mapping")
        except Exception as e:
            logger.warning(f"Device does not support get_room_mapping: {e}")
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
