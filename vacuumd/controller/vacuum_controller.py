import logging
import time
import socket
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
        # 正確設定 timeout 的方式
        self.device.timeout = 5
        # 狀態快取，避免過於頻繁的 UDP 請求導致機器人無響應 (TTL 來自設定檔)
        self._status_cache = TTLCache(maxsize=1, ttl=settings.server.cache_ttl)

        self._cache_key = f"{ip}_status"

    def _is_port_open(self) -> bool:
        """快速檢測機器人 UDP 54321 埠口是否有反應 (不進行協定握手)"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1.0)
                # 發送一個空的 miio hello 封包 (這通常是 miio 探索的第一步)
                hello_msg = bytes.fromhex(
                    "21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                )
                s.sendto(hello_msg, (self.ip, 54321))
                data, _ = s.recvfrom(1024)
                return len(data) > 0
        except Exception:
            return False

    def status(self) -> VacuumState:
        """獲取機器人目前狀態 (包含連通性偵測、主動喚醒與快取檢查)。"""
        if self._cache_key in self._status_cache:
            return self._status_cache[self._cache_key]

        # 斷網環境防休眠機制：先發送一個 UDP Hello 封包預熱
        self._is_port_open()

        try:
            raw_status = self._safe_call("status")
            state = VacuumState.from_miio(raw_status, reachable=True)
        except Exception as e:
            # 發生錯誤時，嘗試「強力喚醒」機制
            logger.warning(f"通訊異常，嘗試強力喚醒機器人 {self.name} ({self.ip})...")

            # 第一階段喚醒：再次確認埠口
            reachable = self._is_port_open()

            if reachable:
                try:
                    # 第二階段喚醒：強制發送 info 請求重啟 session
                    self.device.send("miIO.info", [])
                    time.sleep(0.5)  # 給機器人一點反應時間
                    raw_status = self.device.status()
                    state = VacuumState.from_miio(raw_status, reachable=True)
                except:
                    # 如果埠口開著但通訊依然失敗，標記為 Busy (機器人正在嘗試重連雲端)
                    state = VacuumState.from_miio(None, reachable=True)
            else:
                # 埠口已關閉，機器人可能進入休眠或 Wi-Fi 重啟
                state = VacuumState.from_miio(None, reachable=False)

            if not state.is_reachable:
                # 針對 Unreachable 狀態，我們縮短快取時間，增加之後嘗試喚醒的頻率
                self._status_cache.set(self._cache_key, state, ttl=2)
                return state

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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
    )
    def _safe_call(self, method_name: str, *args, **kwargs):
        """帶有自動重試機制的底層 API 呼叫方法。"""
        method = getattr(self.device, method_name)
        return method(*args, **kwargs)
