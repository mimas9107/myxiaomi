import os
import yaml
from pathlib import Path
from pydantic import BaseModel
from typing import List, Dict, Optional


class DeviceConfig(BaseModel):
    """個別掃地機器人的配置資訊。"""

    id: str
    name: str
    ip: str
    token: str
    # 房間映射設定，key 為機器人內部的 Segment ID，value 為易讀的房間名稱
    room_mapping: Optional[Dict[int, str]] = {}


class ServerConfig(BaseModel):
    """伺服器運作相關配置。"""

    host: str = "0.0.0.0"
    port: int = 8000
    cache_ttl: int = 5  # 狀態快取時間 (秒)
    retry_count: int = 3  # API 呼叫失敗重試次數


class Settings(BaseModel):
    """全域配置結構。"""

    devices: List[DeviceConfig]
    server: ServerConfig


def load_settings() -> Settings:
    """從 YAML 檔案載入設定。"""
    # 優先尋找與 settings.py 同目錄下的 config.yaml
    config_path = Path(__file__).parent / "config.yaml"
    if not config_path.exists():
        # 退而求其次尋找當前工作目錄下的 config.yaml
        config_path = Path("config.yaml")

    if not config_path.exists():
        raise FileNotFoundError(
            f"找不到配置檔案 config.yaml at {config_path.absolute()}"
        )

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return Settings(**data)


# 初始化全域 Singleton 設定實例，方便在專案各處引用
settings = load_settings()
