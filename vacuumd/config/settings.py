import os
import yaml
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional


class DeviceConfig(BaseModel):
    """個別掃地機器人的配置資訊。"""

    id: str
    name: str
    ip: str
    token: str
    token_env: Optional[str] = None
    # 房間映射設定，key 為機器人內部的 Segment ID，value 為易讀的房間名稱
    room_mapping: Dict[int, str] = Field(default_factory=dict)


class ServerConfig(BaseModel):
    """伺服器運作相關配置。"""

    host: str = "0.0.0.0"
    port: int = 8000
    cache_ttl: int = 5  # 狀態快取時間 (秒)
    retry_count: int = 3  # API 呼叫失敗重試次數


class ScheduleConfig(BaseModel):
    """排程任務配置。"""

    task_id: str
    device_id: str
    cron: str  # 標準 5 欄 crontab: 分 時 日 月 週
    est_duration: int = 40
    enabled: bool = True
    # 分區清掃參數：若指定此參數，則只清掃指定的分區（而非全屋）
    # 可使用 zone 名稱（需配合 device 的 room_mapping）或直接指定 zone ID
    zones: Optional[List[int]] = Field(
        default_factory=list, description="分區 ID 列表，若為空則執行全屋清掃"
    )


class Settings(BaseModel):
    """全域配置結構。"""

    devices: List[DeviceConfig]
    server: ServerConfig
    schedules: List[ScheduleConfig] = Field(default_factory=list)


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
        devices = data.get("devices", [])
        for dev in devices:
            raw_token = str(dev.get("token", "")).strip()
            token_env = dev.get("token_env")

            if not raw_token and token_env:
                raw_token = os.getenv(token_env, "").strip()

            if not raw_token:
                dev_id = dev.get("id", "<unknown>")
                raise ValueError(
                    f"Device '{dev_id}' missing token. Set 'token' in config.yaml "
                    "or provide 'token_env' with a valid environment variable."
                )

            dev["token"] = raw_token

        return Settings(**data)


# 初始化全域 Singleton 設定實例，方便在專案各處引用
settings = load_settings()
