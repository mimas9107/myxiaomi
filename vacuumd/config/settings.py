import os
import yaml
from pathlib import Path
from zoneinfo import ZoneInfo
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
    # 使用者時區 (IANA 格式，如 "Asia/Taipei")。
    # cron 排程時間會依此時區解讀；內部邏輯仍統一使用 UTC。
    timezone: str = "UTC"
    # 備援守門：每小時檢查是否因外部定時而正在清掃，若持續清掃則回充
    fallback_guard_enabled: bool = True
    fallback_guard_cron: str = "31 * * * *"
    # 為了繞過 status TTLCache，建議設定至少 > cache_ttl
    fallback_guard_confirm_seconds: int = 6
    # 僅攔截「剛啟動不久」的清掃（分鐘），避免誤停本地長任務
    fallback_guard_recent_cleaning_minutes: int = 10


class ScheduleConfig(BaseModel):
    """排程任務配置。"""

    task_id: str
    device_id: str
    cron: str  # 標準 5 欄 crontab: 分 時 日 月 週 (依 server.timezone 設定解讀)
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


def get_user_tz() -> ZoneInfo:
    """回傳使用者設定的時區 (ZoneInfo 物件)。"""
    return ZoneInfo(settings.server.timezone)


def save_schedules(schedules: List[ScheduleConfig]):
    """
    將排程設定寫回 config.yaml。
    採用局部更新策略：保留 devices 與 server 區段的原樣（含註解），僅替換 schedules 區段。
    使用原子性寫入策略 (寫入暫存檔後更名) 以確保安全。
    """
    import os
    import time

    config_path = Path(__file__).parent / "config.yaml"
    if not config_path.exists():
        config_path = Path("config.yaml")

    # 讀取原本的檔案內容
    lines = []
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

    # 尋找 schedules: 開始的位置
    schedules_start_idx = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("schedules:"):
            schedules_start_idx = i
            break

    # 準備新的 schedules 資料
    new_data = [s.model_dump(exclude_none=True) for s in schedules]
    # 這裡使用 yaml.dump 生成字串，縮排設為 2 
    new_yaml_str = yaml.dump({"schedules": new_data}, allow_unicode=True, sort_keys=False, indent=2)

    # 組合新內容
    final_content = ""
    if schedules_start_idx != -1:
        # 保留 schedules: 之前的內容
        final_content = "".join(lines[:schedules_start_idx])
        final_content += new_yaml_str
    else:
        # 如果原本沒有 schedules 區塊，則直接附加
        final_content = "".join(lines)
        if final_content and not final_content.endswith("\n"):
            final_content += "\n"
        final_content += "\n" + new_yaml_str

    # 原子性寫入：先寫入暫存檔，sync 後再更名
    tmp_path = config_path.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(final_content)
            f.flush()
            os.fsync(f.fileno())  # 強制寫入磁碟實體層
        
        # 更名 (在 Linux 上為原子性操作)
        os.replace(tmp_path, config_path)
        
        # 給予一點安全容許時間讓作業系統或後端處理程序穩定 (回應使用者需求)
        time.sleep(0.5)
        
    except Exception as e:
        if tmp_path.exists():
            os.remove(tmp_path)
        raise e
