import os
import yaml
from pathlib import Path
from pydantic import BaseModel
from typing import List


class DeviceConfig(BaseModel):
    id: str
    name: str
    ip: str
    token: str


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    cache_ttl: int = 5
    retry_count: int = 3


class Settings(BaseModel):
    devices: List[DeviceConfig]
    server: ServerConfig


def load_settings() -> Settings:
    config_path = Path(__file__).parent / "config.yaml"
    if not config_path.exists():
        # Fallback to current working directory if not found in package
        config_path = Path("config.yaml")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
        return Settings(**data)


# Singleton instance
settings = load_settings()
