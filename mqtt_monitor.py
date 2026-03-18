#!/usr/bin/env python3
"""
Simple MQTT monitor for myxiaomi/esp-miao integration.

Usage:
  uv run python mqtt_monitor.py --topic home/discovery
  uv run python mqtt_monitor.py --topic home/vacuum_01/cmd

Defaults to environment variables from .env:
  MQTT_HOST, MQTT_PORT, MQTT_AUTH_USER, MQTT_AUTH_PASSWORD, MQTT_TLS, MQTT_KEEPALIVE
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone


try:
    import paho.mqtt.client as mqtt
except ImportError as exc:
    print("Missing dependency: paho-mqtt. Please add it to pyproject.toml and install.")
    raise


def _env_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _load_env_file(path: str) -> None:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key, value)


def _format_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> int:
    parser = argparse.ArgumentParser(description="MQTT monitor tool")
    parser.add_argument("--topic", default="home/discovery", help="Topic to subscribe")
    parser.add_argument("--env", default=".env", help="Env file path (default: .env)")
    args = parser.parse_args()

    _load_env_file(args.env)

    host = os.getenv("MQTT_HOST", "127.0.0.1")
    port = int(os.getenv("MQTT_PORT", "1883"))
    username = os.getenv("MQTT_AUTH_USER", "")
    password = os.getenv("MQTT_AUTH_PASSWORD", "")
    use_tls = _env_bool(os.getenv("MQTT_TLS", "false"))
    keepalive = int(os.getenv("MQTT_KEEPALIVE", "60"))

    client = mqtt.Client()
    if username or password:
        client.username_pw_set(username, password)
    if use_tls:
        client.tls_set()

    def on_connect(_client, _userdata, _flags, rc):
        if rc != 0:
            print(f"[{_format_ts()}] connect failed rc={rc}")
            return
        print(f"[{_format_ts()}] connected to {host}:{port}, subscribing {args.topic}")
        _client.subscribe(args.topic)

    def on_message(_client, _userdata, msg):
        payload = msg.payload.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(payload)
            payload = json.dumps(parsed, ensure_ascii=False, indent=2)
        except json.JSONDecodeError:
            pass
        print(f"[{_format_ts()}] topic={msg.topic}\n{payload}\n")

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(host, port, keepalive)
    except Exception as exc:
        print(f"[{_format_ts()}] connect error: {exc}")
        return 1

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print(f"[{_format_ts()}] shutdown")
    return 0


if __name__ == "__main__":
    sys.exit(main())
