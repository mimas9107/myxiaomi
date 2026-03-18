import json
import logging
import os
import threading
from typing import Any, Dict, Optional, Tuple

import paho.mqtt.client as mqtt

from vacuumd.controller.manager import manager
from vacuumd.scheduler.engine import automation

logger = logging.getLogger(__name__)

DISCOVERY_TOPIC = "home/discovery"
CONTROL_TOPIC = "home/vacuum_01/cmd"
STATUS_TOPIC = "home/vacuum_01/status"


def _env_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


class MqttBridge:
    """MQTT Bridge：接收控制指令並發布 Discovery / 狀態回應。"""

    def __init__(self) -> None:
        self._client: Optional[mqtt.Client] = None
        self._lock = threading.Lock()
        self._connected = False

    def connect(self) -> bool:
        """建立 MQTT 連線。失敗時回傳 False，並且不中斷主流程。"""
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

        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect

        try:
            client.connect(host, port, keepalive)
        except Exception as exc:
            logger.warning("MQTT 連線失敗：%s", exc)
            return False

        client.loop_start()
        self._client = client
        logger.info("MQTT 連線初始化完成：%s:%s (TLS=%s)", host, port, use_tls)
        return True

    def disconnect(self) -> None:
        """安全關閉 MQTT 連線。"""
        if not self._client:
            return
        try:
            self._client.loop_stop()
            self._client.disconnect()
        except Exception as exc:
            logger.warning("MQTT 斷線時發生錯誤：%s", exc)
        finally:
            self._client = None
            self._connected = False

    def publish_discovery(self) -> None:
        """發布 Discovery Payload。"""
        payload = {
            "device_id": "vacuum_01",
            "device_type": "vacuum",
            "aliases": ["小貓", "掃地機", "吸塵器"],
            "control_topic": CONTROL_TOPIC,
            "commands": {"on": "START", "off": "DOCK"},
            "action_keywords": {
                "on": ["掃地", "清掃", "開始工作", "啟動"],
                "off": ["回充", "回家", "休息", "停止"],
            },
        }
        self._publish(DISCOVERY_TOPIC, payload, retain=True)

    def publish_status(self, status: str, message: str) -> None:
        """發布狀態回應（供 esp-miao 顯示）。"""
        payload = {"status": status, "message": message}
        self._publish(STATUS_TOPIC, payload, retain=False)

    def _publish(self, topic: str, payload: Dict[str, Any], retain: bool) -> None:
        client = self._client
        if not client:
            return
        try:
            client.publish(
                topic,
                json.dumps(payload, ensure_ascii=False),
                qos=0,
                retain=retain,
            )
        except Exception as exc:
            logger.warning("MQTT 發布失敗：topic=%s error=%s", topic, exc)

    def _on_connect(self, client: mqtt.Client, _userdata, _flags, rc: int) -> None:
        if rc != 0:
            logger.warning("MQTT 連線失敗：rc=%s", rc)
            self._connected = False
            return
        with self._lock:
            self._connected = True
            client.subscribe(CONTROL_TOPIC)
        logger.info("MQTT 已連線並訂閱：%s", CONTROL_TOPIC)

    def _on_disconnect(self, _client: mqtt.Client, _userdata, _rc: int) -> None:
        self._connected = False
        logger.warning("MQTT 已斷線")

    def _on_message(self, _client: mqtt.Client, _userdata, msg: mqtt.MQTTMessage) -> None:
        try:
            payload = msg.payload.decode("utf-8", errors="replace").strip()
        except Exception:
            payload = ""

        command = payload.upper()
        if command not in ("START", "DOCK"):
            self.publish_status("error", f"未知指令：{payload}")
            return

        if command == "START":
            ok, message = self._handle_start()
            self.publish_status("ok" if ok else "error", message)
            return

        ok, message = self._handle_dock()
        self.publish_status("ok" if ok else "error", message)

    def _handle_start(self) -> Tuple[bool, str]:
        try:
            controller = manager.get_device("robot_s5")
        except Exception:
            return False, "找不到內部設備設定"

        try:
            status = controller.status()
        except Exception as exc:
            return False, f"讀取狀態失敗：{exc}"

        ok, reason = automation.try_start_voice_run(
            device_id="robot_s5",
            status_state=status.state,
            battery=status.battery,
            cleaned_area=float(status.cleaned_area),
            cleaning_since=str(status.cleaning_since),
        )
        if not ok:
            return False, reason

        try:
            controller.start()
        except Exception as exc:
            automation.rollback_voice_run(device_id="robot_s5")
            return False, f"啟動失敗：{exc}"

        return True, "啟動成功"

    def _handle_dock(self) -> Tuple[bool, str]:
        try:
            controller = manager.get_device("robot_s5")
        except Exception:
            return False, "找不到內部設備設定"

        try:
            controller.home()
        except Exception as exc:
            return False, f"回充失敗：{exc}"

        automation.finish_voice_run(device_id="robot_s5")
        return True, "回充成功"
