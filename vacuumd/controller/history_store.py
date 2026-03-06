import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vacuumd.model.cleaning_history import RunEvent, RunRecord

logger = logging.getLogger(__name__)


class HistoryStore:
    def __init__(self, storage_path: Optional[Path] = None):
        project_root = Path(__file__).resolve().parents[2]
        self.storage_path = storage_path or (project_root / "data" / "cleaning_history.jsonl")
        self._lock = threading.Lock()
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.storage_path.exists():
            self.storage_path.write_text("", encoding="utf-8")

    def _parse_utc(self, dt_str: Optional[str]) -> Optional[datetime]:
        if not dt_str:
            return None
        value = dt_str.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _load_all_records(self) -> List[Dict[str, Any]]:
        self._ensure_storage()
        records: List[Dict[str, Any]] = []
        with open(self.storage_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("歷史檔案第 %s 行 JSON 解析失敗，已略過", line_no)
                    continue
                if not isinstance(obj, dict) or "record_type" not in obj:
                    continue
                records.append(obj)
        return records

    def _atomic_write_records(self, records: List[Dict[str, Any]]) -> None:
        self._ensure_storage()
        tmp_path = self.storage_path.with_suffix(".tmp")
        content = "\n".join(json.dumps(item, ensure_ascii=False) for item in records)
        if content:
            content += "\n"

        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, self.storage_path)

    def _append(self, record_type: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            records = self._load_all_records()
            records.append({"record_type": record_type, "payload": payload})
            self._atomic_write_records(records)

    def append_event(self, event: RunEvent) -> None:
        self._append("event", event.model_dump(mode="json"))

    def append_run_record(self, record: RunRecord) -> None:
        self._append("run", record.model_dump(mode="json"))

    def close_open_runs_as_unknown_end(self) -> int:
        """
        在服務啟動時補記「可能因重啟遺失結束事件」的 run。
        規則：有 started 事件、但無 completed/failed/skipped/incomplete/unknown_end 事件，且無 run 記錄。
        """
        with self._lock:
            records = self._load_all_records()

            latest_event_by_run: Dict[str, Dict[str, Any]] = {}
            has_run_record: Dict[str, bool] = {}

            for item in records:
                record_type = item.get("record_type")
                payload = item.get("payload", {})
                run_id = payload.get("run_id")
                if not run_id:
                    continue

                if record_type == "event":
                    latest_event_by_run[run_id] = payload
                elif record_type == "run":
                    has_run_record[run_id] = True

            now = datetime.now(timezone.utc).isoformat()
            added = 0

            for run_id, event in latest_event_by_run.items():
                event_type = event.get("event_type")
                if event_type != "started":
                    continue
                if has_run_record.get(run_id):
                    continue

                task_id = event.get("task_id", "unknown_task")
                device_id = event.get("device_id", "unknown_device")
                zones = event.get("zones") or []

                # 寫入 unknown_end 事件
                records.append(
                    {
                        "record_type": "event",
                        "payload": {
                            "run_id": run_id,
                            "task_id": task_id,
                            "device_id": device_id,
                            "zones": zones,
                            "event_type": "unknown_end",
                            "ts_utc": now,
                            "reason": "服務重啟後無法判定實際結束時間，已標記 unknown_end",
                        },
                    }
                )

                # 同步寫入最低資訊 run 記錄，避免統計與列表遺失
                started_at = event.get("ts_utc") or now
                records.append(
                    {
                        "record_type": "run",
                        "payload": {
                            "run_id": run_id,
                            "task_id": task_id,
                            "device_id": device_id,
                            "zones": zones,
                            "started_at_utc": started_at,
                            "ended_at_utc": now,
                            "duration_sec": 0,
                            "area_delta_m2": 0.0,
                            "battery_delta_pct": 0,
                            "status": "unknown_end",
                            "is_estimated": len(zones) > 1,
                            "meta": {
                                "reason": "service_restart_unknown_end",
                            },
                        },
                    }
                )
                added += 1

            if added > 0:
                self._atomic_write_records(records)
            return added

    def list_runs(
        self,
        device_id: Optional[str] = None,
        task_id: Optional[str] = None,
        limit: int = 100,
        from_ts_utc: Optional[str] = None,
        to_ts_utc: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        from_dt = self._parse_utc(from_ts_utc)
        to_dt = self._parse_utc(to_ts_utc)

        with self._lock:
            records = self._load_all_records()

        runs: List[Dict[str, Any]] = []
        for item in records:
            if item.get("record_type") != "run":
                continue
            payload = item.get("payload", {})
            if device_id and payload.get("device_id") != device_id:
                continue
            if task_id and payload.get("task_id") != task_id:
                continue

            started_str = payload.get("started_at_utc")
            started_dt = self._parse_utc(started_str)
            if started_dt is None:
                continue

            if from_dt and started_dt < from_dt:
                continue
            if to_dt and started_dt > to_dt:
                continue

            runs.append(payload)

        runs.sort(key=lambda x: x.get("started_at_utc", ""), reverse=True)
        return runs[: max(1, limit)]

    def aggregate_stats(
        self,
        device_id: Optional[str] = None,
        task_id: Optional[str] = None,
        from_ts_utc: Optional[str] = None,
        to_ts_utc: Optional[str] = None,
    ) -> Dict[str, Any]:
        runs = self.list_runs(
            device_id=device_id,
            task_id=task_id,
            limit=1000000,
            from_ts_utc=from_ts_utc,
            to_ts_utc=to_ts_utc,
        )

        completed = [r for r in runs if r.get("status") == "completed"]

        total_runs = len(completed)
        total_area = round(sum(float(r.get("area_delta_m2", 0.0)) for r in completed), 3)
        total_duration = int(sum(int(r.get("duration_sec", 0)) for r in completed))
        total_battery = int(sum(int(r.get("battery_delta_pct", 0)) for r in completed))

        zone_breakdown: Dict[str, Dict[str, Any]] = {}
        for run in completed:
            zones = run.get("zones") or []
            duration = int(run.get("duration_sec", 0))
            battery = int(run.get("battery_delta_pct", 0))
            area = float(run.get("area_delta_m2", 0.0))

            zone_keys = [str(z) for z in zones] if zones else ["whole_home"]
            share = max(1, len(zone_keys))
            is_estimated = share > 1

            for key in zone_keys:
                if key not in zone_breakdown:
                    zone_breakdown[key] = {
                        "total_duration_sec": 0,
                        "total_battery_used_pct": 0,
                        "total_area_m2": 0.0,
                        "run_count": 0,
                        "is_estimated": False,
                    }
                zone_breakdown[key]["total_duration_sec"] += int(duration / share)
                zone_breakdown[key]["total_battery_used_pct"] += int(battery / share)
                zone_breakdown[key]["total_area_m2"] += area / share
                zone_breakdown[key]["run_count"] += 1
                zone_breakdown[key]["is_estimated"] = (
                    zone_breakdown[key]["is_estimated"] or is_estimated
                )

        for z in zone_breakdown.values():
            z["total_area_m2"] = round(float(z["total_area_m2"]), 3)

        return {
            "total_runs": total_runs,
            "total_area_m2": total_area,
            "total_duration_sec": total_duration,
            "avg_area_m2_per_run": round(total_area / total_runs, 3) if total_runs else 0.0,
            "avg_duration_sec_per_run": int(total_duration / total_runs) if total_runs else 0,
            "total_battery_used_pct": total_battery,
            "zone_breakdown": zone_breakdown,
        }


history_store = HistoryStore()
