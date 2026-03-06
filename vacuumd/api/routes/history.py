from typing import Optional

from fastapi import APIRouter, Query

from vacuumd.config.settings import settings
from vacuumd.controller.history_store import history_store

router = APIRouter()


@router.get("/runs")
async def list_history_runs(
    device_id: Optional[str] = None,
    task_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    from_utc: Optional[str] = Query(default=None, alias="from"),
    to_utc: Optional[str] = Query(default=None, alias="to"),
):
    """列出排程執行歷史紀錄。時間參數請使用 UTC ISO8601。"""
    runs = history_store.list_runs(
        device_id=device_id,
        task_id=task_id,
        limit=limit,
        from_ts_utc=from_utc,
        to_ts_utc=to_utc,
    )
    return {
        "timezone": settings.server.timezone,
        "count": len(runs),
        "runs": runs,
    }


@router.get("/stats")
async def get_history_stats(
    device_id: Optional[str] = None,
    task_id: Optional[str] = None,
    from_utc: Optional[str] = Query(default=None, alias="from"),
    to_utc: Optional[str] = Query(default=None, alias="to"),
):
    """回傳歷史清掃統計。時間參數請使用 UTC ISO8601。"""
    stats = history_store.aggregate_stats(
        device_id=device_id,
        task_id=task_id,
        from_ts_utc=from_utc,
        to_ts_utc=to_utc,
    )
    return {
        "timezone": settings.server.timezone,
        **stats,
    }
