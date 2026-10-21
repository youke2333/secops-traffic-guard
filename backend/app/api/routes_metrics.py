"""实时指标与总览接口（大屏数据源 + SSE 推送）。"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, AsyncGenerator, Dict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from ..bus import bus
from ..collector.service import CollectorService
from ..config import Settings, get_settings
from ..database import session_scope
from ..models import Alert, Asset, BlockRule, Vulnerability
from ..system_stats import snapshot as system_snapshot
from .deps import service_dep, settings_dep

router = APIRouter(tags=["metrics"])

# /stream/events 只转发这三类"事件"话题（metrics 由 /stream/metrics 单独推送）
EVENT_TOPICS = ("alert", "alert_enriched", "signal")


def sse_frame(event: str, payload: Any) -> str:
    """SSE 帧格式：event + data(json)。"""
    return f"event: {event}\ndata: {json.dumps(payload, ensure_ascii=False, default=str)}\n\n"


def _db_counters() -> Dict[str, int]:
    """关系库统计（告警/封禁/资产/漏洞），与大屏 KPI 卡片一一对应。"""
    with session_scope() as session:
        alerts_total = session.scalar(select(func.count(Alert.id))) or 0
        alerts_open = session.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
        blocked_total = session.scalar(select(func.count(BlockRule.id))) or 0
        blocked_active = session.scalar(
            select(func.count(BlockRule.id)).where(BlockRule.active.is_(True))
        ) or 0
        assets_total = session.scalar(select(func.count(Asset.id))) or 0
        vulns_open = session.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.status == "open")
        ) or 0
    return {
        "alerts_total": int(alerts_total),
        "alerts_open": int(alerts_open),
        "blocked_total": int(blocked_total),
        "blocked_active": int(blocked_active),
        "assets_total": int(assets_total),
        "vulns_open": int(vulns_open),
    }


@router.get("/health", summary="健康检查")
def health(service: CollectorService = Depends(service_dep),
           settings: Settings = Depends(settings_dep)) -> Dict[str, Any]:
    return {
        "status": "ok",
        "version": settings.app_version,
        "capture_mode": service.capture_mode,
        "firewall_backend": service.blocker.backend.name,
        "dry_run": settings.dry_run,
        "channels": [channel.name for channel in service.notifier.channels],
        "db": settings.db_url.split("://")[0],
    }


@router.get("/status", summary="运行状态（自检用）")
def status(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    return service.status()


@router.get("/overview", summary="大屏总览 KPI")
def overview(service: CollectorService = Depends(service_dep),
             settings: Settings = Depends(settings_dep)) -> Dict[str, Any]:
    counters = _db_counters()
    kpi = service.kpi()
    risk = min(100.0, counters["alerts_open"] * 2.0 + counters["blocked_active"] * 3.0
               + counters["vulns_open"] * 2.5)
    return {
        **kpi,
        **counters,
        "risk_score": round(risk, 1),
        "firewall_backend": service.blocker.backend.name,
        "dry_run": settings.dry_run,
        "capture_mode": service.capture_mode,
        "channels": [channel.name for channel in service.notifier.channels],
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/metrics/trend", summary="趋势数据（带宽/包速率/连接数）")
def metrics_trend(window_sec: int = Query(default=120, ge=5, le=3600),
                  service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    return service.trend_data(window_sec)


@router.get("/metrics/ports", summary="端口流量 TOP（含非标准端口标记）")
def metrics_ports(top: int = Query(default=12, ge=1, le=64),
                  service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    ports = service.port_stats(top)
    return {"total": len(ports), "items": ports}


@router.get("/metrics/ports/baseline", summary="端口基线视图（标准/非标准 + Z 值偏差）")
def metrics_port_baseline(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    items = service.port_baseline()
    return {
        "total": len(items),
        "items": items,
        "standard_ports": sorted(service.settings.standard_ports),
        "threshold": round(service.settings.zscore_threshold + 0.5, 2),
        "window_sec": service.port_window.window,
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/metrics/sessions", summary="实时 TOP 会话（流量监控页明细表）")
def metrics_sessions(top: int = Query(default=20, ge=1, le=200),
                     service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    items = service.top_sessions(top)
    return {"total": len(items), "items": items,
            "conn_table": len(service._conn_table),  # noqa: SLF001 - 仅用于展示会话表规模
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")}


@router.get("/metrics/portfolio", summary="大屏首屏聚合数据（一次拉全）")
def metrics_portfolio(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    payload = service.portfolio()
    payload["overview"] = overview(service, get_settings())
    return payload


@router.get("/system/resources", summary="硬件资源占用（CPU / 内存 / 磁盘 / 网卡）")
def system_resources(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    """硬件资源快照。网卡吞吐复用采集服务的实时快照，其余指标由 system_stats 采集。"""
    latest = service.latest_snapshot or {}
    rx_bps = float(latest.get("bps_in", 0) or 0)
    tx_bps = float(latest.get("bps_out", 0) or 0)
    capacity_mbps = float(getattr(service.settings, "link_speed_mbps", 0) or 0)
    capacity = max(1.0, capacity_mbps * 1_000_000)
    network = {
        "rx_bps": round(rx_bps, 2),
        "tx_bps": round(tx_bps, 2),
        "util": round(min(100.0, (rx_bps + tx_bps) / capacity * 100), 2),
        "capacity_mbps": capacity_mbps or None,
        "iface": latest.get("iface", ""),
    }
    return system_snapshot(network=network)


@router.get("/stream/metrics", summary="实时指标 SSE 流（毫秒级推送）")
async def stream_metrics(request: Request,
                         service: CollectorService = Depends(service_dep)) -> StreamingResponse:
    subscriber = bus.subscribe()

    async def generator() -> AsyncGenerator[str, None]:
        try:
            yield sse_frame("hello", {"ts": time.time(), "mode": service.capture_mode,
                                      "interval_ms": service.settings.tick_interval_ms,
                                      "subscriber": subscriber})
            if service.latest_snapshot:
                yield sse_frame("metrics", service.latest_snapshot)
            while True:
                if await request.is_disconnected():
                    break
                for event in bus.drain(subscriber, "metrics"):
                    yield sse_frame("metrics", event["data"])
                await asyncio.sleep(0.08)      # 80ms 轮询，保证大屏"毫秒级"观感
        finally:
            bus.unsubscribe(subscriber)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",   # nginx 下关闭缓冲，避免推送被攒批
        },
    )


@router.get("/stream/events", summary="告警事件 SSE 流（alert / alert_enriched / signal）")
async def stream_events(request: Request) -> StreamingResponse:
    """告警事件流。

    事件类型（v2 追加后）：
    * ``alert``            —— 新告警（含评分 / 直达标记 / 贡献规则）；
    * ``alert_enriched``   —— AI 研判完成（前端抽屉据此刷新，无需轮询）；
    * ``signal``           —— 被抑制或未达阈值的信号（聚合抑制可见，禁止静默丢弃）。
    """
    subscriber = bus.subscribe()

    async def generator() -> AsyncGenerator[str, None]:
        try:
            yield sse_frame("hello", {"ts": time.time(), "subscriber": subscriber,
                                      "topics": ["alert", "alert_enriched", "signal"]})
            while True:
                if await request.is_disconnected():
                    break
                while True:
                    events = bus.drain(subscriber)
                    if not events:
                        break
                    for event in events:
                        if event["topic"] not in EVENT_TOPICS:
                            continue      # metrics 等其它话题由各自的 SSE 流推送
                        yield sse_frame(str(event["topic"]), event["data"])
                await asyncio.sleep(0.1)
        finally:
            bus.unsubscribe(subscriber)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )

