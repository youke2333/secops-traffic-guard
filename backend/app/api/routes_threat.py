"""威胁告警接口：列表、详情、分面、统计、CSV 导出与一键封禁（v6 P1）。"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select

from ..auth import audit
from ..database import session_scope
from ..models import Alert, BlockRule, ThreatEvent, ThreatTag, utcnow
from ..schemas import ActionResult
from ..threat.store import list_tags
from ..timeutil import hour_bucket, iso_local, parse_local_input
from .deps import blocker_dep, require_role, require_token, service_dep

router = APIRouter(tags=["threats"])

SORT_FIELDS = {
    "ts": ThreatEvent.ts,
    "severity": ThreatEvent.severity,
    "source_ip": ThreatEvent.source_ip,
    "dest_ip": ThreatEvent.dest_ip,
    "category": ThreatEvent.category,
    "rule_id": ThreatEvent.rule_id,
}


def _parse_time(value: str, default: Optional[datetime] = None) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return default
    try:
        # 前端筛选框填的是本地时间，库里的 ts 是 UTC，这里换算后再比较
        return parse_local_input(text)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"非法时间格式：{value}")


def _tag_ids(tags: Iterable[str]):
    names = [str(item).strip() for item in tags if str(item).strip()]
    if not names:
        return None
    return (
        select(ThreatTag.event_id)
        .where(ThreatTag.tag.in_(names))
        .group_by(ThreatTag.event_id)
        .having(func.count(func.distinct(ThreatTag.tag)) == len(set(names)))
    )


def _conditions(*, start: str = "", end: str = "", src_ip: str = "", dst_ip: str = "",
                severity: str = "", direction: str = "", category: str = "",
                rule_id: str = "", rule_pack: str = "", tier: str = "",
                verdict: str = "", status: str = "", q: str = "",
                tags: Optional[List[str]] = None) -> List[Any]:
    clauses: List[Any] = []
    start_at = _parse_time(start)
    end_at = _parse_time(end)
    if start_at:
        clauses.append(ThreatEvent.ts >= start_at)
    if end_at:
        clauses.append(ThreatEvent.ts <= end_at)
    if src_ip:
        clauses.append(ThreatEvent.source_ip == src_ip)
    if dst_ip:
        clauses.append(ThreatEvent.dest_ip == dst_ip)
    if severity:
        clauses.append(ThreatEvent.severity.in_([item.strip() for item in severity.split(",") if item.strip()]))
    if direction:
        clauses.append(ThreatEvent.direction == direction)
    if category:
        clauses.append(ThreatEvent.category.in_([item.strip() for item in category.split(",") if item.strip()]))
    if rule_id:
        clauses.append(ThreatEvent.rule_id == rule_id)
    if rule_pack:
        clauses.append(ThreatEvent.rule_pack == rule_pack)
    if tier:
        clauses.append(ThreatEvent.tier == tier)
    if verdict:
        clauses.append(ThreatEvent.triage_verdict == verdict)
    if status == "alerted":
        clauses.append(ThreatEvent.alert_id.is_not(None))
    elif status == "unalerted":
        clauses.append(ThreatEvent.alert_id.is_(None))
    elif status == "blocked":
        blocked_ips = select(BlockRule.ip).where(BlockRule.active.is_(True))
        clauses.append(ThreatEvent.source_ip.in_(blocked_ips))
    if q:
        like = f"%{q}%"
        clauses.append(or_(
            ThreatEvent.message.ilike(like), ThreatEvent.path.ilike(like),
            ThreatEvent.query.ilike(like), ThreatEvent.rule_id.ilike(like),
            ThreatEvent.source_ip.ilike(like),
        ))
    tag_ids = _tag_ids(tags or [])
    if tag_ids is not None:
        clauses.append(ThreatEvent.id.in_(tag_ids))
    return clauses


def _serialize(row: ThreatEvent, tags: Optional[List[str]] = None) -> Dict[str, Any]:
    return {
        "id": row.id,
        "ts": iso_local(row.ts),          # 库里是 UTC，输出本地时间，避免比大屏时钟早 8 小时
        "alert_id": row.alert_id,
        "source_ip": row.source_ip,
        "source_port": row.source_port,
        "dest_ip": row.dest_ip,
        "dest_port": row.dest_port,
        "protocol": row.protocol,
        "direction": row.direction,
        "category": row.category,
        "severity": row.severity,
        "confidence": row.confidence,
        "rule_id": row.rule_id,
        "rule_pack": row.rule_pack,
        "tier": row.tier,
        "triage_verdict": row.triage_verdict,
        "triage_rule_id": row.triage_rule_id,
        "triage_reason": row.triage_reason,
        "score_delta": row.score_delta,
        "status_code": row.status_code,
        "method": row.method,
        "host": row.host,
        "path": row.path,
        "query": row.query,
        "request_bytes": row.request_bytes,
        "response_bytes": row.response_bytes,
        "capture_source": row.capture_source,
        "capture_level": row.capture_level,
        "iface": row.iface,
        "message": row.message,
        "tags": tags or [],
    }


@router.get("/threats", summary="威胁事件列表（支持标签/方向/档位/研判/关键词筛选）")
def list_threats(
        start: str = Query(default=""), end: str = Query(default=""),
        src_ip: str = Query(default=""), dst_ip: str = Query(default=""),
        severity: str = Query(default=""), direction: str = Query(default=""),
        category: str = Query(default=""), rule_id: str = Query(default=""),
        rule_pack: str = Query(default=""), tier: str = Query(default=""),
        verdict: str = Query(default=""), status: str = Query(default=""),
        q: str = Query(default=""), tag: List[str] = Query(default=[]),
        page: int = Query(default=1, ge=1), page_size: int = Query(default=50, ge=1, le=200),
        sort: str = Query(default="ts"), order: str = Query(default="desc")) -> Dict[str, Any]:
    clauses = _conditions(start=start, end=end, src_ip=src_ip, dst_ip=dst_ip,
                          severity=severity, direction=direction, category=category,
                          rule_id=rule_id, rule_pack=rule_pack, tier=tier,
                          verdict=verdict, status=status, q=q, tags=tag)
    column = SORT_FIELDS.get(sort, ThreatEvent.ts)
    ordering = column.desc() if str(order).lower() != "asc" else column.asc()
    with session_scope() as session:
        total = int(session.scalar(select(func.count(ThreatEvent.id)).where(*clauses)) or 0)
        rows = session.scalars(
            select(ThreatEvent).where(*clauses).order_by(ordering)
            .offset((page - 1) * page_size).limit(page_size)
        ).all()
        tags = list_tags([int(row.id) for row in rows])
    return {
        "total": total, "page": page, "page_size": page_size,
        "items": [_serialize(row, tags.get(int(row.id), [])) for row in rows],
    }


@router.get("/threats/facets", summary="威胁事件分面计数（标签/严重度/方向/类别/规则包/档位）")
def threat_facets(start: str = Query(default=""), end: str = Query(default="")) -> Dict[str, Any]:
    clauses = _conditions(start=start, end=end)
    with session_scope() as session:
        def counts(column) -> Dict[str, int]:
            rows = session.execute(
                select(column, func.count(ThreatEvent.id)).where(*clauses).group_by(column)
                .order_by(func.count(ThreatEvent.id).desc())
            ).all()
            return {str(key or "unknown"): int(value) for key, value in rows}
        tag_rows = session.execute(
            select(ThreatTag.tag, func.count(ThreatTag.event_id))
            .join(ThreatEvent, ThreatEvent.id == ThreatTag.event_id)
            .where(*clauses).group_by(ThreatTag.tag)
            .order_by(func.count(ThreatTag.event_id).desc()).limit(60)
        ).all()
    return {
        "severity": counts(ThreatEvent.severity),
        "direction": counts(ThreatEvent.direction),
        "category": counts(ThreatEvent.category),
        "rule_pack": counts(ThreatEvent.rule_pack),
        "tier": counts(ThreatEvent.tier),
        "verdict": counts(ThreatEvent.triage_verdict),
        "tags": {str(key): int(value) for key, value in tag_rows},
    }


@router.get("/threats/stats", summary="威胁事件趋势与处置统计")
def threat_stats(hours: int = Query(default=24, ge=1, le=168)) -> Dict[str, Any]:
    since = utcnow() - timedelta(hours=hours)
    with session_scope() as session:
        rows = session.execute(
            select(ThreatEvent.ts, ThreatEvent.severity, ThreatEvent.category)
            .where(ThreatEvent.ts >= since).order_by(ThreatEvent.ts)
        ).all()
        alerted = int(session.scalar(select(func.count(ThreatEvent.id))
                                     .where(ThreatEvent.ts >= since, ThreatEvent.alert_id.is_not(None))) or 0)
    buckets: Dict[str, Dict[str, int]] = {}
    for ts, severity, category in rows:
        # 分桶标签按本地时间，否则趋势图 X 轴会整体偏 8 小时、跨天事件落到前一天
        key = hour_bucket(ts)
        bucket = buckets.setdefault(key, {"total": 0, "alerts": 0, "critical": 0, "high": 0})
        bucket["total"] += 1
        if severity in {"critical", "high"}:
            bucket[severity] += 1
    return {
        "hours": hours, "total": len(rows), "alerted": alerted,
        "trend": [{"bucket": key, **value} for key, value in sorted(buckets.items())],
    }



@router.get("/threats/export", summary="按当前筛选条件导出 CSV（流式，UTF-8 BOM）")
def export_threats(
        start: str = Query(default=""), end: str = Query(default=""),
        src_ip: str = Query(default=""), dst_ip: str = Query(default=""),
        severity: str = Query(default=""), direction: str = Query(default=""),
        category: str = Query(default=""), rule_id: str = Query(default=""),
        rule_pack: str = Query(default=""), tier: str = Query(default=""),
        verdict: str = Query(default=""), status: str = Query(default=""),
        q: str = Query(default=""), tag: List[str] = Query(default=[]),
        principal: dict = Depends(require_role("analyst", "admin")),
        service=Depends(service_dep)) -> StreamingResponse:
    settings = service.settings
    clauses = _conditions(start=start, end=end, src_ip=src_ip, dst_ip=dst_ip,
                          severity=severity, direction=direction, category=category,
                          rule_id=rule_id, rule_pack=rule_pack, tier=tier,
                          verdict=verdict, status=status, q=q, tags=tag)
    limit = int(settings.threat_export_max_rows)
    headers = ["时间", "源IP", "目的IP", "目的端口", "方向", "类别", "严重度", "置信度",
               "规则ID", "规则包", "档位", "研判", "HTTP方法", "路径", "状态码",
               "采集来源", "保真度", "告警ID", "标签"]

    def generate():
        yield "\ufeff"
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(headers)
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)
        with session_scope() as session:
            rows = session.scalars(
                select(ThreatEvent).where(*clauses).order_by(ThreatEvent.ts.desc()).limit(limit)
            ).all()
            tags = list_tags([int(row.id) for row in rows])
        for row in rows:
            writer.writerow([
                iso_local(row.ts) or "", row.source_ip, row.dest_ip,
                row.dest_port, row.direction, row.category, row.severity, row.confidence,
                row.rule_id, row.rule_pack, row.tier, row.triage_verdict, row.method,
                row.path, row.status_code, row.capture_source, row.capture_level,
                row.alert_id or "", ",".join(tags.get(int(row.id), [])),
            ])
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    filename = f"threats-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(generate(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/threats/{event_id}", summary="威胁事件详情（请求/响应快照、规则、标签、关联告警）")
def get_threat(event_id: int) -> Dict[str, Any]:
    with session_scope() as session:
        row = session.get(ThreatEvent, event_id)
        if row is None:
            raise HTTPException(status_code=404, detail="威胁事件不存在或已过留存期")
        alert = session.get(Alert, row.alert_id) if row.alert_id else None
        tags = list_tags([event_id]).get(event_id, [])
        result = _serialize(row, tags)
        result.update({
            "request_head": row.request_head, "request_body": row.request_body,
            "response_head": row.response_head, "response_body": row.response_body,
            "evidence": row.evidence or {},
            "alert": {
                "id": alert.id, "ts": iso_local(alert.ts, stored="local") if alert.ts else None,
                "risk_score": alert.risk_score, "status": alert.status,
                "blocked": bool(alert.blocked), "message": alert.message,
            } if alert else None,
        })
    return result


@router.post("/threats/{event_id}/block", response_model=ActionResult,
             summary="一键封禁威胁事件源 IP")
def block_threat(event_id: int, ttl_sec: int = Query(default=1800, ge=60, le=86400),
                 principal: dict = Depends(require_token),
                 blocker=Depends(blocker_dep)) -> ActionResult:
    with session_scope() as session:
        row = session.get(ThreatEvent, event_id)
        if row is None:
            raise HTTPException(status_code=404, detail="威胁事件不存在")
        ip, category, severity = row.source_ip, row.category, row.severity
    if not ip:
        raise HTTPException(status_code=400, detail="该事件没有源 IP，无法封禁")
    result = blocker.block(ip=ip, reason=f"[人工] 威胁事件 #{event_id}：{category}",
                           category=category, severity=severity, ttl_sec=ttl_sec,
                           source="manual", operator=str(principal.get("username") or "dashboard"))
    audit("block", username=str(principal.get("username") or ""), target=ip,
          detail=f"来源=威胁事件 #{event_id} ttl={ttl_sec}s")
    return ActionResult(success=bool(result.get("success")), message=str(result.get("message")),
                        code="ok" if result.get("success") else "firewall_failed", detail=result)

