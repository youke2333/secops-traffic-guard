"""威胁事件（疑似攻击流量明细）落库与查询辅助。"""

from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, select

from ..collector.direction import detect_direction
from ..config import Settings, get_settings
from ..database import session_scope
from ..detection.engine import Anomaly
from ..models import ThreatEvent, ThreatTag, utcnow

logger = logging.getLogger(__name__)

_COUNTER_LOCK = threading.Lock()
_COUNTER = {"minute": 0, "count": 0}


def _truncate(text: str, limit: int) -> str:
    raw = str(text or "")
    data = raw.encode("utf-8", errors="ignore")
    if len(data) <= limit:
        return raw
    return data[:limit].decode("utf-8", errors="ignore") + "\n…[已截断]"


def mask_snapshot(text: str) -> str:
    """脱敏 Cookie / Authorization / password 字段（默认开启）。"""
    value = str(text or "")
    value = re.sub(r"(?i)(cookie:\s*)([^\r\n]+)", r"\1[已脱敏]", value)
    value = re.sub(r"(?i)(authorization:\s*)([^\r\n]+)", r"\1[已脱敏]", value)
    value = re.sub(r"(?i)(password|passwd|pwd|token)=([^&\s;]+)", r"\1=[已脱敏]", value)
    return value


def _allow_store(settings: Settings) -> bool:
    limit = int(getattr(settings, "threat_rate_limit_per_min", 0) or 0)
    if limit <= 0:
        return True
    minute = int(time.time() // 60)
    with _COUNTER_LOCK:
        if _COUNTER["minute"] != minute:
            _COUNTER["minute"] = minute
            _COUNTER["count"] = 0
        if _COUNTER["count"] >= limit:
            return False
        _COUNTER["count"] += 1
        return True


def _request_info(evidence: Dict[str, Any], anomaly: Anomaly) -> Dict[str, Any]:
    request = evidence.get("request") if isinstance(evidence, dict) else None
    request = request if isinstance(request, dict) else {}
    method = str(request.get("method") or "")
    path = str(request.get("path") or "")
    query = str(request.get("query") or "")
    head = str(request.get("head") or "")
    body = str(request.get("body") or "")
    if not head and method:
        head = f"{method} {path}{('?' + query) if query else ''} HTTP/1.1"
    return {
        "method": method,
        "path": path,
        "query": query,
        "head": head,
        "body": body,
        "host": str(request.get("host") or ""),
        "status": int(request.get("status") or 0),
        "src_port": int(request.get("src_port") or 0),
        "source": str(request.get("source") or ""),
        "level": str(request.get("capture_level") or ("L1" if body else "L0")),
        "iface": str(request.get("iface") or ""),
    }


def _pack_of(rule_source: str) -> str:
    source = str(rule_source or "").lower()
    if "intrusion" in source:
        return "intrusion"
    if "sigma" in source:
        return "sigma"
    if source in {"et", "suricata"} or "et-" in source:
        return "et"
    if "custom" in source:
        return "custom"
    if "mixed" in source:
        return "mixed"
    return "builtin"


def build_tags(anomaly: Anomaly, evidence: Dict[str, Any]) -> List[str]:
    tags: List[str] = []
    name = str(evidence.get("category_name") or "").strip()
    if name:
        tags.append(name)
    if evidence.get("combination_attack"):
        tags.append("组合攻击")
    if anomaly.direct_alert or evidence.get("direct_alert"):
        tags.append("高危直达")
    tier = str(evidence.get("tier") or "")
    if tier:
        tags.append(tier)
    source = str(anomaly.rule_source or evidence.get("rule_source") or "")
    pack = _pack_of(source)
    if pack not in {"builtin", "mixed"}:
        tags.append(pack)
    return list(dict.fromkeys(tag for tag in tags if tag))


def save_threat_event(anomaly: Anomaly, *, alert_id: Optional[int] = None,
                      settings: Optional[Settings] = None,
                      triage: Optional[Dict[str, Any]] = None) -> Optional[int]:
    """把一次命中落库为威胁事件；返回事件 ID（关闭/超限/失败时返回 None）。"""
    cfg = settings or get_settings()
    if not cfg.threat_store_enabled or not _allow_store(cfg):
        return None
    evidence = dict(anomaly.evidence or {})
    request = _request_info(evidence, anomaly)
    for key in ("head", "body", "query"):
        if cfg.threat_mask_secrets:
            request[key] = mask_snapshot(request[key])
    request["head"] = _truncate(request["head"], int(cfg.threat_request_max_bytes))
    request["body"] = _truncate(request["body"], int(cfg.threat_request_max_bytes))
    response = evidence.get("response") if isinstance(evidence.get("response"), dict) else {}
    response_head = _truncate(str(response.get("head") or ""), int(cfg.threat_response_max_bytes))
    response_body = _truncate(str(response.get("body") or ""), int(cfg.threat_response_max_bytes))
    direction = detect_direction(anomaly.source_ip, anomaly.dest_ip, cfg.protected_cidrs)
    tags = build_tags(anomaly, evidence)
    triage = triage or {}

    try:
        with session_scope() as session:
            row = ThreatEvent(
                ts=utcnow(), alert_id=alert_id,
                source_ip=anomaly.source_ip or "", dest_ip=anomaly.dest_ip or "",
                source_port=int(request["src_port"] or 0),
                dest_port=int(anomaly.dest_port or 0), protocol=anomaly.protocol or "TCP",
                direction=direction, category=anomaly.category or "",
                severity=anomaly.severity or "medium", confidence=anomaly.confidence or "medium",
                rule_id=anomaly.rule_id or "", rule_pack=_pack_of(str(anomaly.rule_source or "")),
                tier=str(evidence.get("tier") or ""),
                triage_verdict=str(triage.get("verdict") or ""),
                triage_rule_id=str(triage.get("rule_id") or ""),
                triage_reason=str(triage.get("reason") or ""),
                score_delta=float(triage.get("score_delta") or 0.0),
                status_code=int(request["status"] or 0), method=request["method"],
                host=request["host"], path=request["path"], query=request["query"],
                request_head=request["head"], request_body=request["body"],
                response_head=response_head, response_body=response_body,
                request_bytes=len(request["head"].encode("utf-8")) + len(request["body"].encode("utf-8")),
                response_bytes=len(response_head.encode("utf-8")) + len(response_body.encode("utf-8")),
                capture_source=request["source"], capture_level=request["level"] or "L0",
                iface=request["iface"], message=anomaly.message or "",
                evidence=evidence,
            )
            session.add(row)
            session.flush()
            event_id = row.id
            for tag in tags:
                session.add(ThreatTag(event_id=event_id, tag=tag))
            return event_id
    except Exception:
        logger.exception("威胁事件落库失败：%s %s", anomaly.category, anomaly.source_ip)
        return None


def list_tags(event_ids: List[int]) -> Dict[int, List[str]]:
    if not event_ids:
        return {}
    with session_scope() as session:
        rows = session.scalars(select(ThreatTag).where(ThreatTag.event_id.in_(event_ids))).all()
    result: Dict[int, List[str]] = {}
    for row in rows:
        result.setdefault(int(row.event_id), []).append(str(row.tag))
    return result


def purge_old_events(settings: Optional[Settings] = None) -> int:
    """按留存天数清理威胁事件与孤儿标签（每小时调用一次即可）。"""
    cfg = settings or get_settings()
    cutoff = utcnow() - timedelta(days=int(cfg.threat_retention_days))
    with session_scope() as session:
        ids = session.scalars(select(ThreatEvent.id).where(ThreatEvent.ts < cutoff)).all()
        if not ids:
            return 0
        for start in range(0, len(ids), 5000):
            chunk = list(ids[start:start + 5000])
            session.execute(delete(ThreatTag).where(ThreatTag.event_id.in_(chunk)))
            session.execute(delete(ThreatEvent).where(ThreatEvent.id.in_(chunk)))
        return len(ids)

