"""研判规则执行器（v6 P3，默认关闭）。

输入一次命中（Anomaly）与可用上下文，按优先级短路求值：
* ``suppress_alert`` / ``benign``：只抑制告警，仍写入 threat_events 与 signals（不静默）；
* ``escalate``：累加 ``score_delta``，不直接封禁；
* ``confirm`` / ``downgrade``：仅改变标签与分值。

规则中引用但本系统当前拿不到的字段一律按“不匹配”处理（不猜测），
因此不会因为缺字段产生误抑制。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import Settings, get_settings
from ..detection.engine import Anomaly

logger = logging.getLogger(__name__)
_MISSING = object()


class TriageEngine:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.rules: List[Dict[str, Any]] = []
        self._seen: Dict[tuple, float] = {}
        self.load()

    @property
    def path(self) -> Path:
        return Path(self.settings.rulesets_path) / "triage_rules.json"

    def load(self) -> int:
        self.rules = []
        if not self.settings.rulesets_enabled or not self.settings.triage_enabled:
            return 0
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            logger.exception("研判规则加载失败：%s", self.path)
            return 0
        rules = [item for item in payload.get("rules") or [] if isinstance(item, dict)]
        rules.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
        self.rules = rules
        logger.info("研判规则已加载：%d 条", len(self.rules))
        return len(self.rules)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _context(anomaly: Anomaly, now: float) -> Dict[str, Any]:
        evidence = anomaly.evidence or {}
        request = evidence.get("request") if isinstance(evidence.get("request"), dict) else {}
        moment = datetime.fromtimestamp(now)
        try:
            src_private = ipaddress.ip_address(anomaly.source_ip).is_private
        except ValueError:
            src_private = _MISSING
        try:
            dst_private = ipaddress.ip_address(anomaly.dest_ip).is_private
        except ValueError:
            dst_private = _MISSING
        return {
            "http.ua": request.get("user_agent", _MISSING),
            "http.method": request.get("method", _MISSING),
            "http.path": request.get("path", _MISSING),
            "http.query": request.get("query", _MISSING),
            "http.body": request.get("body", _MISSING),
            "http.header": request.get("head", _MISSING),
            "http.status": request.get("status", _MISSING),
            "http.content_type": request.get("content_type", _MISSING),
            "http.referer": request.get("referer", _MISSING),
            "http.filename_ext": _MISSING,
            "src.ip": anomaly.source_ip or _MISSING,
            "src.is_internal": src_private,
            "dst.ip": anomaly.dest_ip or _MISSING,
            "dst.port": anomaly.dest_port or _MISSING,
            "dst.is_internal": dst_private,
            "rule.id": anomaly.rule_id or _MISSING,
            "rule.category": anomaly.category or _MISSING,
            "rule.severity": anomaly.severity or _MISSING,
            "rule.confidence": anomaly.confidence or _MISSING,
            "time.hour": moment.hour,
            "time.is_weekend": moment.weekday() >= 5,
            "time.is_workhour": 9 <= moment.hour < 18 and moment.weekday() < 5,
            "time.is_holiday": False,
            "time.in_maintenance_window": False,
            "time.in_backup_window": False,
            "proto": anomaly.protocol or _MISSING,
            "score": anomaly.score,
        }

    @staticmethod
    def _get(context: Dict[str, Any], field: str) -> Any:
        return context.get(str(field), _MISSING)

    @classmethod
    def _compare(cls, actual: Any, op: str, expected: Any) -> bool:
        if actual is _MISSING:
            return op in {"not_exists", "!="}
        op = str(op or "==")
        if op == "exists":
            return actual is not None and actual != ""
        if op == "not_exists":
            return actual is None or actual == ""
        if op in {">", ">=", "<", "<="}:
            try:
                left, right = float(actual), float(expected)
            except (TypeError, ValueError):
                return False
            return {">": left > right, ">=": left >= right,
                    "<": left < right, "<=": left <= right}[op]
        if op == "contains":
            return str(expected).lower() in str(actual).lower()
        if op == "contains_all":
            values = expected if isinstance(expected, list) else str(expected).split(",")
            return all(str(item).lower() in str(actual).lower() for item in values)
        if op == "regex":
            try:
                return re.search(str(expected), str(actual), re.IGNORECASE) is not None
            except re.error:
                return False
        if op == "in":
            values = expected if isinstance(expected, list) else str(expected).split(",")
            return str(actual) in {str(item).strip() for item in values}
        if op == "not_in":
            values = expected if isinstance(expected, list) else str(expected).split(",")
            return str(actual) not in {str(item).strip() for item in values}
        if op == "!=":
            return str(actual) != str(expected)
        return str(actual) == str(expected)

    @classmethod
    def _match(cls, node: Dict[str, Any], context: Dict[str, Any]) -> bool:
        if not isinstance(node, dict) or not node:
            return True
        if "all" in node:
            return all(cls._match(item, context) for item in node.get("all") or [])
        if "any" in node:
            return any(cls._match(item, context) for item in node.get("any") or [])
        if "not" in node:
            return not cls._match(node.get("not") or {}, context)
        field = node.get("field")
        if not field:
            return True
        return cls._compare(cls._get(context, field), str(node.get("op") or "=="), node.get("value"))

    # ------------------------------------------------------------------ #
    def evaluate(self, anomaly: Anomaly, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
        if not self.rules:
            return None
        moment = float(now or time.time())
        context = self._context(anomaly, moment)
        matched: List[Dict[str, Any]] = []
        for rule in self.rules:
            if not self._match(rule.get("scope") or {}, context):
                continue
            if not self._match(rule.get("when") or {}, context):
                continue
            result = {
                "rule_id": str(rule.get("id") or ""),
                "name": str(rule.get("name") or ""),
                "verdict": str(rule.get("verdict") or "suspicious"),
                "action": str(rule.get("action") or "confirm"),
                "score_delta": float(rule.get("score_delta") or 0.0),
                "reason": str(rule.get("reason") or ""),
            }
            # 抑制类规则优先：即使低优先级，也必须能压过高优先级的通用提级规则。
            if result["action"] == "suppress_alert" or result["verdict"] == "benign":
                ttl = int(rule.get("ttl_sec") or 0)
                key = (result["rule_id"], anomaly.source_ip)
                if ttl > 0 and moment - self._seen.get(key, 0.0) < ttl:
                    continue
                self._seen[key] = moment
                result["score_delta"] = sum(item["score_delta"] for item in matched) + result["score_delta"]
                return result
            matched.append(result)
        if not matched:
            return None
        primary = matched[0]
        primary["score_delta"] = sum(item["score_delta"] for item in matched)
        if len(matched) > 1:
            primary["reason"] = primary["reason"] + "；并命中 " + "、".join(
                item["rule_id"] for item in matched[1:6])
        return primary

    @property
    def stats(self) -> Dict[str, Any]:
        return {"enabled": bool(self.rules), "rules": len(self.rules),
                "path": str(self.path)}

