"""匹配后端抽象与 RulePlan（规则计划）。

RulePlan 在加载期完成所有可预计算的工作（正则编译、path_regex、方法/状态集合），
运行期只做字段匹配；RE2 后端仅用于“减少候选”，最终判定仍由 RulePlan 精匹配完成，
因此预筛不会改变任何检测语义。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Pattern


@dataclass(slots=True)
class RulePlan:
    idx: int
    rule_id: str
    category: str
    severity: str
    confidence: str
    tier: str
    patterns: List[Pattern[str]]
    excludes: List[Pattern[str]]
    targets: List[str]
    match_mode: str
    match_all: bool
    methods: frozenset
    statuses: frozenset
    path_re: Optional[Pattern[str]] = None
    path_not_re: Optional[Pattern[str]] = None
    threshold_count: int = 1
    threshold_window: int = 60
    direct_alert: bool = False
    rule: Dict[str, Any] = field(default_factory=dict)


def compile_plan(idx: int, rule: Dict[str, Any]) -> Optional[RulePlan]:
    """编译单条规则；正则非法时返回 None（加载日志会记录，不静默）。"""
    try:
        patterns = [re.compile(str(item), re.IGNORECASE)
                    for item in (rule.get("patterns") or []) if str(item)]
        if not patterns:
            return None
        excludes = [re.compile(str(item), re.IGNORECASE)
                    for item in (rule.get("exclude_patterns") or []) if str(item)]
        path_re = (re.compile(str(rule["path_regex"]), re.IGNORECASE)
                   if rule.get("path_regex") else None)
        path_not = (re.compile(str(rule["path_not_regex"]), re.IGNORECASE)
                    if rule.get("path_not_regex") else None)
        threshold = rule.get("threshold") or {}
        return RulePlan(
            idx=idx, rule_id=str(rule.get("id") or ""),
            category=str(rule.get("category") or ""),
            severity=str(rule.get("severity") or ""),
            confidence=str(rule.get("confidence") or "medium"),
            tier=str(rule.get("tier") or ""),
            patterns=patterns, excludes=excludes,
            targets=[str(item) for item in (rule.get("match_targets") or ["any"])],
            match_mode=str(rule.get("match_mode") or "normalized"),
            match_all=bool(rule.get("match_all")),
            methods=frozenset(str(item).upper() for item in (rule.get("method_in") or [])),
            statuses=frozenset(int(item) for item in (rule.get("status_in") or [])),
            path_re=path_re, path_not_re=path_not,
            threshold_count=max(1, int(threshold.get("count") or 1)),
            threshold_window=max(1, int(threshold.get("window_sec") or 60)),
            direct_alert=bool(rule.get("direct_alert")),
            rule=rule,
        )
    except (re.error, TypeError, ValueError):
        return None


class MatcherBackend:
    """候选后端协议：返回 bytearray（1=需要进入精匹配）。"""

    name = "python"

    def candidates(self, targets: Dict[str, Dict[str, str]]) -> Optional[bytearray]:
        return None

    def stats(self) -> Dict[str, Any]:
        return {"matcher_backend": self.name, "matcher_patterns": 0,
                "matcher_fallback_rules": 0, "compile_ms": 0.0}
