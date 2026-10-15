"""CVE 知识库匹配：把扫描到的「产品 + 版本」映射为具体漏洞与修复建议。

知识库为可维护的 JSON（``backend/data/cve_rules.json``），运维可按需扩展，
无需改代码；命中规则后输出：CVE 编号、CVSS、严重等级、修复版本、处置建议。

匹配策略（从严到宽）：
1. 精确版本约束（``version_lt`` / ``version_le`` / ``version_eq``）；
2. 版本区间（``version_between``）；
3. banner 正则特征（``banner_regex``，用于 Log4Shell 这类无版本号可判的场景）；
4. 端口级配置类风险（``port_misconfig``，如 Docker API 未授权访问）。
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


@dataclass
class CveMatch:
    cve: str
    title: str
    severity: str
    cvss: float
    product: str
    version: str
    port: int
    recommendation: str
    fixed_version: str = ""
    evidence: str = ""
    references: List[str] = field(default_factory=list)
    # 发现途径与研判可信度（scan/web/traffic_rule/traffic_ai；confirmed/suspected）
    source: str = "scan"
    confidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def version_tuple(value: str) -> tuple:
    """把版本号转成可比较元组：'2.4.57' -> (2, 4, 57)。"""
    parts = re.findall(r"\d+", value or "")
    return tuple(int(p) for p in parts[:4]) or (0,)


def _compare(left: str, right: str) -> int:
    a, b = version_tuple(left), version_tuple(right)
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


class CveKnowledgeBase:
    def __init__(self, rules_path: Optional[Path] = None,
                 additional_rules: Optional[List[Dict[str, Any]]] = None) -> None:
        self.rules_path = Path(rules_path) if rules_path else None
        self.additional_rules = list(additional_rules or [])
        self.rules: List[Dict[str, Any]] = []
        self.version = "unknown"
        self.load()

    def load(self) -> int:
        if self.rules_path is None or not self.rules_path.exists():
            logger.warning("CVE 规则文件不存在: %s", self.rules_path)
            return 0
        try:
            payload = json.loads(self.rules_path.read_text(encoding="utf-8"))
        except Exception:
            logger.exception("加载 CVE 规则失败")
            return 0
        self.version = payload.get("version", "unknown")
        self.rules = self._merge(payload.get("rules", []))
        logger.info("已加载 CVE 规则 %d 条（知识库版本 %s，含扩展 %d 条）",
                    len(self.rules), self.version, len(self.additional_rules))
        return len(self.rules)

    def _merge(self, rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """合并内置与扩展 CVE 规则：同一 CVE 编号以扩展条目为准（版本区间更精确）。"""
        if not self.additional_rules:
            return list(rules)
        merged: Dict[str, Dict[str, Any]] = {}
        for rule in rules:
            if isinstance(rule, dict):
                merged[str(rule.get("cve") or rule.get("title") or "")] = rule
        for rule in self.additional_rules:
            if isinstance(rule, dict):
                merged[str(rule.get("cve") or rule.get("title") or "")] = rule
        return [value for value in merged.values() if value]

    # ------------------------------------------------------------------ #
    # 匹配
    # ------------------------------------------------------------------ #
    def match(self, product: str, version: str = "", port: int = 0,
              banner: str = "", service: str = "") -> List[CveMatch]:
        """返回命中的全部漏洞规则（同一产品可能命中多条）。"""
        hits: List[CveMatch] = []
        product_l = (product or "").lower()
        service_l = (service or "").lower()
        banner_l = (banner or "").lower()

        for rule in self.rules:
            product_pattern = rule.get("product_regex")
            if product_pattern:
                if not re.search(product_pattern, product_l or service_l, re.IGNORECASE):
                    continue
            elif rule.get("service_regex"):
                if not re.search(rule["service_regex"], service_l, re.IGNORECASE):
                    continue

            ports = rule.get("ports")
            if ports and port and port not in ports:
                continue

            banner_regex = rule.get("banner_regex")
            if banner_regex and not re.search(banner_regex, banner_l, re.IGNORECASE):
                continue

            if not self._version_hit(rule, version):
                continue

            hits.append(CveMatch(
                cve=rule.get("cve", "UNKNOWN"),
                title=rule.get("title", ""),
                severity=rule.get("severity", "medium"),
                cvss=float(rule.get("cvss", 0.0)),
                product=product or service,
                version=version or "未识别",
                port=port,
                recommendation=rule.get("recommendation", ""),
                fixed_version=rule.get("fixed_version", ""),
                evidence=(rule.get("evidence_template", "") or "").format(
                    product=product, version=version or "未识别", port=port, banner=(banner or "")[:120]
                ).strip(),
                references=rule.get("references", []),
            ))
        return hits

    @staticmethod
    def _version_hit(rule: Dict[str, Any], version: str) -> bool:
        """版本约束判定；规则未写版本约束时视为"命中即风险"（如配置类问题）。"""
        constraints = [key for key in
                       ("version_lt", "version_le", "version_gt", "version_ge", "version_eq", "version_between")
                       if key in rule]
        if not constraints:
            return True
        if not version:
            # 版本未识别时**不猜测**（默认不报告）：宁可漏报也不误报。
            # 需要宽松行为的规则可显式设置 assume_risk_if_unknown=true。
            return bool(rule.get("assume_risk_if_unknown", False))

        for key in constraints:
            value = rule[key]
            if key == "version_lt" and _compare(version, str(value)) < 0:
                return True
            if key == "version_le" and _compare(version, str(value)) <= 0:
                return True
            if key == "version_gt" and _compare(version, str(value)) > 0:
                return True
            if key == "version_ge" and _compare(version, str(value)) >= 0:
                return True
            if key == "version_eq" and _compare(version, str(value)) == 0:
                return True
            if key == "version_between" and isinstance(value, Sequence) and len(value) == 2:
                low, high = str(value[0]), str(value[1])
                if _compare(version, low) >= 0 and _compare(version, high) <= 0:
                    return True
        return False

    @property
    def stats(self) -> Dict[str, Any]:
        return {"rules": len(self.rules), "version": self.version, "path": str(self.rules_path or "")}
