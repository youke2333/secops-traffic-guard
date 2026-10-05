"""内置知识库加载器：把 `web_attack_rules.json` / `cve_rules.json` 转成统一 `Rule`。

* Web 规则（17 大类 / 63 条）→ 供 HTTP 检测器合并使用，同时完成直达标记注入；
* CVE 规则（18 条）→ 供漏洞扫描器查询（无正则，走版本/端口匹配）。

注意：**只读取、不修改**知识库文件本身；直达标记是加载期在内存里注入的，
这样 `web_attack_rules.json` 仍然可以直接被运维手工编辑（不需要懂 direct_alert 语义）。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import Rule, should_inject_direct_alert, valid_confidence, valid_severity

logger = logging.getLogger(__name__)

CVE_CATEGORY = "cve_vulnerability"


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path or not Path(path).exists():
        logger.warning("规则文件不存在，已跳过：%s", path)
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        logger.exception("规则文件解析失败：%s", path)
        return None


def load_web_rules(path: Path, source: str = "native") -> List[Rule]:
    """加载 Web 攻击知识库（Java/JSON 结构），并在内存注入直达标记。"""
    payload = _read_json(path)
    if not payload:
        return []
    categories = {str(item.get("key")): item for item in payload.get("categories", []) or []}
    rules: List[Rule] = []
    for raw in payload.get("rules", []) or []:
        category = str(raw.get("category") or "")
        meta = categories.get(category, {})
        severity = valid_severity(raw.get("severity") or meta.get("severity") or "medium")
        confidence = valid_confidence(raw.get("confidence") or "medium")
        targets = [str(item) for item in (raw.get("match_targets") or ["any"])]
        rules.append(Rule(
            id=str(raw.get("id") or ""),
            source=source,
            category=category,
            severity=severity,
            confidence=confidence,
            direct_alert=should_inject_direct_alert(category, severity, confidence, source),
            match_targets=targets,
            patterns=[str(item) for item in (raw.get("patterns") or [])],
            exclude_patterns=[str(item) for item in (raw.get("exclude_patterns") or [])],
            threshold=raw.get("threshold"),
            title=str(raw.get("title") or ""),
            cvss=float(raw.get("cvss") or 0.0),
            remediation=str(raw.get("remediation") or ""),
            references=[str(item) for item in (raw.get("references") or [])],
            examples=[str(item) for item in (raw.get("examples") or [])],
            raw=dict(raw),
        ))
    logger.info("native 加载器：Web 规则 %d 条（来源 %s）", len(rules), Path(path).name)
    return rules


def load_cve_rules(path: Path, source: str = "native") -> List[Rule]:
    """加载 CVE 知识库；CVE 规则永不直达（版本匹配存在不确定性）。"""
    payload = _read_json(path)
    if not payload:
        return []
    rules: List[Rule] = []
    for raw in payload.get("rules", []) or []:
        rules.append(Rule(
            id=str(raw.get("cve") or raw.get("id") or ""),
            source=source,
            category=str(raw.get("category") or CVE_CATEGORY),
            severity=valid_severity(raw.get("severity") or "medium"),
            confidence=valid_confidence(raw.get("confidence") or "medium"),
            direct_alert=False,
            match_targets=["netflow"],
            title=str(raw.get("title") or ""),
            cve=str(raw.get("cve") or "") or None,
            product_regex=raw.get("product_regex"),
            service_regex=raw.get("service_regex"),
            version_lt=_str_or_none(raw.get("version_lt")),
            version_le=_str_or_none(raw.get("version_le")),
            version_gt=_str_or_none(raw.get("version_gt")),
            version_ge=_str_or_none(raw.get("version_ge")),
            version_eq=_str_or_none(raw.get("version_eq")),
            version_between=[str(item) for item in raw.get("version_between") or []] or None,
            cvss=float(raw.get("cvss") or 0.0),
            remediation=str(raw.get("recommendation") or ""),
            references=[str(item) for item in (raw.get("references") or [])],
            raw=dict(raw),
        ))
    logger.info("native 加载器：CVE 规则 %d 条（来源 %s）", len(rules), Path(path).name)
    return rules


def _str_or_none(value: Any) -> Optional[str]:
    return str(value) if value not in (None, "") else None


def load_pair(web_path: Path, cve_path: Path) -> Tuple[List[Rule], List[Rule]]:
    """便捷入口：返回 (Web 规则, CVE 规则)。"""
    return load_web_rules(web_path), load_cve_rules(cve_path)
