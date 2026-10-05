"""扩展 CVE 规则加载器：`backend/data/cve_rules_extended.json` → 统一 `Rule`。

用途：内置 `cve_rules.json` 只保留高频高危条目（18 条），从开源签名库
（如 vedas-signatures / nuclei-templates 里的 CVE 描述）转换出的更大规则集放在
`cve_rules_extended.json`，加载时与内置条目**合并**：

* 同一 CVE 编号时以扩展条目为准（扩展条目通常版本区间更精确）；
* CVE 规则**永不设置 direct_alert**：版本号匹配本身存在不确定性（banner 解析、
  回移植补丁等），必须走聚合评分或人工研判，避免"一命中就自动封禁"造成业务中断；
* 扩展文件缺失或格式错误时自动降级为"仅内置规则"，不影响系统启动。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from .base import Rule

logger = logging.getLogger(__name__)


def load_extended_rules(path: Path) -> List[Rule]:
    """读取扩展 CVE 文件（不存在时返回空列表）。"""
    file_path = Path(path)
    if not file_path.exists():
        logger.info("扩展 CVE 规则文件不存在，跳过：%s", file_path)
        return []
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("扩展 CVE 规则解析失败：%s", file_path)
        return []
    rules = payload.get("rules", []) if isinstance(payload, dict) else []
    converted: List[Rule] = []
    for raw in rules:
        if not isinstance(raw, dict):
            continue
        cve = str(raw.get("cve") or raw.get("id") or "").strip()
        if not cve:
            continue
        converted.append(Rule(
            id=cve,
            source="cve_ext",
            category=str(raw.get("category") or "cve_vulnerability"),
            severity=str(raw.get("severity") or "medium").lower(),
            confidence=str(raw.get("confidence") or "medium").lower(),
            direct_alert=False,
            match_targets=["netflow"],
            title=str(raw.get("title") or ""),
            cve=cve,
            product_regex=raw.get("product_regex"),
            service_regex=raw.get("service_regex"),
            version_lt=_text(raw.get("version_lt")),
            version_le=_text(raw.get("version_le")),
            version_gt=_text(raw.get("version_gt")),
            version_ge=_text(raw.get("version_ge")),
            version_eq=_text(raw.get("version_eq")),
            version_between=[str(item) for item in raw.get("version_between") or []] or None,
            cvss=float(raw.get("cvss") or 0.0),
            remediation=str(raw.get("recommendation") or raw.get("remediation") or ""),
            references=[str(item) for item in (raw.get("references") or [])],
            raw=dict(raw),
        ))
    logger.info("cve_ext 加载器：%s → %d 条规则", file_path.name, len(converted))
    return converted


def _text(value: Any) -> Any:
    return str(value) if value not in (None, "") else None


def merge_cve_rules(native: List[Rule], extended: List[Rule]) -> List[Rule]:
    """合并内置与扩展 CVE 规则：同编号以扩展为准，输出按 CVE 编号排序（便于比对）。"""
    merged: Dict[str, Rule] = {}
    for rule in native:
        merged[rule.id] = rule
    for rule in extended:
        merged[rule.id] = rule
    return [merged[key] for key in sorted(merged)]
