"""规则包加载（v6 P2）：入侵检测包 HTTP 部分 + 类别合并 + 分档。

本模块只负责“把磁盘规则转成 Web 知识库可消费的结构”，不做匹配。
流级（109）/ 研判（300）/ 病毒（329）规则由各自执行器消费，未启用时不会加载进 Web 引擎。
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import Settings, get_settings

logger = logging.getLogger(__name__)

PACK_FILES = {
    "intrusion": "intrusion_rules.json",
    "triage": "triage_rules.json",
    "malware": "malware_signatures.json",
}


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _checksum(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_intrusion_pack(settings: Optional[Settings] = None) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """返回 (HTTP 规则, 新增类别, 加载报告)。

    * 默认只加载 ``RULES_TIERS=core``；
    * 未定义类别按 ``RULES_UNKNOWN_CATEGORY`` 处理（默认拒绝并计数，不静默）；
    * 规则 ID / pattern 冲突交给知识库统一去重。
    """
    cfg = settings or get_settings()
    path = Path(cfg.rulesets_path) / PACK_FILES["intrusion"]
    report: Dict[str, Any] = {
        "pack": "intrusion", "file": str(path), "loaded": False,
        "total": 0, "http": 0, "flow": 0, "selected": 0,
        "skipped_tier": 0, "skipped_unknown": 0, "skipped_invalid": 0,
        "by_tier": {}, "checksum": _checksum(path), "version": "", "error": "",
        "tiers_enabled": list(cfg.rules_tiers),
    }
    if not path.exists():
        report["error"] = "规则包文件不存在"
        return [], [], report
    try:
        payload = _read_json(path)
    except Exception as exc:
        report["error"] = f"规则包解析失败：{exc}"
        logger.exception("入侵规则包加载失败：%s", path)
        return [], [], report

    report["version"] = str(payload.get("version") or "")
    taxonomy = payload.get("taxonomy") or []
    categories = [dict(item) for item in taxonomy if isinstance(item, dict) and item.get("key")]
    known = {str(item.get("key")) for item in categories}
    enabled_tiers = {str(item).lower() for item in cfg.rules_tiers}
    selected: List[Dict[str, Any]] = []
    stats = payload.get("stats") or {}
    report["by_tier"] = stats.get("by_tier") or {}
    report["total"] = int(stats.get("total") or len(payload.get("rules") or []))
    report["http"] = int(stats.get("http_text") or 0)
    report["flow"] = int(stats.get("flow") or 0)

    for raw in payload.get("rules") or []:
        if not isinstance(raw, dict):
            report["skipped_invalid"] += 1
            continue
        if not raw.get("patterns") or raw.get("flow_condition"):
            continue                       # 流级规则不进 Web 引擎
        tier = str(raw.get("tier") or "extended").lower()
        if tier not in enabled_tiers:
            report["skipped_tier"] += 1
            continue
        category = str(raw.get("category") or "")
        if category not in known:
            report["skipped_unknown"] += 1
            if cfg.rules_unknown_category == "reject":
                logger.error("规则 %s 的类别 %s 未在 taxonomy 中定义，已拒绝加载",
                             raw.get("id"), category)
            continue
        rule = dict(raw)
        rule["rule_source"] = "intrusion-pack"
        rule["tier"] = tier
        rule.setdefault("references", [])
        rule.setdefault("remediation", "")
        rule.setdefault("false_positive_hint", "")
        selected.append(rule)

    report["selected"] = len(selected)
    report["loaded"] = True
    logger.info("规则包 intrusion：total=%d http=%d flow=%d selected=%d "
                "skipped_tier=%d unknown=%d checksum=%s",
                report["total"], report["http"], report["flow"], report["selected"],
                report["skipped_tier"], report["skipped_unknown"], report["checksum"][:12])
    return selected, categories, report


def _pack_meta(name: str, cfg: Settings) -> Dict[str, Any]:
    path = Path(cfg.rulesets_path) / PACK_FILES[name]
    meta: Dict[str, Any] = {
        "pack": name, "file": str(path), "exists": path.exists(),
        "count": 0, "checksum": _checksum(path), "version": "", "updated_at": "",
        "enabled": bool(cfg.rulesets_enabled), "engine": "",
    }
    if not path.exists():
        return meta
    try:
        payload = _read_json(path)
        meta.update({
            "count": int((payload.get("stats") or {}).get("total") or len(payload.get("rules") or [])),
            "version": str(payload.get("version") or ""),
            "updated_at": str(payload.get("updated_at") or ""),
            "engine": ",".join(payload.get("match_engines") or []) if isinstance(
                payload.get("match_engines"), list) else str(payload.get("match_engine") or ""),
        })
    except Exception as exc:
        meta["error"] = str(exc)
    return meta


def packs_overview(settings: Optional[Settings] = None,
                   intrusion_report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """规则包总览（供规则管理页 / API 展示，不触发执行器）。"""
    cfg = settings or get_settings()
    items = [_pack_meta(name, cfg) for name in PACK_FILES]
    for item in items:
        if item["pack"] == "intrusion" and intrusion_report:
            item.update({
                "selected": intrusion_report.get("selected", 0),
                "by_tier": intrusion_report.get("by_tier", {}),
                "skipped_tier": intrusion_report.get("skipped_tier", 0),
                "skipped_unknown": intrusion_report.get("skipped_unknown", 0),
                "error": intrusion_report.get("error", ""),
            })
        elif item["pack"] == "triage":
            item["enabled"] = bool(cfg.rulesets_enabled and cfg.triage_enabled)
        elif item["pack"] == "malware":
            item["enabled"] = bool(cfg.rulesets_enabled and cfg.malware_scan_enabled)
    return {
        "rulesets_enabled": bool(cfg.rulesets_enabled),
        "tiers_enabled": list(cfg.rules_tiers),
        "shadow_mode": bool(cfg.rules_shadow_mode),
        "total": sum(int(item.get("count") or 0) for item in items),
        "packs": items,
    }

