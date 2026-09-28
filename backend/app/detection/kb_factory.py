"""统一 Web 知识库构建入口（v6）：启动与热加载共用，避免两套加载逻辑漂移。

修复的既有隐患：
* ``POST /rules/reload`` 曾只传 Sigma/ET，丢掉高置信度直达规则与直达标记；
* 规则包类别必须与规则同一批合并，否则新增类别会被静默丢弃；
* 知识库构建完成后再由调用方原子替换引用，检测线程取快照使用。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..config import Settings, get_settings
from .web_knowledge import (
    WebAttackKnowledgeBase,
    _strict_inputs,
    _registry_inputs,
)


def build_web_kb(settings: Optional[Settings] = None, registry=None) -> WebAttackKnowledgeBase:
    cfg = settings or get_settings()
    if registry is not None:
        extras, direct_ids = registry.extras_for_web(), registry.direct_alert_ids
    else:
        extras, direct_ids = _registry_inputs(cfg)
    strict_rules, strict_direct = _strict_inputs(cfg)
    categories = []
    pack_report: Dict[str, Any] = {}
    pack_rules = []
    if getattr(cfg, "rulesets_enabled", True):
        try:
            from ..rules.packs import load_intrusion_pack

            pack_rules, categories, pack_report = load_intrusion_pack(cfg)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("入侵规则包加载失败，降级为内置规则继续运行")

    merged = list(pack_rules) + list(extras) + list(strict_rules)
    kb = WebAttackKnowledgeBase(
        cfg.web_attack_rules_path,
        extra_rules=merged,
        direct_alert_ids=set(direct_ids) | set(strict_direct),
        extra_categories=categories,
        tiers=list(cfg.rules_tiers),
        matcher_backend=cfg.match_backend,
        re2_max_mem_mb=cfg.re2_max_mem_mb,
        max_rules=cfg.rules_max_count,
        reject_unknown_category=(cfg.rules_unknown_category == "reject"),
    )
    kb.pack_report = pack_report
    return kb
