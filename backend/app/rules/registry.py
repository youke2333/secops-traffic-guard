"""规则注册表：统一加载 + 索引 + 热加载。

职责边界：
* **只做"加载与索引"**，不做检测。检测仍由 `detection/web_knowledge.py`（HTTP 侧）与
  `scanner/cve.py`（漏洞侧）执行，因此对外提供两种消费方式：
  1. `direct_alert_ids`：规则 ID → 是否直达，检测器用它给 `Anomaly` 打直达标记；
  2. `extras_for_web()`：Sigma / ET 规则转成内置知识库结构，直接合并进检测器的规则表。
* **热加载**：`reload()` 幂等，可在运行期由 `POST /rules/reload` 触发，无需重启服务。
* **永不抛异常**：任何来源加载失败都降级为"该来源 0 条"，保证检测链路持续可用。
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..config import Settings, get_settings
from .base import Rule
from .cve_ext_loader import load_extended_rules, merge_cve_rules
from .et_loader import load_et_rules
from .native_loader import load_cve_rules, load_web_rules
from .sigma_loader import load_sigma_rules

logger = logging.getLogger(__name__)

SOURCE_LABELS = {
    "native": "内置知识库（web_attack_rules.json / cve_rules.json）",
    "sigma": "Sigma YAML（backend/data/sigma_rules）",
    "et": "Suricata / ET Open（backend/data/et_rules）",
    "cve_ext": "扩展 CVE（cve_rules_extended.json）",
}


class RuleRegistry:
    """全局规则注册表（线程安全，单例见 `get_registry()`）。"""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._lock = threading.RLock()
        self._by_category: Dict[str, List[Rule]] = defaultdict(list)
        self._by_target: Dict[str, List[Rule]] = defaultdict(list)
        self._by_id: Dict[str, Rule] = {}
        self._by_source: Dict[str, List[Rule]] = defaultdict(list)
        self._web_rules: List[Rule] = []
        self._cve_rules: List[Rule] = []
        self._extras: List[Dict[str, Any]] = []
        self._direct_ids: set = set()
        self.loaded_at: float = 0.0
        self.report: Dict[str, Any] = {}

    @property
    def rules_dir(self) -> Path:
        raw = getattr(self.settings, "rules_dir", "") or ""
        if raw:
            return Path(raw).resolve()
        return Path(__file__).resolve().parents[2] / "data"

    def load_all(self) -> Dict[str, Any]:
        """加载全部来源并重建索引；返回加载报告（同时写日志与 /rules/sources）。"""
        with self._lock:
            errors: List[str] = []
            sigma_rules: List[Rule] = []
            et_rules: List[Rule] = []
            ext_rules: List[Rule] = []
            try:
                web_rules = load_web_rules(self.settings.web_attack_rules_path)
                cve_rules = load_cve_rules(self.settings.cve_rules_path)
            except Exception as exc:      # pragma: no cover - 防御性
                errors.append(f"native: {exc}")
                logger.exception("内置规则加载失败")
                web_rules, cve_rules = [], []
            if getattr(self.settings, "sigma_rules_enabled", True):
                try:
                    sigma_rules = load_sigma_rules(self.rules_dir / "sigma_rules")
                except Exception as exc:
                    errors.append(f"sigma: {exc}")
                    logger.exception("Sigma 规则加载失败")
            if getattr(self.settings, "et_rules_enabled", True):
                try:
                    et_rules = load_et_rules(self.rules_dir / "et_rules")
                except Exception as exc:
                    errors.append(f"et: {exc}")
                    logger.exception("ET 规则加载失败")
            if getattr(self.settings, "cve_ext_enabled", True):
                try:
                    ext_rules = load_extended_rules(self.rules_dir / "cve_rules_extended.json")
                except Exception as exc:
                    errors.append(f"cve_ext: {exc}")
                    logger.exception("扩展 CVE 规则加载失败")

            external = [rule for rule in (sigma_rules + et_rules) if rule.patterns]
            self._web_rules = web_rules + external
            self._cve_rules = merge_cve_rules(cve_rules, ext_rules)
            self._extras = [rule.to_kb_rule() for rule in external]
            self._reindex(self._web_rules + self._cve_rules)

            self.loaded_at = time.time()
            self.report = {
                "loaded_at": round(self.loaded_at, 3),
                "native": len(web_rules) + len(cve_rules),
                "native_web": len(web_rules),
                "native_cve": len(cve_rules),
                "sigma": len(sigma_rules),
                "et": len(et_rules),
                "cve_ext": len(ext_rules),
                "web_effective": len(self._web_rules),
                "cve_effective": len(self._cve_rules),
                "direct_alert": len(self._direct_ids),
                "errors": errors,
                "rules_dir": str(self.rules_dir),
                "web_rules_path": str(self.settings.web_attack_rules_path),
                "cve_rules_path": str(self.settings.cve_rules_path),
            }
            logger.info(
                "rules loaded: native=%d(web %d/cve %d), sigma=%d, et=%d, cve_ext=%d, direct_alert=%d",
                self.report["native"], len(web_rules), len(cve_rules), len(sigma_rules),
                len(et_rules), len(ext_rules), len(self._direct_ids),
            )
            return self.report

    def _reindex(self, rules: Sequence[Rule]) -> None:
        self._by_category = defaultdict(list)
        self._by_target = defaultdict(list)
        self._by_id = {}
        self._by_source = defaultdict(list)
        self._direct_ids = set()
        for rule in rules:
            if not rule.id:
                continue
            self._by_id.setdefault(rule.id, rule)
            self._by_category[rule.category].append(rule)
            for target in rule.match_targets or ["any"]:
                self._by_target[target].append(rule)
            self._by_source[rule.source].append(rule)
            if rule.direct_alert:
                self._direct_ids.add(rule.id)

    def reload(self) -> Dict[str, Any]:
        """热加载（幂等）。"""
        logger.info("规则热加载被触发")
        return self.load_all()

    # ------------------------------------------------------------------ #
    # 查询（索引查询，O(1) 定位候选集合）
    # ------------------------------------------------------------------ #
    def get_rules(self, category: Optional[str] = None, target: Optional[str] = None,
                  source: Optional[str] = None, direct_only: bool = False) -> List[Rule]:
        with self._lock:
            if category:
                candidates = list(self._by_category.get(category, []))
            elif target:
                candidates = list(self._by_target.get(target, []))
            elif source:
                candidates = list(self._by_source.get(source, []))
            else:
                candidates = list(self._by_id.values())
        result: List[Rule] = []
        for rule in candidates:
            if target and target not in (rule.match_targets or []):
                continue
            if source and rule.source != source:
                continue
            if direct_only and not rule.direct_alert:
                continue
            result.append(rule)
        return result

    def rule(self, rule_id: str) -> Optional[Rule]:
        with self._lock:
            return self._by_id.get(str(rule_id))

    def is_direct(self, rule_id: str) -> bool:
        with self._lock:
            return str(rule_id) in self._direct_ids

    @property
    def direct_alert_ids(self) -> set:
        with self._lock:
            return set(self._direct_ids)

    @property
    def web_rules(self) -> List[Rule]:
        with self._lock:
            return list(self._web_rules)

    @property
    def cve_rules(self) -> List[Rule]:
        with self._lock:
            return list(self._cve_rules)

    def extras_for_web(self) -> List[Dict[str, Any]]:
        """Sigma / ET 规则 → 内置知识库结构（供 Web 检测器合并）。"""
        with self._lock:
            return [dict(item) for item in self._extras]

    def categories(self) -> List[str]:
        with self._lock:
            return sorted(self._by_category)

    def by_source(self, source: str) -> List[Rule]:
        with self._lock:
            return list(self._by_source.get(source, []))

    def sources(self, web_categories: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        """各来源加载情况（供 GET /rules/sources 与前端「规则来源」面板展示）。"""
        with self._lock:
            known = set(web_categories or [])
            rows = []
            for source, label in SOURCE_LABELS.items():
                rules = list(self._by_source.get(source, []))
                mapped = [rule for rule in rules if rule.patterns and (not known or rule.category in known)]
                rows.append({
                    "source": source,
                    "label": label,
                    "enabled": self._source_enabled(source),
                    "rules": len(rules),
                    "web_rules": len([rule for rule in rules if rule.patterns]),
                    "mapped_to_web_category": len(mapped),
                    "direct_alert": len([rule for rule in rules if rule.direct_alert]),
                    "by_category": _count_by(rules, "category"),
                    "by_severity": _count_by(rules, "severity"),
                })
            return {
                "loaded_at": self.report.get("loaded_at"),
                "direct_alert_total": len(self._direct_ids),
                "sources": rows,
                "errors": list(self.report.get("errors", [])),
            }

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self.report,
                "categories": len(self._by_category),
                "by_source": {source: len(rules) for source, rules in self._by_source.items()},
                "by_category": {key: len(value) for key, value in sorted(self._by_category.items())},
                "by_target": {key: len(value) for key, value in sorted(self._by_target.items())},
                "direct_alert_ids": sorted(self._direct_ids),
            }

    def _source_enabled(self, source: str) -> bool:
        if source == "sigma":
            return bool(getattr(self.settings, "sigma_rules_enabled", True))
        if source == "et":
            return bool(getattr(self.settings, "et_rules_enabled", True))
        if source == "cve_ext":
            return bool(getattr(self.settings, "cve_ext_enabled", True))
        return True


def _count_by(rules: Sequence[Rule], attr: str) -> Dict[str, int]:
    counter: Dict[str, int] = defaultdict(int)
    for rule in rules:
        counter[str(getattr(rule, attr, "") or "unknown")] += 1
    return dict(sorted(counter.items()))


_registry: Optional[RuleRegistry] = None


def get_registry(settings: Optional[Settings] = None, reload: bool = False) -> RuleRegistry:
    """全局单例：首次调用即完成加载，之后复用。

    * 传入了**不同**的 Settings 对象（测试或运维切换配置）时自动重建，避免脏读旧配置；
    * `reload=True` 强制重建（供 `POST /rules/reload` 热加载）。
    """
    global _registry
    if _registry is None or reload or (settings is not None and _registry.settings is not settings):
        _registry = RuleRegistry(settings)
        _registry.load_all()
    return _registry


def reset_registry() -> None:
    """测试用：清空单例，下次调用重新加载。"""
    global _registry
    _registry = None
