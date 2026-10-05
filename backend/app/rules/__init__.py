"""统一规则加载层：把内置知识库与开源规则库（Sigma / Suricata-ET / 扩展 CVE）归一化为 `Rule`。

层次关系（详见方案第 1 层）：

    backend/data/*.json            ─┐
    backend/data/sigma_rules/*.yml ─┼→ rules.loader → rules.registry → detection（HTTP 侧/CVE 侧）
    backend/data/et_rules/*.rules  ─┤
    cve_rules_extended.json        ─┘

对外只需要认识两个入口：
* `get_registry()`            —— 全局单例注册表（加载 + 索引 + 热加载 + 直达标记）；
* `load_*` 系列函数            —— 单文件/单目录加载（测试与运维脚本使用）。
"""

from .base import (
    DIRECT_ALERT_CATEGORIES,
    NO_DIRECT_ALERT_CATEGORIES,
    Rule,
    should_inject_direct_alert,
)
from .cve_ext_loader import load_extended_rules, merge_cve_rules
from .et_loader import load_et_rules
from .loader import load_path
from .native_loader import load_cve_rules, load_web_rules
from .registry import RuleRegistry, get_registry, reset_registry
from .sigma_loader import load_sigma_rules

__all__ = [
    "Rule",
    "RuleRegistry",
    "get_registry",
    "reset_registry",
    "load_path",
    "load_web_rules",
    "load_cve_rules",
    "load_sigma_rules",
    "load_et_rules",
    "load_extended_rules",
    "merge_cve_rules",
    "should_inject_direct_alert",
    "DIRECT_ALERT_CATEGORIES",
    "NO_DIRECT_ALERT_CATEGORIES",
]
