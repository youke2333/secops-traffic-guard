"""统一规则 Schema：无论规则来自哪个开源库，最终都归一化成 `Rule`。

设计要点：
* **单一结构**：JSON（内置知识库）/ Sigma YAML / Suricata(.rules) / 扩展 CVE 全部映射为同一份
  `Rule`，检测引擎与前端只需要认识这一种结构；
* **直达标记（direct_alert）**：规则固有的"单条命中即可立即告警"属性，由加载器按类别白名单 +
  严重度/置信度自动注入（见 `native_loader.DIRECT_ALERT_CATEGORIES`）；
* **保留原始定义**：`raw` 字段保存来源的原始字典，便于审计与问题回溯（"为什么命中"可查）。

字段语义约定（与 `backend/data/web_attack_rules.json` 保持兼容）：
* ``category``     攻击大类（Web 侧沿用知识库的 key，如 sql_injection；流量侧用 port_scan 等）
* ``severity``     critical / high / medium / low
* ``confidence``   规则本身的置信度 high / medium / low（影响评分权重，见 detection/scoring.py）
* ``patterns``     已编译就绪的正则字符串列表（匹配前统一做归一化，见 detection/web_knowledge.py）
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
SOURCES = ("native", "sigma", "et", "cve_ext")

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}

# 匹配目标（与 web_knowledge.build_targets() 的字段名一一对应）
MATCH_TARGETS = (
    "path", "query", "body", "header", "cookie", "user_agent", "referer", "filename", "any",
)

# 这些类别一旦命中即为致命攻击：加载时自动 direct_alert=True（详见方案 1.5 节）
# 注：这里用的是**知识库的大类 key**（不含 web_ 前缀），检测器会统一加前缀。
DIRECT_ALERT_CATEGORIES = {
    "command_injection",     # RCE / 命令注入
    "webshell",              # Webshell 访问
    "ssti",                  # 服务端模板注入
    "file_upload",           # 上传 PHP/JSP 木马（file_upload_webshell）
    "xxe",                   # XXE
}

# 明确**不**注入直达标记的类别（仍走滑动窗口聚合，避免误报直接触发响应动作）
# 说明：sql_injection / xss 类规则旧接口拼接、回显场景误报率较高；
#       port_scan / brute_force 依赖频次阈值；path_traversal 需结合文件敏感度人工确认。
NO_DIRECT_ALERT_CATEGORIES = {
    "sql_injection", "sql_injection_blind", "xss_reflected", "xss_stored",
    "brute_force", "csrf", "insecure_captcha", "path_traversal", "ssrf",
    "ldap_nosql_injection", "crlf_injection", "file_inclusion",
    # 流量侧类别
    "port_scan", "brute_force_net", "traffic_spike", "nonstandard_port",
    "behavior_anomaly",
}

# CVE 规则永不直达：版本号匹配本身存在不确定性，必须走聚合或人工研判
CVE_NEVER_DIRECT = True


@dataclass
class Rule:
    """统一规则结构（所有来源的归一化目标）。"""

    id: str
    source: str = "native"                      # native / sigma / et / cve_ext
    category: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    score_weight: float = 0.0                   # 命中该规则时的评分贡献（无 severity 时用）
    direct_alert: bool = False                  # 单条命中即告警，绕过聚合投票
    match_targets: List[str] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    match_all: bool = False                     # True 时要求 patterns 全部命中
    match_mode: str = "normalized"              # normalized / raw / both
    method_in: List[str] = field(default_factory=list)
    status_in: List[int] = field(default_factory=list)
    require_absent: List[str] = field(default_factory=list)
    threshold: Optional[dict] = None            # {"window_sec": 60, "count": 10}
    title: str = ""
    cve: Optional[str] = None
    product_regex: Optional[str] = None
    service_regex: Optional[str] = None
    version_lt: Optional[str] = None
    version_le: Optional[str] = None
    version_gt: Optional[str] = None
    version_ge: Optional[str] = None
    version_eq: Optional[str] = None
    version_between: Optional[List[str]] = None
    cvss: float = 0.0
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def is_web(self) -> bool:
        """是否属于 HTTP 侧（Web 攻击）规则：供 Web 检测器合并使用。"""
        return self.source in ("native", "sigma", "et") and bool(self.patterns)

    @property
    def key(self) -> str:
        """去重键：同一来源下 id 唯一；不同来源允许同 id（保留 `source` 便于溯源）。"""
        return f"{self.source}:{self.id}"

    def public(self) -> Dict[str, Any]:
        """面向前端 / API 的精简展示（去掉正则等实现细节，避免泄露绕过思路）。"""
        return {
            "id": self.id,
            "source": self.source,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "title": self.title,
            "direct_alert": self.direct_alert,
            "match_targets": list(self.match_targets),
            "pattern_count": len(self.patterns),
            "threshold": self.threshold,
            "cve": self.cve,
            "cvss": self.cvss,
            "remediation": self.remediation,
            "references": list(self.references),
        }

    def to_kb_rule(self) -> Dict[str, Any]:
        """转成 `web_attack_rules.json` 的规则结构，供 Web 检测器直接合并使用。

        这样 Sigma / ET 规则无需改动检测引擎即可生效（检测链路保持单一实现）。
        """
        return {
            "id": self.id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "cvss": self.cvss,
            "match_targets": list(self.match_targets) or ["any"],
            "patterns": list(self.patterns),
            "exclude_patterns": list(self.exclude_patterns),
            "match_all": bool(self.match_all),
            "match_mode": self.match_mode,
            "method_in": list(self.method_in),
            "status_in": list(self.status_in),
            "require_absent": list(self.require_absent),
            "threshold": self.threshold,
            "remediation": self.remediation,
            "references": list(self.references),
            "examples": list(self.examples),
            "direct_alert": bool(self.direct_alert),
            "rule_source": self.source,
        }


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(str(severity or "").lower(), 1)


def confidence_rank(confidence: str) -> int:
    return CONFIDENCE_RANK.get(str(confidence or "").lower(), 1)


def valid_severity(severity: str) -> str:
    value = str(severity or "").lower()
    return value if value in SEVERITY_RANK else "medium"


def valid_confidence(confidence: str) -> str:
    value = str(confidence or "").lower()
    return value if value in CONFIDENCE_RANK else "medium"


def should_inject_direct_alert(category: str, severity: str, confidence: str,
                               source: str = "native") -> bool:
    """直达标记注入判定（加载期一次性计算，运行期零成本）。

    规则（与方案 1.5 节一致）：
    1. CVE 规则永不直达；
    2. 类别在 `DIRECT_ALERT_CATEGORIES` 白名单内 → 直达；
    3. 类别在 `NO_DIRECT_ALERT_CATEGORIES` 黑名单内 → 不直达；
    4. Sigma / ET 等外部规则：critical + high 置信度 → 直达（保守，只放行最确定的一类）。
    """
    if source == "cve_ext":
        return False
    key = str(category or "").strip()
    if key in NO_DIRECT_ALERT_CATEGORIES:
        return False
    if key in DIRECT_ALERT_CATEGORIES:
        return True
    if source in ("sigma", "et"):
        return valid_severity(severity) == "critical" and valid_confidence(confidence) == "high"
    return False
