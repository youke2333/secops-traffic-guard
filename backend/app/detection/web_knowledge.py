"""Web 攻击检测知识库：把 HTTP 请求映射为结构化 Web 攻击告警。

知识库文件：``backend/data/web_attack_rules.json``（内置 17 大类 / 63 条规则，可自行扩展，
无需改代码）。覆盖 OWASP Top 10 的主要攻击面：

    SQL 注入 / SQL 盲注 / 反射型 XSS / 存储型 XSS / 命令注入 / 文件包含(LFI+RFI) /
    恶意文件上传 / 暴力破解 / CSRF / 不安全验证码 / 目录穿越 / SSRF / XXE /
    Webshell / SSTI / LDAP-NoSQL 注入 / CRLF 注入

检测流水线（每条 HTTP 请求）：

    字段提取（path/query/body/header/cookie/user_agent/referer/filename）
      → 归一化（多轮 URL 解码 → HTML 实体解码 → SQL 注释归一 → 空白折叠 → 小写）
      → 规则匹配（patterns / exclude_patterns / match_all / method_in / status_in / require_absent）
      → 频次阈值（threshold：窗口内累计达到 count 次才告警，用于暴力破解 / CSRF / 验证码）
      → 分类聚合与组合提级（同一请求命中多类 → 提级为组合攻击）
      → 冷却抑制（同 (分类, 源 IP) 在冷却窗内只报一次，避免告警风暴）
      → Anomaly(category="web_<大类>") → 复用既有落库 / 自动封禁 / 通知 / SSE 推送链路
"""

from __future__ import annotations

import html
import ipaddress
import json
import logging
import re
import re
import threading
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote_plus

from ..config import Settings, get_settings
from .engine import Anomaly
from .matcher import RulePlan, build_matcher, compile_plan

CONFIDENCE_SCORE = {"high": 0.95, "medium": 0.7, "low": 0.45}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_BY_ORDER = {value: key for key, value in SEVERITY_ORDER.items()}
DEFAULT_TARGETS = ["any"]
MAX_SNIPPET = 120


# --------------------------------------------------------------------------- #
# 请求事件
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class WebRequestEvent:
    """标准化 HTTP 请求事件（由访问日志、仿真源或外部 WAF/代理投递）。"""

    ts: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 80
    proto: str = "TCP"
    method: str = "GET"
    path: str = "/"
    query: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    status: int = 0
    iface: str = ""
    source: str = ""       # log | demo | api（便于排查数据来源）
    response_head: str = ""    # 响应头快照（上游代理采集，敏感头已脱敏）
    response_body: str = ""    # 文本响应体快照（截断，二进制响应为空）

    def header(self, name: str) -> str:
        target = (name or "").lower()
        for key, value in (self.headers or {}).items():
            if (key or "").lower() == target:
                return value or ""
        return ""

    @property
    def url(self) -> str:
        return f"{self.path}?{self.query}" if self.query else (self.path or "/")

    @property
    def request_line(self) -> str:
        return f"{self.method or 'GET'} {self.url} HTTP/1.1"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "WebRequestEvent":
        """从 API 请求体 / 队列消息构建事件（字段缺失时使用安全默认值）。"""
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        query = payload.get("query") or ""
        path = payload.get("path") or "/"
        if "?" in path and not query:      # 允许直接投递完整 URL
            path, query = path.split("?", 1)
        body = payload.get("body") or ""
        return cls(
            ts=float(payload.get("ts") or time.time()),
            src_ip=str(payload.get("src_ip") or ""),
            dst_ip=str(payload.get("dst_ip") or ""),
            src_port=int(payload.get("src_port") or 0),
            dst_port=int(payload.get("dst_port") or 80),
            proto=str(payload.get("proto") or "TCP"),
            method=str(payload.get("method") or "GET").upper(),
            path=str(path)[:2048],
            query=str(query)[:4096],
            body=str(body)[:8192],
            headers={str(k): str(v)[:1024] for k, v in headers.items()},
            status=int(payload.get("status") or 0),
            iface=str(payload.get("iface") or ""),
            source=str(payload.get("source") or "api"),
            response_head=str(payload.get("response_head") or ""),
            response_body=str(payload.get("response_body") or ""),
        )


@dataclass(slots=True)
class WebAttackHit:
    """一条规则的命中结果。"""

    rule_id: str
    category: str
    category_name: str
    title: str
    severity: str
    cvss: float
    confidence: str
    cwe: str
    owasp: str
    target: str
    snippet: str
    remediation: str
    references: List[str] = field(default_factory=list)
    false_positive_hint: str = ""
    threshold_count: int = 0
    window_sec: int = 0
    matched_pattern: str = ""
    # ---- 规则来源与直达标记（v2 新增：支持 Sigma / ET 外部规则与直达机制）----
    rule_source: str = "native"
    direct_alert: bool = False
    tier: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# 归一化工具
# --------------------------------------------------------------------------- #
_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SPACE_RE = re.compile(r"[ \t]{2,}")
_PERCENT_U_RE = re.compile(r"%u([0-9a-fA-F]{4})")
_FILENAME_RE = re.compile(r'filename\s*=\s*"?([^";\r\n]{1,180})', re.IGNORECASE)
_NULL_RE = re.compile(r"%00|\x00")


def decode_multi(value: str, rounds: int = 3) -> str:
    """多轮 URL 解码，处理 %xx / %uXXXX / 双写编码（%2527 → %27 → '）。"""
    text = value or ""
    for _ in range(max(1, rounds)):
        text = _PERCENT_U_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text


def normalize(value: str) -> str:
    """归一化：解码 → HTML 实体 → 去空字节/控制符 → SQL 注释转空格 → 折叠空白 → 小写。"""
    if not value:
        return ""
    text = decode_multi(value)
    text = html.unescape(text)
    text = _NULL_RE.sub(" ", text)
    text = _CONTROL_RE.sub("", text)
    text = _SQL_COMMENT_RE.sub(" ", text)
    text = _SPACE_RE.sub(" ", text)
    return text.lower()


def safe_snippet(value: str, limit: int = MAX_SNIPPET) -> str:
    """告警证据里的片段做脱敏处理：去控制字符、折叠空白、截断。"""
    text = _CONTROL_RE.sub(" ", value or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def extract_filename(body: str, query: str) -> str:
    """从 multipart/表单中提取上传文件名（供文件上传类规则使用）。"""
    match = _FILENAME_RE.search(body or "")
    if match:
        return match.group(1).strip()
    match = re.search(r"(?:filename|file|uploadfile|upload_file|name)\s*=\s*([^&\s]{1,120})",
                      query or "", re.IGNORECASE)
    return match.group(1).strip() if match else ""


logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# 知识库
# --------------------------------------------------------------------------- #
class WebAttackKnowledgeBase:
    """加载并索引 ``web_attack_rules.json``（大类的 OWASP/CWE 信息也来自该文件）。

    v2 起额外支持两个"外部输入"，用于接入开源规则库（Sigma / Suricata-ET）与直达标记：

    * ``extra_rules``：外部规则（已转成知识库结构），只保留类别在知识库中已定义的条目；
    * ``direct_alert_ids``：需要标记为"直达"的规则 ID（来自 rules 注册表，加载期一次性注入，
      不修改磁盘上的知识库文件）。
    """

    def __init__(self, rules_path: Optional[Path] = None,
                 extra_rules: Optional[List[Dict[str, Any]]] = None,
                 direct_alert_ids: Optional[set] = None,
                 extra_categories: Optional[List[Dict[str, Any]]] = None,
                 tiers: Optional[List[str]] = None,
                 matcher_backend: str = "auto",
                 re2_max_mem_mb: int = 64,
                 max_rules: int = 10000,
                 reject_unknown_category: bool = True) -> None:
        self.rules_path = Path(rules_path) if rules_path else None
        self.extra_rules = list(extra_rules or [])
        self.direct_alert_ids = set(direct_alert_ids or set())
        self.extra_categories = list(extra_categories or [])
        self.tiers = [str(item).lower() for item in (tiers or ["core", "extended", "lab"])]
        self.matcher_backend = matcher_backend
        self.re2_max_mem_mb = int(re2_max_mem_mb)
        self.max_rules = max(100, int(max_rules))
        self.reject_unknown_category = bool(reject_unknown_category)
        self.version = "unknown"
        self.updated_at = ""
        self.description = ""
        self.field_help: Dict[str, str] = {}
        self.categories: List[Dict[str, Any]] = []
        self.rules: List[Dict[str, Any]] = []
        self.external_loaded = 0
        self.skipped_tier = 0
        self.skipped_unknown = 0
        self.skipped_invalid = 0
        self.duplicates = 0
        self._by_key: Dict[str, Dict[str, Any]] = {}
        self._by_category: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._compiled: Dict[str, Dict[str, Any]] = {}
        self._plans: List[RulePlan] = []
        self._plan_by_id: Dict[str, RulePlan] = {}
        self.matcher = build_matcher([], "python")
        self.build_ms = 0.0
        self.load()

    # ------------------------------------------------------------------ #
    def load(self) -> int:
        if self.rules_path is None or not self.rules_path.exists():
            logger.warning("Web 攻击知识库文件不存在: %s", self.rules_path)
            return 0
        try:
            payload = json.loads(self.rules_path.read_text(encoding="utf-8"))
        except Exception:
            logger.exception("加载 Web 攻击知识库失败")
            return 0

        self.version = payload.get("version", "unknown")
        self.updated_at = payload.get("updated_at", "")
        self.description = payload.get("description", "")
        self.field_help = payload.get("field_help", {}) or {}
        self.categories = payload.get("categories", []) or []
        self.rules = payload.get("rules", []) or []

        self._merge_categories()
        self._by_key = {str(item.get("key")): item for item in self.categories}
        self._by_category = defaultdict(list)
        self._compiled = {}
        for rule in self.rules:
            category = str(rule.get("category") or "")
            self._by_category[category].append(rule)
            self._compile(rule)
        self._merge_external()
        self._inject_direct_alert()
        self._prune_categories()
        self._build_matcher()
        logger.info("已加载 Web 攻击规则 %d 条 / %d 个大类（知识库版本 %s，外部合并 %d 条，"
                    "直达 %d 条，档位 %s，跳过 tier=%d unknown=%d dup=%d，后端 %s）",
                    len(self.rules), len(self.categories), self.version,
                    self.external_loaded, len(self._direct_ids()), ",".join(self.tiers),
                    self.skipped_tier, self.skipped_unknown, self.duplicates,
                    self.matcher.name)
        return len(self.rules)

    def _merge_categories(self) -> None:
        """合并规则包 taxonomy：必须先于规则合并，否则新增类别会被静默丢弃。"""
        if not self.extra_categories:
            return
        existing = {str(item.get("key")) for item in self.categories}
        added = 0
        for category in self.extra_categories:
            key = str(category.get("key") or "")
            if not key or key in existing:
                continue
            self.categories.append(dict(category))
            existing.add(key)
            added += 1
        if added:
            logger.info("规则包合并新增攻击类别 %d 个", added)

    def _prune_categories(self) -> None:
        """只保留实际有规则的类别，避免前端出现“0 条规则”的空分类。

        流级专属类别（DDoS/DNS 隧道/挖矿/C2 等）会在 P3 流级执行器启用后
        随其规则一起进入分类表；当前 Web 引擎不虚报覆盖。
        """
        used = {str(rule.get("category")) for rule in self.rules if rule.get("category")}
        kept = [item for item in self.categories if str(item.get("key")) in used]
        removed = len(self.categories) - len(kept)
        self.categories = kept
        self._by_key = {str(item.get("key")): item for item in self.categories}
        if removed:
            logger.info("已隐藏 %d 个当前无规则的类别（多为流级专属，待 P3 启用）", removed)

    # ------------------------------------------------------------------ #
    # 外部规则合并（Sigma / ET）与直达标记注入
    # ------------------------------------------------------------------ #
    def _compile(self, rule: Dict[str, Any]) -> bool:
        """编译单条规则的正则；失败时返回 False（该规则不会参与匹配）。"""
        try:
            self._compiled[str(rule.get("id"))] = {
                "patterns": [re.compile(p, re.IGNORECASE) for p in rule.get("patterns", []) or []],
                "excludes": [re.compile(p, re.IGNORECASE)
                             for p in rule.get("exclude_patterns", []) or []],
            }
            return True
        except re.error:
            logger.exception("规则正则编译失败，已跳过：%s", rule.get("id"))
            return False

    def _merge_external(self) -> None:
        """合并规则包 / Sigma / ET：类别必须先定义，按档位过滤，按 pattern 精确去重。"""
        self.external_loaded = 0
        if not self.extra_rules:
            return
        existing = {str(rule.get("id")) for rule in self.rules}
        signatures = {
            frozenset(str(item).lower() for item in (rule.get("patterns") or []))
            for rule in self.rules if rule.get("patterns")
        }
        for raw in self.extra_rules:
            if not isinstance(raw, dict):
                self.skipped_invalid += 1
                continue
            if len(self.rules) >= self.max_rules:
                logger.warning("Web 规则数达到上限 %d，停止合并外部规则", self.max_rules)
                break
            rule = dict(raw)
            rule_id = str(rule.get("id") or "")
            category = str(rule.get("category") or "")
            tier = str(rule.get("tier") or "").lower()
            if not rule_id:
                self.skipped_invalid += 1
                continue
            if rule_id in existing:
                self.duplicates += 1
                continue
            if tier and tier not in self.tiers:
                self.skipped_tier += 1
                continue
            if category not in self._by_key:
                self.skipped_unknown += 1
                message = "规则 %s 的类别 %s 未定义，已跳过" % (rule_id, category)
                if self.reject_unknown_category:
                    logger.error(message)
                else:
                    logger.warning(message)
                continue
            signature = frozenset(str(item).lower() for item in (rule.get("patterns") or []))
            if not signature:
                self.skipped_invalid += 1
                continue
            if signature in signatures:
                self.duplicates += 1
                continue
            if not self._compile(rule):
                self.skipped_invalid += 1
                continue
            if not rule.get("references"):
                rule["references"] = [str(self._by_key[category].get("reference") or
                                           "https://owasp.org/Top10/")]
            self.rules.append(rule)
            self._by_category[category].append(rule)
            existing.add(rule_id)
            signatures.add(signature)
            self.external_loaded += 1

    def _build_matcher(self) -> None:
        """RulePlan 预编译 + 可选 RE2 索引（在规则合并、直达标记注入之后执行）。"""
        started = time.perf_counter()
        plans: List[RulePlan] = []
        for rule in self.rules:
            plan = compile_plan(len(plans), rule)
            if plan is None:
                self.skipped_invalid += 1
                logger.error("规则编译失败（无有效 pattern 或正则非法）：%s", rule.get("id"))
                continue
            plans.append(plan)
        self._plans = plans
        self._plan_by_id = {plan.rule_id: plan for plan in plans}
        self.matcher = build_matcher(plans, self.matcher_backend, self.re2_max_mem_mb)
        self.build_ms = round((time.perf_counter() - started) * 1000, 2)

    def candidates(self, targets: Dict[str, Dict[str, str]]) -> Optional[bytearray]:
        return self.matcher.candidates(targets)

    def plan(self, rule_id: str) -> Optional[RulePlan]:
        return self._plan_by_id.get(str(rule_id or ""))

    def _inject_direct_alert(self) -> None:
        """在内存里给规则打直达标记（磁盘文件保持原样，运维无需理解直达语义）。"""
        if not self.direct_alert_ids:
            return
        for rule in self.rules:
            if str(rule.get("id")) in self.direct_alert_ids:
                rule["direct_alert"] = True

    def _direct_ids(self) -> set:
        return {str(rule.get("id")) for rule in self.rules if rule.get("direct_alert")}

    # ------------------------------------------------------------------ #
    @property
    def loaded(self) -> bool:
        return bool(self.rules)

    def category(self, key: str) -> Dict[str, Any]:
        return self._by_key.get(key, {})

    def category_name(self, key: str) -> str:
        return str(self.category(key).get("name") or key)

    def severity_of(self, rule: Dict[str, Any]) -> str:
        return str(rule.get("severity") or self.category(str(rule.get("category"))).get("severity")
                   or "medium")

    def rules_of(self, key: str) -> List[Dict[str, Any]]:
        return list(self._by_category.get(key, []))

    def public_rules(self) -> List[Dict[str, Any]]:
        """面向前端 / API 的规则清单（保留展示与说明所需字段）。"""
        rows: List[Dict[str, Any]] = []
        for rule in self.rules:
            category = self.category(str(rule.get("category")))
            rows.append({
                "id": rule.get("id"),
                "category": rule.get("category"),
                "category_name": category.get("name"),
                "title": rule.get("title"),
                "severity": self.severity_of(rule),
                "cvss": rule.get("cvss"),
                "confidence": rule.get("confidence"),
                "cwe": category.get("cwe"),
                "owasp": category.get("owasp"),
                "match_targets": rule.get("match_targets"),
                "pattern_count": len(rule.get("patterns") or []),
                "threshold": rule.get("threshold"),
                "remediation": rule.get("remediation"),
                "examples": rule.get("examples") or [],
                "direct_alert": bool(rule.get("direct_alert")),
                "source": str(rule.get("rule_source") or "native"),
                "tier": str(rule.get("tier") or ""),
            })
        return rows

    def public_categories(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for category in self.categories:
            key = str(category.get("key"))
            rows.append({**category, "rule_count": len(self._by_category.get(key, []))})
        return rows

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "updated_at": self.updated_at,
            "rules": len(self.rules),
            "categories": len(self.categories),
            "by_category": {str(c.get("key")): len(self._by_category.get(str(c.get("key")), []))
                            for c in self.categories},
            "by_tier": dict(Counter(str(rule.get("tier") or "builtin") for rule in self.rules)),
            "external_rules": self.external_loaded,
            "direct_alert_rules": len(self._direct_ids()),
            "tiers_enabled": list(self.tiers),
            "skipped_tier": self.skipped_tier,
            "skipped_unknown": self.skipped_unknown,
            "skipped_invalid": self.skipped_invalid,
            "duplicates": self.duplicates,
            "matcher": {**self.matcher.stats(), "build_ms": self.build_ms,
                        "plans": len(self._plans)},
            "path": str(self.rules_path or ""),
            "description": self.description,
        }

    def compiled(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return self._compiled.get(rule_id)


def _registry_inputs(settings: Settings) -> Tuple[List[Dict[str, Any]], set]:
    """从统一规则层取（外部规则, 直达规则 ID）。

    规则层异常时安全降级为"仅内置知识库"，保证 Web 检测链路始终可用；
    降级事实会写日志，且 `/rules/sources`、`/web/stats` 都能看到各来源的实际加载量。
    """
    try:
        from ..rules import get_registry

        registry = get_registry(settings)
        return registry.extras_for_web(), registry.direct_alert_ids
    except Exception:      # pragma: no cover - 防御性
        logger.exception("规则层加载失败，Web 检测回落为仅内置知识库")
        return [], set()


def _strict_inputs(settings: Settings) -> Tuple[List[Dict[str, Any]], set]:
    """读取"高置信度直达规则"（不限路径，只看载荷本身）。

    这类规则用于自动封禁的判定：只有明确的高危载荷（UNION SELECT、命令拼接执行、
    路径穿越读取系统文件等）才标记 ``direct_alert``，避免签名类规则误报导致误封。
    文件缺失时静默跳过，内置知识库与规则包照常工作。
    """
    path = settings.web_strict_rules_path
    if not path.exists():
        return [], set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("高置信度规则加载失败（已跳过）：%s", path)
        return [], set()
    rules: List[Dict[str, Any]] = []
    for raw in payload.get("rules", []) or []:
        if not isinstance(raw, dict) or not raw.get("id") or not raw.get("patterns"):
            continue
        rule = dict(raw)
        rule.setdefault("rule_source", "strict")
        rule.setdefault("direct_alert", False)
        rules.append(rule)
    direct = {str(rule.get("id")) for rule in rules if rule.get("direct_alert")}
    logger.info("高置信度直达规则已加载：%d 条（直达 %d 条）", len(rules), len(direct))
    return rules, direct


def _parse_ignored_sources(values) -> Tuple[set, list]:
    """解析 WEB_IGNORE_IPS：支持单 IP 与 CIDR（用于抑制传感器自访问误报）。"""
    ips, networks = set(), []
    for item in values or []:
        text = str(item or "").strip()
        if not text:
            continue
        try:
            if "/" in text:
                networks.append(ipaddress.ip_network(text, strict=False))
            else:
                ips.add(str(ipaddress.ip_address(text)))
        except ValueError:
            logger.warning("忽略非法的 WEB_IGNORE_IPS 项：%s", text)
    return ips, networks


# --------------------------------------------------------------------------- #
# 检测器
# --------------------------------------------------------------------------- #
class WebAttackDetector:
    """按知识库规则检测 Web 攻击：输入 ``WebRequestEvent``，输出 ``Anomaly`` 列表。

    * 规则匹配是纯函数式的（同一请求可命中多类）；
    * 频次类规则（暴力破解 / CSRF / 验证码）先累计窗口内次数，达标才告警；
    * 同一 (大类, 源 IP) 在冷却窗口内只告警一次，避免告警风暴。
    """

    def __init__(self, settings: Optional[Settings] = None,
                 knowledge_base: Optional[WebAttackKnowledgeBase] = None) -> None:
        self.settings = settings or get_settings()
        self._kb_lock = threading.RLock()
        if knowledge_base is not None:
            self.kb = knowledge_base
        else:
            from .kb_factory import build_web_kb

            self.kb = build_web_kb(self.settings)
        self._ignored_ips, self._ignored_networks = _parse_ignored_sources(
            getattr(self.settings, "web_ignore_ips", None))
        self.analyzed = 0
        self.hits_total = 0
        self.alerts_total = 0
        self.suppressed = 0
        self.last_hit_at = 0.0
        self.by_category: Counter = Counter()
        self.by_severity: Counter = Counter()
        self.counters: Counter = Counter()
        self._windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._cooldowns: Dict[Tuple[str, str], float] = {}

    # ------------------------------------------------------------------ #
    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self.settings.web_detect_enabled),
            "source": self.settings.web_detect_source,
            "ignored_sources": int(self.counters.get("ignored_source", 0)),
            "analyzed_requests": self.analyzed,
            "matched_hits": self.hits_total,
            "alerts_emitted": self.alerts_total,
            "suppressed": self.suppressed,
            "last_hit_at": self.last_hit_at,
            "categories": dict(self.by_category),
            "severity": dict(self.by_severity),
            "counters": dict(self.counters),
            "window_keys": len(self._windows),
            "cooldown_sec": int(self.settings.alert_cooldown_sec),
            "kb": self.kb.stats,
        }

    def reset(self) -> None:
        self.__init__(self.settings, self.kb)

    def reload_kb(self, registry=None) -> WebAttackKnowledgeBase:
        """构建新知识库后原子替换引用；失败保留旧对象（不进入半可用状态）。"""
        from .kb_factory import build_web_kb

        kb = build_web_kb(self.settings, registry=registry)
        with self._kb_lock:
            self.kb = kb
        return kb

    # ------------------------------------------------------------------ #
    # 字段提取
    # ------------------------------------------------------------------ #
    def build_targets(self, event: WebRequestEvent) -> Dict[str, Dict[str, str]]:
        """把请求拆成可匹配字段，并给出「原始 raw / 归一化 text」两种形态。"""
        headers = "\n".join(f"{key}: {value}" for key, value in (event.headers or {}).items())
        blobs = {
            "path": event.path or "/",
            "query": event.query or "",
            "body": event.body or "",
            "header": headers,
            "cookie": event.header("cookie"),
            "user_agent": event.header("user-agent"),
            "referer": event.header("referer"),
            "filename": extract_filename(event.body, event.query),
        }
        blobs["any"] = "\n".join([event.request_line, *blobs.values()])
        return {name: {"raw": value, "text": normalize(value)} for name, value in blobs.items()}

    @staticmethod
    def _method_ok(rule: Dict[str, Any], event: WebRequestEvent) -> bool:
        methods = rule.get("method_in")
        if methods and str(event.method or "").upper() not in {str(m).upper() for m in methods}:
            return False
        statuses = rule.get("status_in")
        if statuses and int(event.status or 0) not in {int(s) for s in statuses}:
            return False
        return True

    @staticmethod
    def _absent_ok(rule: Dict[str, Any], event: WebRequestEvent) -> bool:
        """``require_absent``：声明的请求头必须缺失/为空（如 CSRF 检查 Origin/Referer）。"""
        for name in rule.get("require_absent") or []:
            if str(event.header(str(name)) or "").strip():
                return False
        return True

    def _ignored_source(self, source_ip: str) -> bool:
        """WEB_IGNORE_IPS 命中即跳过检测（传感器/管理机/靶场主机自访问防误报）。"""
        text = str(source_ip or "").strip()
        if not text:
            return False
        if text in self._ignored_ips:
            return True
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        return any(address in network for network in self._ignored_networks)

    def is_ignored_source(self, source_ip: str) -> bool:
        """公开入口：供服务层在自动封禁前做二次防误封校验。"""
        return self._ignored_source(source_ip)

    @staticmethod
    def _search(pattern: "re.Pattern[str]", targets: Dict[str, Dict[str, str]],
                names: Sequence[str], mode: str) -> Optional[Tuple[str, str, "re.Match[str]"]]:
        """在指定字段中查找正则；返回 (字段名, 文本, 匹配对象)。"""
        for name in names:
            entry = targets.get(name)
            if not entry:
                continue
            variants: List[str] = []
            if mode in ("normalized", "both"):
                variants.append(entry["text"])
            if mode in ("raw", "both"):
                variants.append(entry["raw"])
            for text in variants:
                if not text:
                    continue
                match = pattern.search(text)
                if match:
                    return name, text, match
        return None

    # ------------------------------------------------------------------ #
    # 频次阈值（暴力破解 / CSRF / 验证码等）
    # ------------------------------------------------------------------ #
    def _required_count(self, rule: Dict[str, Any]) -> Tuple[int, int]:
        """返回 (需要达到的命中次数, 统计窗口秒数)；无 threshold 时返回 (1, 0)。"""
        threshold = rule.get("threshold") or {}
        required = int(threshold.get("count") or 1)
        window_sec = int(threshold.get("window_sec") or 60)
        if str(rule.get("category")) == "brute_force":
            override = int(self.settings.web_brute_force_attempts or 0)
            if override > 0:
                required = override
        return max(1, required), max(1, window_sec)

    def _window_count(self, rule_id: str, src_ip: str, window_sec: int, now: float) -> int:
        """把本次命中计入滑动窗口并返回窗口内累计次数。"""
        bucket = self._windows[(rule_id, src_ip or "-")]
        cutoff = now - window_sec
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(now)
        return len(bucket)

    def _is_excluded(self, patterns: Sequence["re.Pattern[str]"],
                     targets: Dict[str, Dict[str, str]], mode: str) -> bool:
        """误报抑制：任意字段命中任一 exclude_patterns 即丢弃该规则。"""
        for pattern in patterns:
            if self._search(pattern, targets, ["any"], "both" if mode == "both" else mode):
                return True
        return False

    @staticmethod
    def _targets_empty(targets: Dict[str, Dict[str, str]], names: Sequence[str]) -> bool:
        """字段掩码：规则声明的字段全为空时整条跳过（GET 可跳过 body-only 规则）。"""
        for name in names:
            entry = targets.get(name) or {}
            if entry.get("text") or entry.get("raw"):
                return False
        return True

    # ------------------------------------------------------------------ #
    # 规则匹配
    # ------------------------------------------------------------------ #
    def inspect(self, event: WebRequestEvent, now: Optional[float] = None) -> List[WebAttackHit]:
        """对单条请求执行规则匹配；返回命中列表（含仍处于阈值累计中的状态计数）。"""
        kb = self.kb                    # 取一次快照：热加载期间本次检测不受影响
        if not kb.loaded:
            return []
        if self._ignored_source(event.src_ip):
            self.counters["ignored_source"] += 1
            return []
        moment = float(now or event.ts or time.time())
        targets = self.build_targets(event)
        candidates = kb.candidates(targets)
        hits: List[WebAttackHit] = []

        for index, rule in enumerate(kb.rules):
            plan = kb.plan(str(rule.get("id")))
            if plan is None:
                continue
            if candidates is not None and plan.idx < len(candidates) and not candidates[plan.idx]:
                continue
            if plan.methods and str(event.method or "").upper() not in plan.methods:
                continue
            if plan.statuses and int(event.status or 0) not in plan.statuses:
                continue
            if not self._absent_ok(rule, event):
                continue
            if plan.path_re and not plan.path_re.search(event.path or ""):
                continue
            if plan.path_not_re and plan.path_not_re.search(event.path or ""):
                continue
            names = plan.targets or DEFAULT_TARGETS
            if self._targets_empty(targets, names):
                continue

            matched: List[Tuple[str, str, str]] = []       # (正则, 字段, 片段)
            for pattern in plan.patterns:
                found = self._search(pattern, targets, names, plan.match_mode)
                if found:
                    matched.append((pattern.pattern, found[0], safe_snippet(found[2].group(0))))
                    if not plan.match_all:
                        break
            if not matched:
                continue
            if plan.match_all and len(matched) < len(plan.patterns):
                continue
            # exclude 延迟到 pattern 命中之后再跑（大多数请求根本走不到这里）
            if plan.excludes and self._is_excluded(plan.excludes, targets, plan.match_mode):
                self.counters["excluded"] += 1
                continue

            required, window_sec = self._required_count(rule)
            count = 0
            if required > 1:
                count = self._window_count(str(rule.get("id")), event.src_ip, window_sec, moment)
                if count < required:
                    self.counters["threshold_pending"] += 1
                    continue

            category = str(rule.get("category"))
            meta = kb.category(category)
            hits.append(WebAttackHit(
                rule_id=str(rule.get("id")),
                category=category,
                category_name=self.kb.category_name(category),
                title=str(rule.get("title") or ""),
                severity=self.kb.severity_of(rule),
                cvss=float(rule.get("cvss") or 0.0),
                confidence=str(rule.get("confidence") or "medium"),
                cwe=str(meta.get("cwe") or ""),
                owasp=str(meta.get("owasp") or ""),
                target=matched[0][1],
                snippet=matched[0][2],
                remediation=str(rule.get("remediation") or ""),
                references=list(rule.get("references") or []),
                false_positive_hint=str(rule.get("false_positive_hint") or ""),
                threshold_count=count,
                window_sec=window_sec if required > 1 else 0,
                matched_pattern=matched[0][0],
                rule_source=str(rule.get("rule_source") or "native"),
                direct_alert=bool(rule.get("direct_alert")),
                tier=str(rule.get("tier") or ""),
            ))
        return hits

    # ------------------------------------------------------------------ #
    # 告警生成（分类聚合 + 组合提级 + 冷却抑制）
    # ------------------------------------------------------------------ #
    def evaluate(self, event: WebRequestEvent, now: Optional[float] = None) -> List[Anomaly]:
        if not self.settings.web_detect_enabled:
            return []
        moment = float(now or event.ts or time.time())
        self.analyzed += 1
        hits = self.inspect(event, moment)
        if not hits:
            return []

        self.hits_total += len(hits)
        self.last_hit_at = moment
        grouped: Dict[str, List[WebAttackHit]] = defaultdict(list)
        for hit in hits:
            grouped[hit.category].append(hit)
        combined = len(grouped) > 1

        anomalies: List[Anomaly] = []
        for category, group in grouped.items():
            cooldown_key = (category, event.src_ip or "-")
            if moment - self._cooldowns.get(cooldown_key, 0.0) < max(1, int(self.settings.alert_cooldown_sec)):
                self.suppressed += 1
                self.counters["suppressed"] += 1
                continue
            self._cooldowns[cooldown_key] = moment

            severity = max((hit.severity for hit in group),
                           key=lambda item: SEVERITY_ORDER.get(item, 0))
            if combined:      # 同一请求命中多类 → 提级（组合攻击更危险）
                severity = SEVERITY_BY_ORDER.get(min(4, SEVERITY_ORDER.get(severity, 2) + 1), severity)
            top = max(group, key=lambda hit: CONFIDENCE_SCORE.get(hit.confidence, 0.6))
            score = CONFIDENCE_SCORE.get(top.confidence, 0.6) + (0.05 if combined else 0.0)
            # 直达标记：本组内任一命中规则为"直达规则"即视为直达（致命攻击不参与聚合投票）
            direct = any(hit.direct_alert for hit in group)
            rule_sources = sorted({hit.rule_source for hit in group})

            category_name = self.kb.category_name(category)
            meta = self.kb.category(category)
            rule_ids = [hit.rule_id for hit in group]
            source = f"源 {event.src_ip} " if event.src_ip else ""
            message = (f"{source}{event.method} {safe_snippet(event.url, 80)} 命中「{category_name}」"
                       f"（{len(group)} 条规则：{','.join(rule_ids)}）")
            if top.threshold_count > 1:
                message += f"，{top.window_sec}s 内累计 {top.threshold_count} 次"
            if combined:
                message += f"，且同时命中 {len(grouped)} 类攻击（组合攻击）"
            message += f"；命中片段：{group[0].snippet}"

            anomaly = Anomaly(
                category=f"web_{category}",
                severity=severity,
                score=round(min(1.0, score), 3),
                message=message,
                source_ip=event.src_ip or "",
                dest_ip=event.dst_ip or "",
                dest_port=int(event.dst_port or 0),
                protocol=event.proto or "TCP",
                detector="web-kb",
                evidence=self._evidence(event, category, category_name, meta, group,
                                        combined, grouped, direct),
                rule_id=top.rule_id,
                confidence=top.confidence,
                direct_alert=direct,
                rule_source=rule_sources[0] if len(rule_sources) == 1 else "mixed",
            )
            anomalies.append(anomaly)
            self.alerts_total += 1
            self.by_category[category] += 1
            self.by_severity[severity] += 1

        if len(self._cooldowns) > 4096:      # 定期清理过期冷却键
            cutoff = moment - max(1, int(self.settings.alert_cooldown_sec)) * 4
            self._cooldowns = {key: value for key, value in self._cooldowns.items() if value >= cutoff}
        return anomalies

    def _request_snapshot(self, event: WebRequestEvent) -> Dict[str, Any]:
        """生成可落库的请求快照（L0=日志元数据 / L1=含完整请求头体）。"""
        limit = int(getattr(self.settings, "threat_request_max_bytes", 16384))
        headers: List[str] = []
        for key, value in (event.headers or {}).items():
            name = str(key or "")
            if name.lower() in {"cookie", "authorization", "proxy-authorization"}:
                value = "[已脱敏]"
            headers.append(f"{name}: {value}")
        request_line = event.request_line
        host = event.header("host")
        lines = [request_line]
        if host:
            lines.append(f"Host: {host}")
        lines.extend(headers)
        head = "\n".join(lines)
        body = str(event.body or "")
        if len(body.encode("utf-8", errors="ignore")) > limit:
            body = body.encode("utf-8", errors="ignore")[:limit].decode("utf-8", errors="ignore")
            body += "\n…[已截断]"
        return {
            "method": event.method,
            "path": event.path,
            "query": event.query,
            "host": host,
            "head": head,
            "body": body,
            "status": event.status,
            "src_ip": event.src_ip,
            "src_port": event.src_port,
            "dst_ip": event.dst_ip,
            "dst_port": event.dst_port,
            "content_type": event.header("content-type"),
            "user_agent": event.header("user-agent"),
            "referer": event.header("referer"),
            "source": event.source,
            "iface": event.iface,
            "capture_level": "L1" if body or event.source in {"api", "proxy"} else "L0",
        }

    def _evidence(self, event: WebRequestEvent, category: str, category_name: str,
                  meta: Dict[str, Any], group: Sequence[WebAttackHit], combined: bool,
                  grouped: Dict[str, List[WebAttackHit]], direct: bool = False) -> Dict[str, Any]:
        """组装告警证据（规则命中明细 + 请求摘要 + 处置建议，供页面与审计直读）。"""
        peak = max(group, key=lambda hit: hit.threshold_count)
        return {
            "rule_ids": [hit.rule_id for hit in group],
            "rules": [{"id": hit.rule_id, "title": hit.title, "severity": hit.severity,
                       "confidence": hit.confidence, "target": hit.target, "snippet": hit.snippet,
                       "pattern": hit.matched_pattern, "cvss": hit.cvss,
                       "source": hit.rule_source, "direct_alert": hit.direct_alert}
                      for hit in group],
            "rule_sources": sorted({hit.rule_source for hit in group}),
            "direct_alert": direct,
            "tier": str(peak.tier or ""),
            "category": category,
            "category_name": category_name,
            "cwe": meta.get("cwe"),
            "owasp": meta.get("owasp"),
            "cvss": max((hit.cvss for hit in group), default=0.0),
            "confidence": max(group, key=lambda hit: CONFIDENCE_SCORE.get(hit.confidence, 0.6)).confidence,
            "matched_targets": sorted({hit.target for hit in group}),
            "snippets": [hit.snippet for hit in group][:5],
            "threshold": {"window_sec": peak.window_sec, "count": peak.threshold_count}
                         if peak.threshold_count > 1 else None,
            "combination_attack": combined,
            "categories_hit": sorted(grouped.keys()),
            "remediation": group[0].remediation,
            "references": group[0].references,
            "false_positive_hint": group[0].false_positive_hint,
            "request": self._request_snapshot(event),
            "response": self._response_snapshot(event),
            "kb_version": self.kb.version,
        }

    def _response_snapshot(self, event: WebRequestEvent) -> Dict[str, str]:
        """生成可落库的响应快照（仅文本类响应含 body；敏感头脱敏；截断到留存上限）。"""
        limit = int(getattr(self.settings, "threat_response_max_bytes", 8192))
        head = str(event.response_head or "")
        body = str(event.response_body or "")
        if head:
            # 兜底脱敏：上游未处理的 Set-Cookie / Authorization 等敏感头
            head = re.sub(r"(?im)^((?:set-cookie|cookie|authorization|proxy-authorization)"
                          r"|www-authenticate):\s*(.{0,64})(?:;.*)?$",
                          r"\1: \2[已脱敏]", head)
        return {
            "head": self._clip(head, limit),
            "body": self._clip(body, limit),
        }

    @staticmethod
    def _clip(text: str, limit: int) -> str:
        data = text.encode("utf-8", errors="ignore")
        if len(data) <= limit:
            return text
        return data[:limit].decode("utf-8", errors="ignore") + "\n…[已截断]"

    # ------------------------------------------------------------------ #
    # 便捷入口（供 API / 服务层复用）
    # ------------------------------------------------------------------ #
    def inspect_dict(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """对 API 投递的请求做「只检测、不告警」的体检（规则自测 / 第三方 WAF 联调）。"""
        event = WebRequestEvent.from_dict(payload)
        hits = self.inspect(event)
        return {
            "event": event.to_dict(),
            "hits": [hit.to_dict() for hit in hits],
            "hit_count": len(hits),
            "categories": sorted({hit.category for hit in hits}),
            "kb_version": self.kb.version,
        }

    def ingest(self, payload: Dict[str, Any], now: Optional[float] = None) -> List[Anomaly]:
        """外部投递路径：解析请求体 → 检测 → 返回告警（服务层负责落库/封禁/推送）。"""
        event = WebRequestEvent.from_dict(payload)
        event.source = event.source or "api"
        return self.evaluate(event, now)
