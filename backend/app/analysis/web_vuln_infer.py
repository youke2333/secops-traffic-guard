"""攻击流量证据 → 漏洞判定（规则打底 + AI 复核）。

为什么需要这一层：
    主动漏扫只能看到「端口 / 版本 / 配置 / 暴露面」，看不到应用逻辑里的注入点。
    真正能证明"这台机器的这个服务存在命令注入"的，是我们自己捕获到的
    **攻击请求 + 目标响应**：请求里有载荷，响应里回显了命令结果。

设计要点：
1. 通用性：漏洞名称只取自下面的 ``VULN_CLASS``（命令注入 / SQL 注入 / 目录穿越 …），
   **不掺任何靶场、产品、站点名**。模型只回答"是否成立"，不给漏洞起名，
   避免出现"某某平台的命令注入"这类牌子化措辞。
2. 证据优先：判定以响应为依据（SQL 报错、命令回显、被包含文件的特征行、载荷原样反射）。
   没有响应包时只能给"疑似"，绝不编造"确认"。
3. AI 可选：``llm_enabled`` + API Key 都就绪时才请求模型复核；不可用时静默降级为规则判定，
   并在证据里标注研判来源，前端据此显示「AI 复核 / 规则研判」。
4. 隐私：发给模型的只有脱敏后的请求/响应摘要（内网 IP 段位、Cookie/Authorization 已脱敏），
   超长内容截断，且不发送源 IP。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import select

from ..config import Settings, get_settings
from ..database import session_scope
from ..models import Asset, ThreatEvent
from ..timeutil import iso_local
from .llm_client import DeepSeekClient, LLMUnavailable
from .prompts import mask_ip

logger = logging.getLogger(__name__)

# 研判结论
CONFIRMED = "confirmed"
SUSPECTED = "suspected"
DISMISSED = "dismissed"

# 研判来源（写入 vulnerabilities.source / confidence）
SOURCE_TRAFFIC_AI = "traffic_ai"
SOURCE_TRAFFIC_RULE = "traffic_rule"

# 单条事件送模型的字符上限
MAX_REQUEST_CHARS = 1200
MAX_RESPONSE_CHARS = 1200

# --------------------------------------------------------------------------- #
# 通用漏洞类型表（category → 通用名称 / CWE / 基础评级 / 修复要点）
# 名称刻意保持"技术类型"粒度：命令注入、SQL 注入、目录穿越……
# 这样同一类漏洞在任何业务系统上都叫同一个名字，不绑定具体产品或靶场。
# --------------------------------------------------------------------------- #
VULN_CLASS: Dict[str, Dict[str, Any]] = {
    "web_sql_injection": {
        "title": "SQL 注入", "cwe": "CWE-89", "severity": "critical", "cvss": 9.1,
        "recommendation": "对全部数据库访问改用参数化查询/预编译语句；收敛数据库账号权限；"
                          "在网关层对注入特征做拦截并留存原始请求以备取证。",
    },
    "web_sql_injection_blind": {
        "title": "SQL 盲注", "cwe": "CWE-89", "severity": "critical", "cvss": 8.6,
        "recommendation": "改用参数化查询；对同一来源的相似请求做频次限制；"
                          "核对数据库慢查询与异常出网行为，确认是否已被拖库。",
    },
    "web_command_injection": {
        "title": "命令注入", "cwe": "CWE-78", "severity": "critical", "cvss": 9.8,
        "recommendation": "禁止把外部输入拼进系统命令，改用参数化调用（如 exec 数组形式）；"
                          "以最小权限运行应用进程；对已确认回显的主机立即隔离取证。",
    },
    "web_file_inclusion": {
        "title": "文件包含", "cwe": "CWE-98", "severity": "critical", "cvss": 8.8,
        "recommendation": "包含路径改为白名单枚举，禁止由请求参数决定文件名；"
                          "关闭 allow_url_include，限制可包含目录。",
    },
    "web_file_upload": {
        "title": "任意文件上传", "cwe": "CWE-434", "severity": "critical", "cvss": 9.0,
        "recommendation": "服务端校验文件类型与内容（不只信扩展名/MIME）；上传目录禁止执行脚本；"
                          "文件重命名并落到独立域名/存储上。",
    },
    "web_path_traversal": {
        "title": "目录穿越", "cwe": "CWE-22", "severity": "high", "cvss": 7.5,
        "recommendation": "对文件名做规范化后校验是否仍在允许目录内；拒绝含 .. / 绝对路径的输入。",
    },
    "web_xss_reflected": {
        "title": "反射型 XSS", "cwe": "CWE-79", "severity": "high", "cvss": 6.1,
        "recommendation": "输出按上下文做 HTML/属性/JS 转义；配置 CSP；对回显参数做长度与字符白名单。",
    },
    "web_xss_stored": {
        "title": "存储型 XSS", "cwe": "CWE-79", "severity": "high", "cvss": 7.2,
        "recommendation": "入库前做输入校验、出库时按上下文转义；富文本用白名单过滤；配置 CSP。",
    },
    "web_ssrf": {
        "title": "服务端请求伪造", "cwe": "CWE-918", "severity": "high", "cvss": 7.7,
        "recommendation": "对外部可控 URL 做协议/域名白名单；禁止访问内网段与元数据地址；限制重定向跳数。",
    },
    "web_xxe": {
        "title": "XML 外部实体注入", "cwe": "CWE-611", "severity": "high", "cvss": 7.5,
        "recommendation": "解析 XML 时禁用外部实体与 DTD；优先改用 JSON。",
    },
    "web_ssti": {
        "title": "服务端模板注入", "cwe": "CWE-1336", "severity": "critical", "cvss": 9.0,
        "recommendation": "模板内容不得由用户输入拼装；改用沙箱化模板引擎并限制可用对象。",
    },
    "web_ldap_nosql_injection": {
        "title": "LDAP/NoSQL 注入", "cwe": "CWE-90", "severity": "high", "cvss": 7.3,
        "recommendation": "查询条件做严格类型校验与转义，禁止把请求参数直接拼进查询文档/过滤器。",
    },
    "web_crlf_injection": {
        "title": "CRLF 注入", "cwe": "CWE-93", "severity": "medium", "cvss": 5.0,
        "recommendation": "回写响应头前过滤 \\r\\n 等控制字符；使用框架提供的安全响应头接口。",
    },
    "web_csrf": {
        "title": "跨站请求伪造", "cwe": "CWE-352", "severity": "high", "cvss": 6.5,
        "recommendation": "所有写操作校验 CSRF Token / SameSite Cookie / Origin；"
                          "敏感操作要求二次确认。",
    },
    "web_brute_force": {
        "title": "认证暴力破解", "cwe": "CWE-307", "severity": "high", "cvss": 7.0,
        "recommendation": "增加登录失败次数限制与锁定；启用验证码/MFA；对来源 IP 做封禁与告警。",
    },
    "web_insecure_captcha": {
        "title": "验证码可绕过", "cwe": "CWE-804", "severity": "medium", "cvss": 5.3,
        "recommendation": "验证码改为服务端一次性校验并绑定会话；不返回明文答案；失败即失效。",
    },
    "web_webshell": {
        "title": "Webshell 访问", "cwe": "CWE-506", "severity": "critical", "cvss": 9.8,
        "recommendation": "立即隔离主机取证：定位并清除后门文件、检查进程与外联；"
                          "排查上传点与文件写权限，修复后再恢复服务。",
    },
}

# --------------------------------------------------------------------------- #
# 响应侧证据特征（只在"响应确实回到了攻击者"时才有意义）
# --------------------------------------------------------------------------- #
RE_SQL_ERROR = re.compile(
    r"(you have an error in your sql syntax|sqlstate\[|ora-\d{5}|pg_query\(\)|"
    r"unclosed quotation mark|warning:\s*mysql|sqlite3?\.(?:operational)?error|"
    r"system\.data\.sqlclient|microsoft ole db provider for sql server)", re.I)
RE_SHELL_OUT = re.compile(
    r"(uid=\d+\([\w-]+\)|gid=\d+\([\w-]+\)|groups=\d+\(|root:x:0:0|"
    r"nt authority\\system|volume in drive [a-z]|directory of [a-z]:\\|"
    r"/bin/(?:ba|da)?sh|command not found|sh: \d+: )", re.I)
RE_LFI_OUT = re.compile(r"(root:x:0:0|\[boot loader\]|; for 16-bit app support|\[fonts\])", re.I)
RE_BLOCKED = re.compile(
    r"(request rejected|blocked by|access denied|not acceptable|"
    r"web application firewall|安全策略|请求被拦截|拦截|拒绝访问)", re.I)
RE_SCRIPT_TAG = re.compile(r"(<script[^>]*>|onerror\s*=|onload\s*=|javascript:)", re.I)


@dataclass
class Evidence:
    """一条 Web 攻击事件中与"漏洞是否成立"相关的字段。"""

    event_id: int
    ts: Any
    asset_ip: str
    port: int
    method: str
    path: str
    query: str
    status: int
    category: str
    request_body: str = ""
    response_head: str = ""
    response_body: str = ""

    @property
    def has_response(self) -> bool:
        return bool(self.response_head or self.response_body)

    @property
    def target(self) -> str:
        path = (self.path or "/").split("?")[0][:160]
        return f"{self.method or 'GET'} {path}"


@dataclass
class Judgement:
    verdict: str
    rationale: str
    snippet: str = ""
    judged_by: str = "rule"      # rule | ai
    confidence: float = 0.0
    details: List[str] = field(default_factory=list)


@dataclass
class InferredVuln:
    """一条由流量证据推出的漏洞（落库前的中间态）。"""

    asset_ip: str
    port: int
    service: str
    category: str
    title: str
    cwe: str
    severity: str
    cvss: float
    recommendation: str
    confidence: str              # confirmed | suspected
    judged_by: str
    evidence: str
    event_ids: List[int] = field(default_factory=list)
    found_at: Any = None

    @property
    def source(self) -> str:
        return SOURCE_TRAFFIC_AI if self.judged_by == "ai" else SOURCE_TRAFFIC_RULE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_ip": self.asset_ip, "port": self.port, "service": self.service,
            "category": self.category, "title": self.title, "cve": self.cwe,
            "severity": self.severity, "cvss": self.cvss,
            "recommendation": self.recommendation,
            "confidence": self.confidence, "judged_by": self.judged_by,
            "source": self.source, "evidence": self.evidence,
            "event_ids": list(self.event_ids),
        }


class WebVulnInferrer:
    """把历史 Web 攻击事件按「服务 + 漏洞类型」聚合成漏洞结论。"""

    def __init__(self, settings: Optional[Settings] = None,
                 client: Optional[DeepSeekClient] = None) -> None:
        self.settings = settings or get_settings()
        self.client = client or DeepSeekClient(self.settings)
        self.counters: Dict[str, int] = {
            "inspected": 0, "confirmed": 0, "suspected": 0, "dismissed": 0,
            "ai_ok": 0, "ai_failed": 0, "ai_skipped": 0,
        }

    # ------------------------------------------------------------------ #
    # 对外入口
    # ------------------------------------------------------------------ #
    def infer(self, ip: str, limit: int = 0, use_ai: bool = True
              ) -> List[InferredVuln]:
        """对某个资产的历史 Web 攻击事件做研判，返回漏洞结论（不落库）。"""
        if not getattr(self.settings, "web_vuln_infer_enabled", True):
            return []
        limit = int(limit or getattr(self.settings, "web_vuln_infer_limit", 200))
        events = self._load_events(ip, limit)
        if not events:
            return []
        service_map = self._service_map(ip)
        grouped = self._group(events)
        findings: List[InferredVuln] = []
        for (port, category), items in grouped.items():
            finding = self._judge_group(ip, port, category, items, service_map,
                                        use_ai=use_ai)
            if finding is not None:
                findings.append(finding)
        findings.sort(key=lambda item: (item.cvss, item.port), reverse=True)
        return findings

    def summary(self) -> Dict[str, Any]:
        return {"enabled": bool(getattr(self.settings, "web_vuln_infer_enabled", True)),
                "ai_enabled": bool(getattr(self.settings, "web_vuln_infer_ai", True)),
                "client_available": self.client.available, **self.counters}

    # ------------------------------------------------------------------ #
    # 取数
    # ------------------------------------------------------------------ #
    def _load_events(self, ip: str, limit: int) -> List[Evidence]:
        """取该资产最近的可研判事件（inbound：攻击打到本机服务上）。"""
        categories = list(VULN_CLASS.keys())
        try:
            with session_scope() as session:
                rows = session.scalars(
                    select(ThreatEvent)
                    .where(ThreatEvent.dest_ip == ip)
                    .where(ThreatEvent.category.in_(categories))
                    .order_by(ThreatEvent.ts.desc())
                    .limit(max(1, limit))
                ).all()
                return [self._to_evidence(row) for row in rows]
        except Exception:
            logger.exception("读取攻击流量证据失败：%s", ip)
            return []

    @staticmethod
    def _to_evidence(row: ThreatEvent) -> Evidence:
        return Evidence(
            event_id=int(row.id), ts=row.ts, asset_ip=row.dest_ip or "",
            port=int(row.dest_port or 0), method=row.method or "", path=row.path or "",
            query=row.query or "", status=int(row.status_code or 0),
            category=row.category or "", request_body=row.request_body or "",
            response_head=row.response_head or "", response_body=row.response_body or "",
        )

    @staticmethod
    def _group(events: Sequence[Evidence]) -> Dict[Tuple[int, str], List[Evidence]]:
        """按「服务端口 + 漏洞类型」聚合；同一服务同一类漏洞只出一条结论。"""
        grouped: Dict[Tuple[int, str], List[Evidence]] = {}
        for item in events:
            grouped.setdefault((item.port, item.category), []).append(item)
        return grouped

    def _service_map(self, ip: str) -> Dict[int, str]:
        """端口 → 服务标签（取自资产指纹，取不到时退回「HTTP 应用」）。"""
        try:
            with session_scope() as session:
                asset = session.scalar(select(Asset).where(Asset.ip == ip))
                services = list(asset.services or []) if asset else []
        except Exception:
            services = []
        mapping: Dict[int, str] = {}
        for item in services:
            try:
                port = int(item.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if not port:
                continue
            name = str(item.get("name") or "").strip()
            product = str(item.get("product") or "").strip()
            version = str(item.get("version") or "").strip()
            label = " ".join(part for part in (product, version) if part) or name
            mapping[port] = label or "HTTP 应用"
        return mapping

    # ------------------------------------------------------------------ #
    # 研判
    # ------------------------------------------------------------------ #
    def _judge_group(self, ip: str, port: int, category: str, items: List[Evidence],
                     service_map: Dict[int, str], use_ai: bool) -> Optional[InferredVuln]:
        meta = VULN_CLASS.get(category)
        if meta is None:
            return None
        self.counters["inspected"] += len(items)
        # 优先挑"有响应且状态成功"的那条做证据：那是能证明漏洞成立的关键样本
        best = sorted(items, key=lambda item: (item.has_response, 200 <= item.status < 300,
                                               -item.event_id))[-1]
        judgement = judge_by_response(best, category)
        if use_ai and getattr(self.settings, "web_vuln_infer_ai", True):
            judgement = self._ai_review(ip, best, category, meta, judgement)
        if judgement.verdict == DISMISSED:
            self.counters["dismissed"] += 1
            return None
        self.counters[judgement.verdict] = self.counters.get(judgement.verdict, 0) + 1
        return InferredVuln(
            asset_ip=ip, port=port, service=service_map.get(port, "HTTP 应用"),
            category=category, title=str(meta["title"]), cwe=str(meta["cwe"]),
            severity=str(meta["severity"]), cvss=float(meta["cvss"]),
            recommendation=str(meta["recommendation"]),
            confidence=judgement.verdict, judged_by=judgement.judged_by,
            evidence=self._evidence_text(best, items, judgement),
            event_ids=[item.event_id for item in items][:10],
            found_at=best.ts,
        )

    @staticmethod
    def _evidence_text(best: Evidence, items: Sequence[Evidence], judgement: Judgement) -> str:
        """证据文本：先给人看结论，再给机器可核对的原始片段。"""
        source = "AI 复核" if judgement.judged_by == "ai" else "规则研判"
        lines = [
            f"研判来源：{source}（{len(items)} 条同类攻击事件）",
            f"研判结论：{'确认存在' if judgement.verdict == CONFIRMED else '疑似存在'}"
            + (f"（置信度 {judgement.confidence:.2f}）" if judgement.confidence else ""),
            f"攻击请求：{best.target}"
            + (f" → HTTP {best.status}" if best.status else " → 无响应包"),
        ]
        if judgement.snippet:
            lines.append(f"响应证据：{judgement.snippet}")
        if judgement.rationale:
            lines.append(f"判定依据：{judgement.rationale}")
        for extra in judgement.details:
            if extra:
                lines.append(extra)
        lines.append(f"首次发现：{iso_local(best.ts, stored='local') if best.ts else '-'}")
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # AI 复核
    # ------------------------------------------------------------------ #
    def _ai_review(self, ip: str, best: Evidence, category: str,
                   meta: Dict[str, Any], base: Judgement) -> Judgement:
        """让模型复核"这次攻击是否真的打穿了"；不可用时原样返回规则结论。"""
        if not self.client.available:
            self.counters["ai_skipped"] += 1
            return base
        try:
            raw = self.client.chat_json(self._messages(ip, best, meta), max_tokens=400,
                                        temperature=0.0)
            verdict, confidence, rationale = self._validate_ai(raw)
        except LLMUnavailable as exc:
            self.counters["ai_failed"] += 1
            logger.warning("漏洞流量研判 AI 不可用，回落规则结论：%s", exc)
            return base

        self.counters["ai_ok"] += 1
        if base.verdict == CONFIRMED:
            # 规则已握有客观证据（SQL 报错 / 命令回显），模型只能补充说明，不能推翻
            return Judgement(verdict=CONFIRMED, rationale=rationale or base.rationale,
                             snippet=base.snippet, judged_by="ai",
                             confidence=max(confidence, 0.8), details=base.details)
        if verdict in {"vulnerable", "likely"}:
            return Judgement(verdict=CONFIRMED, rationale=rationale, snippet=base.snippet,
                             judged_by="ai", confidence=confidence, details=base.details)
        if verdict == "not_vulnerable" and confidence >= 0.6:
            return Judgement(verdict=DISMISSED, rationale=rationale or "模型判定未打穿",
                             snippet=base.snippet, judged_by="ai", confidence=confidence,
                             details=base.details)
        return Judgement(verdict=SUSPECTED, rationale=rationale or base.rationale,
                         snippet=base.snippet, judged_by="ai", confidence=confidence,
                         details=base.details)

    def _messages(self, ip: str, best: Evidence, meta: Dict[str, Any]) -> List[Dict[str, str]]:
        import json

        digest = {
            "target_asset": mask_ip(ip, bool(getattr(self.settings, "llm_mask_internal_ip", True))),
            "port": best.port,
            "suspected_vuln_type": meta["title"],
            "cwe": meta["cwe"],
            "request": {
                "method": best.method,
                "path": _clip(best.path, 200),
                "query": _clip(best.query, 300),
                "body": _clip(best.request_body, MAX_REQUEST_CHARS),
            },
            "response": {
                "status": best.status,
                "head": _clip(best.response_head, 400),
                "body": _clip(best.response_body, MAX_RESPONSE_CHARS),
            },
        }
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "请研判以下攻击请求是否证明目标存在对应漏洞：\n"
                                        + json.dumps(digest, ensure_ascii=False)},
        ]

    @staticmethod
    def _validate_ai(raw: Dict[str, Any]) -> Tuple[str, float, str]:
        verdict = str(raw.get("verdict") or "").strip().lower()
        if verdict not in {"vulnerable", "likely", "not_vulnerable", "unknown"}:
            raise LLMUnavailable(f"非法 verdict：{verdict!r}")
        try:
            confidence = float(raw.get("confidence"))
        except (TypeError, ValueError) as exc:
            raise LLMUnavailable("confidence 非数值") from exc
        confidence = min(1.0, max(0.0, confidence))
        rationale = str(raw.get("rationale") or "").strip()[:200]
        return verdict, round(confidence, 3), rationale


# --------------------------------------------------------------------------- #
# 规则研判：只看响应能否证明"打穿了"
# --------------------------------------------------------------------------- #
def judge_by_response(event: Evidence, category: str) -> Judgement:
    """根据响应特征给出结论；无响应时只能给"疑似"。"""
    body = event.response_body or ""
    status = int(event.status or 0)

    if not event.has_response:
        return Judgement(
            verdict=SUSPECTED, judged_by="rule", confidence=0.4,
            rationale="只采集到攻击请求、没有响应包，无法确认是否打穿；"
                      "已按请求特征记为疑似，建议开启响应体留存或人工复现。",
            details=["提示：可在采集配置中提高 Web 抓包等级以保留响应体。"])

    if RE_BLOCKED.search(body) and status in {401, 403, 406, 429, 501}:
        return Judgement(verdict=DISMISSED, judged_by="rule", confidence=0.5,
                         rationale=f"响应 HTTP {status} 且命中拦截特征，判定为未打穿。")

    if category in {"web_sql_injection", "web_sql_injection_blind"}:
        found = _first(RE_SQL_ERROR, body)
        if found:
            return Judgement(CONFIRMED, "响应中返回数据库报错，说明注入参数进入了 SQL 语句。",
                             snippet=found, judged_by="rule", confidence=0.92)

    if category == "web_command_injection":
        found = _first(RE_SHELL_OUT, body)
        if found:
            return Judgement(CONFIRMED, "响应回显了系统命令的执行结果，命令注入成立。",
                             snippet=found, judged_by="rule", confidence=0.95)

    if category in {"web_path_traversal", "web_file_inclusion"}:
        found = _first(RE_LFI_OUT, body)
        if found:
            return Judgement(CONFIRMED, "响应返回了目标主机的本地文件内容，路径穿越/文件包含成立。",
                             snippet=found, judged_by="rule", confidence=0.9)

    if category in {"web_xss_reflected", "web_xss_stored"}:
        payload = _decode(event.query or "") or _decode(event.request_body or "")
        if RE_SCRIPT_TAG.search(payload or "") and RE_SCRIPT_TAG.search(body or ""):
            snippet = _first(RE_SCRIPT_TAG, body)
            return Judgement(CONFIRMED, "响应把脚本载荷原样回显（未转义），XSS 成立。",
                             snippet=snippet, judged_by="rule", confidence=0.85)

    if category == "web_file_upload" and 200 <= status < 300 and body:
        return Judgement(SUSPECTED, "上传请求返回成功，但未验证落地文件能否访问；"
                                    "需人工确认上传目录是否可执行。",
                         judged_by="rule", confidence=0.5)

    if category in {"web_brute_force", "web_csrf", "web_insecure_captcha", "web_webshell"}:
        return Judgement(SUSPECTED, "该类型以请求频次/会话特征判定，响应本身不足以证明漏洞成立。",
                         judged_by="rule", confidence=0.45)

    return Judgement(SUSPECTED, f"响应未出现该类漏洞的典型证据（HTTP {status}）。",
                     judged_by="rule", confidence=0.4)


def _first(pattern: re.Pattern, text: str, width: int = 80) -> str:
    match = pattern.search(text or "")
    if not match:
        return ""
    start = max(0, match.start() - 20)
    return re.sub(r"\s+", " ", text[start:match.end() + width]).strip()[:220]


def _decode(value: str) -> str:
    from urllib.parse import unquote_plus

    try:
        return unquote_plus(value or "")
    except Exception:
        return value or ""


def _clip(text: str, limit: int) -> str:
    data = str(text or "")
    return data if len(data) <= limit else data[:limit] + "…[已截断]"


SYSTEM_PROMPT = """你是 Web 应用漏洞研判助手。输入是一次真实的攻击请求与目标响应（JSON）。
你的任务是判断：**这次攻击是否真的打穿了目标，从而证明目标存在该类漏洞**。

只输出 JSON，不要任何解释文本：
{"verdict": "vulnerable|likely|not_vulnerable|unknown",
 "confidence": 0.0~1.0,
 "rationale": "判定依据，<=100字，必须引用响应中的具体现象"}

判定原则：
1. 以响应为准：只有响应中出现该类漏洞的客观证据（数据库报错、命令回显、本地文件内容、
   载荷被原样反射）才能给 vulnerable；
2. 响应为通用报错页、登录页、拦截页、或状态码 4xx/5xx 且无相关证据时，给 not_vulnerable
   或 unknown；
3. 响应体为空或缺失时，只能给 unknown，不得猜测；
4. 只描述漏洞类型（如"命令注入"），**不要出现任何产品名、站点名、靶场名**；
5. rationale 用中文，不复述完整请求内容，不输出被攻击方的主机名与 IP。"""
