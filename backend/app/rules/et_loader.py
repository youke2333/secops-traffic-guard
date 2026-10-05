"""Suricata / ET Open 规则加载器：`backend/data/et_rules/*.rules` → 统一 `Rule`。

解析范围（与方案 1.3 节一致，按本系统实际能力做了收敛）：
* 只解析 ``alert`` 动作行，只保留 ``http`` 协议规则（dns/tls 规则当前无对应匹配字段，加载期跳过）；
* 提取 ``msg`` / ``content``（含 ``http_uri``/``http_client_body``/``http_header``/``http_cookie``
  等修饰符）/ ``pcre`` / ``flow`` / ``classtype`` / ``threshold``；
* ``flow:...to_client`` 的响应方向规则跳过（本系统只检测**入向请求**）；
* 含十六进制字节块（``|0a 0d|``）、``content|base64``、``fast_pattern`` 之外的复杂修饰符的
  content 会被跳过；若某条规则最终没有任何可用 content/pcre，则整条跳过并计数。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .base import Rule, should_inject_direct_alert, valid_confidence, valid_severity
from .category_map import category_of, references_of, remediation_of

logger = logging.getLogger(__name__)

CONTENT_TARGET_MODIFIERS = {
    # Suricata 的 http_uri 是"规范化 URI"（路径 + 查询串），本系统的 any 目标同样覆盖
    # 请求行 + path + query，因此映射到 any 才不会漏报（如 .php 出现在 path、cmd= 出现在 query）
    "http_uri": "any",
    "http_raw_uri": "any",
    "http_client_body": "body",
    "http_header": "header",
    "http_cookie": "cookie",
    "http_user_agent": "user_agent",
    "http_host": "header",
    "http_referer": "referer",
    "http_stat_code": None,        # 响应侧，忽略
    "http_stat_msg": None,
}

# Suricata classtype → 本系统严重度（无映射时按 msg 关键词兜底）
CLASSTYPE_SEVERITY = {
    "web-application-attack": "high",
    "web-application-activity": "medium",
    "attempted-recon": "medium",
    "attempted-admin": "high",
    "attempted-user": "high",
    "shellcode-detect": "critical",
    "trojan-activity": "critical",
    "policy-violation": "low",
    "unknown": "medium",
}

# 修饰符里出现这些关键字即视为无法等价表达（认证/流方向/编码类）
UNSUPPORTED_CONTENT_MODIFIERS = {
    "base64_decode", "base64_data", "base64", "urilen", "dce_stub_data",
    "byte_test", "byte_jump", "byte_extract", "isdataat", "dsize",
}

OPTION_RE = re.compile(r'([A-Za-z0-9_.\-]+)\s*(?::\s*("(?:[^"\\]|\\.)*"|[^;]*))?\s*;')
# 只匹配"头部"，不在结尾加 $ —— 完整规则行后面还有 "(msg: ...)" 选项块
HEADER_RE = re.compile(r'^\s*(alert|drop|pass|reject)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<-|<>)\s+(\S+)\s+(\S+)\s*')


def load_et_rules(rules_dir: Path) -> List[Rule]:
    """加载目录下全部 Suricata 规则（递归 *.rules / *.txt）。"""
    directory = Path(rules_dir)
    if not directory.exists():
        return []
    files = sorted({*directory.rglob("*.rules"), *directory.rglob("*.txt")})
    if not files:
        return []
    rules: List[Rule] = []
    skipped = 0
    total = 0
    for path in files:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            total += 1
            rule = convert_rule(text, origin=path.name)
            if rule is None:
                skipped += 1
                continue
            rules.append(rule)
    logger.info("et 加载器：%s 个文件 → 读取 %d 行、命中 %d 条、跳过 %d 条",
                len(files), total, len(rules), skipped)
    return rules


def _split_options(text: str) -> Optional[Tuple[str, str]]:
    """（保留给外部脚本/测试使用的兼容入口）拆分头部与选项块。"""
    match = HEADER_RE.match(text)
    if not match:
        return None
    rest = text[match.end():].strip()
    if not rest.startswith("("):
        return None
    end = rest.rfind(")")
    return text[:match.end()].strip(), rest[1:end] if end > 0 else rest[1:]


def _parse_options(blob: str) -> List[Tuple[str, str]]:
    return [(match.group(1).lower(), (match.group(2) or "").strip()) for match in
            OPTION_RE.finditer(blob)]


def _unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    return (text.replace('\\"', '"').replace("\\|", "|").replace("\\;", ";")
            .replace("\\\\", "\\"))


HEX_BLOCK_RE = re.compile(r"\|[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2})*\|")


def _content_to_pattern(blob: str) -> Optional[str]:
    """Suricata content → 正则片段；含十六进制字节块（不可打印）时返回 None。"""
    raw = blob.strip()
    if raw[:1] == '"' and raw[-1:] == '"':
        raw = raw[1:-1]
    if HEX_BLOCK_RE.search(raw):
        return None      # |0a 0d| 这类字节块无法用文本正则等价表达
    text = (raw.replace('\\"', '"').replace("\\;", ";").replace("\\|", "|")
               .replace("\\\\", "\\"))
    if not text:
        return None
    return re.escape(text)


def _pcre_to_pattern(blob: str) -> Optional[str]:
    """pcre:"/re/flags" → 正则；含无法等价表达的 flag（U/R/B 等）时返回 None。"""
    text = _unquote(blob)
    match = re.match(r"^/(.*)/[a-zA-Z]*$", text, re.S)
    if not match:
        return None
    flags = text.rsplit("/", 1)[-1]
    if set(flags.lower()) - {"i", "s", "m"}:
        return None
    pattern = match.group(1)
    # Suricata 的 \xNN 转义在 Python re 下语义一致，可直接透传；只做合法性校验
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None
    return pattern


def convert_rule(line: str, origin: str = "") -> Optional[Rule]:
    """单行 Suricata 规则 → `Rule`；不适用时返回 None。"""
    header_match = HEADER_RE.match(line)
    if not header_match:
        return None
    action, proto, _src, _sport, direction, _dst, _dport = header_match.groups()
    if action != "alert" or proto.lower() != "http":
        return None
    if direction == "<-":       # 只保留入向（请求）规则
        return None
    # 选项块 = 头部之后的第一段括号内容（msg 里可能含括号，故必须在匹配头部后截取）
    rest = line[header_match.end():].strip()
    if not rest.startswith("("):
        return None
    end = rest.rfind(")")
    blob = rest[1:end] if end > 0 else rest[1:]
    options = _parse_options(blob)
    if not options:
        return None

    msg = ""
    sid = ""
    classtype = ""
    flow = ""
    threshold: Optional[Dict[str, int]] = None
    references: List[str] = []
    targets: List[str] = []
    patterns: List[str] = []
    pcre_used = False
    current_target = "any"
    unsupported = False

    for key, value in options:
        if key == "msg":
            msg = _unquote(value)
        elif key == "sid":
            sid = value
        elif key == "classtype":
            classtype = value.lower()
        elif key == "flow":
            flow = value.lower()
        elif key == "pcre":
            pattern = _pcre_to_pattern(value)
            if pattern is None:
                unsupported = True
                continue
            pcre_used = True
            patterns.append(pattern)
            targets.append(current_target)
        elif key == "content":
            pattern = _content_to_pattern(value)
            if pattern is None:
                unsupported = True
                continue
            patterns.append(pattern)
            targets.append(current_target)
        elif key in CONTENT_TARGET_MODIFIERS:
            target = CONTENT_TARGET_MODIFIERS[key]
            if target is None:
                unsupported = True
                continue
            current_target = target
        elif key == "reference":
            references.append(_reference_url(value))
        elif key in UNSUPPORTED_CONTENT_MODIFIERS:
            unsupported = True
        elif key == "threshold":
            threshold = _parse_threshold(value) or threshold

    if unsupported and not patterns:
        return None
    if not patterns:
        return None
    if "to_client" in flow or "from_server" in flow:
        return None       # 响应方向规则：本系统只检测入向请求

    category = category_of(" ".join([msg, classtype]))
    if not category:
        logger.debug("ET 规则无法映射到内置攻击大类，已跳过：%s", msg or sid)
        return None

    severity = valid_severity(CLASSTYPE_SEVERITY.get(classtype, "medium"))
    confidence = valid_confidence("medium" if pcre_used else "high")
    rule_id = "ET-" + (sid or re.sub(r"[^0-9A-Za-z]+", "-", msg or origin).strip("-")[:40]
                       or "UNNAMED")

    return Rule(
        id=rule_id,
        source="et",
        category=category,
        severity=severity,
        confidence=confidence,
        direct_alert=should_inject_direct_alert(category, severity, confidence, "et"),
        match_targets=sorted(set(targets)) or ["any"],
        patterns=patterns,
        match_all=True,          # Suricata 多个 content 之间是 AND 语义
        match_mode="normalized",
        threshold=threshold,
        title=msg or rule_id,
        remediation=remediation_of(category),
        references=references or references_of(category),
        raw={"line": line, "classtype": classtype, "flow": flow},
    )


def _reference_url(value: str) -> str:
    text = value.strip().strip('"')
    if "," in text:
        _kind, url = text.split(",", 1)
        text = url.strip()
    if text.startswith("http"):
        return text
    return "https://" + text.lstrip("/")


def _parse_threshold(value: str) -> Optional[Dict[str, int]]:
    """threshold: type both, track by_src, count 10, seconds 60; → 滑动窗口阈值。"""
    text = _unquote(value).lower()
    count = re.search(r"count\s+(\d+)", text)
    seconds = re.search(r"seconds\s+(\d+)", text)
    if not count or not seconds:
        return None
    return {"window_sec": max(1, int(seconds.group(1))), "count": max(1, int(count.group(1)))}
