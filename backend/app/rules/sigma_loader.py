"""Sigma YAML 规则加载器：`backend/data/sigma_rules/*.yml` → 统一 `Rule`。

筛选策略（与方案 1.3 节一致）：
1. 只保留"可在流量侧匹配"的规则：logsource 属于 webserver / proxy / http 类，
   或 detection 字段能映射到 path/query/body/header/cookie/user_agent/referer；
2. 进程创建、注册表、文件系统、Windows 事件日志等规则**加载期跳过**（记录日志，不报错）；
3. 条件只支持 `selection` / `selection and not filter...` / `1 of selection*` / `all of selection*`，
   更复杂的条件跳过（宁可少加载，不可错加载 —— 错加载会直接变成线上的误报）。

依赖：pyyaml（requirements.txt 已声明）。缺失时整个 Sigma 分支自动降级为"0 条"，不影响系统运行。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .base import Rule, should_inject_direct_alert, valid_confidence, valid_severity
from .category_map import category_of, references_of, remediation_of

logger = logging.getLogger(__name__)

# Sigma 字段 → 本系统匹配目标（None 表示该字段不参与正则匹配，而是转为方法/状态约束）
FIELD_MAP: Dict[str, Optional[str]] = {
    "cs-uri": "query",
    "cs-uri-query": "query",
    "cs-uri-stem": "path",
    "c-uri": "path",
    "c-uri-query": "query",
    "c-uri-stem": "path",
    "cs-uri-extension": "filename",
    "uri": "path",
    "url": "any",
    "request-uri": "path",
    "cs-body": "body",
    "cs-method": None,
    "sc-status": None,
    "cs-user-agent": "user_agent",
    "c-useragent": "user_agent",
    "cs-referer": "referer",
    "cs-cookie": "cookie",
    "cs-header": "header",
}

# 可等价表达的值修饰符；其余（base64 / windash / cidr / gt / lt）无法等价 → 跳过该规则
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}

SKIP_LOGSOURCE_CATEGORIES = {
    "process_creation", "registry_set", "registry_add", "registry_delete", "registry_event",
    "file_event", "file_delete", "file_change", "image_load", "driver_load", "pipe_created",
    "wmi_event", "ps_script", "ps_module", "ps_classic_start", "sysmon", "security", "system",
    "application", "windows", "linux", "auditd", "clamav", "antivirus", "firewall",
}
ALLOWED_LOGSOURCE_CATEGORIES = {"webserver", "proxy", "http", "web", "waf", "ids"}
HTTP_PRODUCTS = {"apache", "nginx", "iis", "tomcat", "httpd", "java", "nodejs", "php"}


def load_sigma_rules(rules_dir: Path) -> List[Rule]:
    """加载目录下全部 Sigma 规则（递归 *.yml / *.yaml）。"""
    directory = Path(rules_dir)
    if not directory.exists():
        return []
    files = sorted({*directory.rglob("*.yml"), *directory.rglob("*.yaml")})
    if not files:
        return []
    try:
        import yaml  # noqa: F401  仅用于探测依赖
    except Exception:  # pragma: no cover - 取决于环境
        logger.warning("未安装 pyyaml，Sigma 规则加载已跳过（pip install pyyaml）")
        return []

    rules: List[Rule] = []
    skipped = 0
    for path in files:
        documents = _load_yaml(path)
        if documents is None:
            continue
        for raw in documents:
            if not isinstance(raw, dict):
                continue
            detection = raw.get("detection") or {}
            if not isinstance(detection, dict) or not _http_applicable(raw, detection):
                skipped += 1
                continue
            rule = convert_rule(raw, origin=path.name)
            if rule is None:
                skipped += 1
                continue
            rules.append(rule)
    logger.info("sigma 加载器：%s 个文件 → 命中 %d 条、跳过 %d 条（非流量侧/无法映射）",
                len(files), len(rules), skipped)
    return rules


def _load_yaml(path: Path) -> Optional[List[Any]]:
    """读取 YAML（支持 `---` 分隔的多文档文件：Sigma 规则集常见形态）。"""
    try:
        import yaml
    except Exception:  # pragma: no cover
        return None
    try:
        return list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except Exception:
        logger.exception("Sigma 规则解析失败：%s", path)
        return None


def _http_applicable(raw: Dict[str, Any], detection: Dict[str, Any]) -> bool:
    logsource = raw.get("logsource") or {}
    category = str(logsource.get("category") or "").lower()
    product = str(logsource.get("product") or "").lower()
    if category in SKIP_LOGSOURCE_CATEGORIES:
        return False
    if category in ALLOWED_LOGSOURCE_CATEGORIES or product in HTTP_PRODUCTS:
        return True
    return _fields_supported(detection)


def _fields_supported(detection: Dict[str, Any]) -> bool:
    """detection 里出现无法映射的字段（如 process.command_line）即视为不适用。"""
    found = False
    for value in detection.values():
        for block in value if isinstance(value, list) else [value]:
            if not isinstance(block, dict):
                continue
            for raw_key in block:
                field = str(raw_key).split("|")[0]
                if field not in FIELD_MAP:
                    return False
                found = True
    return found


def _parse_condition(condition: str, detection: Dict[str, Any]
                     ) -> Optional[Tuple[List[str], List[str], bool]]:
    """返回 (主 selection keys, 排除 selection keys, 是否要求全部命中)；无法解析则 None。"""
    text = re.sub(r"\s+", " ", str(condition or "")).strip().lower()
    if not text:
        return None
    declared = {str(key) for key in detection}
    not_parts = [item for item in re.findall(r"not\s+([a-z0-9_*]+)", text) if item in declared]
    head = re.split(r"\band\s+not\b", text)[0].strip()
    quantifier = re.fullmatch(r"(1|any|all)\s+of\s+(selection[a-z0-9_]*\*?|them)", head)
    if quantifier:
        scope = quantifier.group(2)
        if scope.endswith("*") or scope == "them":
            keys = sorted(key for key in declared if key.startswith("selection"))
        else:
            keys = [scope] if scope in declared else []
        if not keys:
            return None
        return keys, not_parts, quantifier.group(1) == "all"
    if re.fullmatch(r"[a-z0-9_]+", head) and head in declared:
        return [head], not_parts, False
    return None


def _value_to_patterns(value: Any, modifiers: List[str]) -> Optional[List[str]]:
    """把 Sigma 的值（含修饰符）转成正则列表；修饰符不支持时返回 None。"""
    if not SUPPORTED_MODIFIERS.issuperset(modifiers):
        return None
    modifier = next((item for item in modifiers if item != "all"), None)
    patterns: List[str] = []
    for item in (value if isinstance(value, list) else [value]):
        text = str(item)
        if not text:
            continue
        if modifier == "re":
            patterns.append(text)
            continue
        literal = re.escape(text)
        if modifier == "startswith":
            patterns.append("^" + literal)
        elif modifier == "endswith":
            patterns.append(literal + "$")
        else:
            # contains 与"无修饰符"统一按包含处理：与 Suricata content 语义一致，
            # 且 HTTP 字段通常带前后缀（如 query 中的 a=1 前缀），全等匹配会漏报
            patterns.append(literal)
    return patterns or None


def convert_rule(raw: Dict[str, Any], origin: str = "") -> Optional[Rule]:
    """单条 Sigma 规则 → `Rule`；不适用时返回 None（调用方计入跳过数）。"""
    if not isinstance(raw, dict):
        return None
    detection = raw.get("detection") or {}
    if not isinstance(detection, dict):
        return None
    parsed = _parse_condition(str(raw.get("condition") or detection.get("condition") or "selection"),
                              detection)
    if parsed is None:
        logger.debug("Sigma 规则条件不受支持，已跳过：%s", raw.get("title"))
        return None
    main_keys, exclude_keys, match_all = parsed

    title = str(raw.get("title") or "")
    tags = " ".join(str(item) for item in raw.get("tags") or [])
    category = category_of(" ".join([title, str(raw.get("description") or ""), tags]))
    if not category:
        logger.debug("Sigma 规则无法映射到内置攻击大类，已跳过：%s", title)
        return None

    targets: List[str] = []
    patterns: List[str] = []
    method_in: List[str] = []
    status_in: List[int] = []
    regex_used = False
    all_modifier = False
    pattern_keys = set()
    for key in main_keys:
        block = detection.get(key) or {}
        for stat in block if isinstance(block, list) else [block]:
            if not isinstance(stat, dict):
                continue
            for raw_key, value in stat.items():
                parts = str(raw_key).split("|")
                field, modifiers = parts[0], parts[1:]
                values = value if isinstance(value, list) else [value]
                if field == "cs-method":
                    method_in += [str(item).upper() for item in values]
                    continue
                if field == "sc-status":
                    status_in += [int(item) for item in values if str(item).isdigit()]
                    continue
                target = FIELD_MAP.get(field)
                if target is None:
                    return None
                found = _value_to_patterns(value, modifiers)
                if not found:
                    return None
                regex_used = regex_used or "re" in modifiers
                all_modifier = all_modifier or "all" in modifiers
                pattern_keys.add(key)
                targets.append(target)
                patterns += found
    if not patterns:
        return None
    # Sigma 语义还原：`|all` 修饰符 → 该字段的多个值都要命中；同一 selection 内多个字段 → AND。
    # 本系统的规则结构是"pattern 列表 + match_all 开关"，因此上面两种情况都映射为 match_all=True。
    match_all = bool(match_all or all_modifier or len(pattern_keys) > 1)

    exclude_patterns: List[str] = []
    require_absent: List[str] = []
    for key in exclude_keys:
        block = detection.get(key) or {}
        for stat in block if isinstance(block, list) else [block]:
            if not isinstance(stat, dict):
                continue
            for raw_key, value in stat.items():
                parts = str(raw_key).split("|")
                if parts[0] == "cs-header":
                    require_absent += [str(item) for item in
                                       (value if isinstance(value, list) else [value])]
                    continue
                found = _value_to_patterns(value, parts[1:]) or [
                    re.escape(str(value))]
                exclude_patterns += found

    level = str(raw.get("level") or "medium").lower()
    severity = valid_severity({"informational": "low"}.get(level, level))
    confidence = valid_confidence("medium" if regex_used else "high")
    references = [str(item) for item in (raw.get("references") or [])] or references_of(category)
    raw_id = str(raw.get("id") or "").strip()
    if not raw_id:
        raw_id = _slug(title or origin)
    rule_id = raw_id if raw_id.upper().startswith("SIGMA-") else "SIGMA-" + raw_id

    return Rule(
        id=rule_id,
        source="sigma",
        category=category,
        severity=severity,
        confidence=confidence,
        direct_alert=should_inject_direct_alert(category, severity, confidence, "sigma"),
        match_targets=sorted(set(targets)) or ["any"],
        patterns=patterns,
        exclude_patterns=exclude_patterns,
        match_all=match_all,
        match_mode="normalized",
        method_in=method_in,
        status_in=sorted(set(status_in)),
        require_absent=require_absent,
        title=title or rule_id,
        remediation=remediation_of(category),
        references=references,
        examples=[str(item) for item in (raw.get("examples") or [])],
        raw=dict(raw),
    )


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", str(text or "")).strip("-").upper()
    return slug[:48] or "UNNAMED"
