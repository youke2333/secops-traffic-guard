"""Prompt 模板集中管理（方案第 4 层）。

安全约束（务必遵守，否则等于把内网信息与注入面直接交给外部 API）：

1. Prompt 输入**只接受结构化字段**：源 IP（可脱敏）、目的端口、评分、规则 ID、类别、严重度、
   证据摘要键值（zscore / baseline_mean_pps / 命中次数等）；**禁止拼接原始 payload / URL /
   User-Agent / Cookie 字符串** —— 原始载荷里可能带 `ignore previous instructions` 之类的注入；
2. 只把"结论 + 枚举值"当作可信输出，任何非法值一律降级（见 `llm_client.validate_result`）；
3. 证据引用（evidence_refs）取自检测器给出的结构化字段，便于人工复核；
4. 系统提示里明确告知模型：direct_alert=True 表示单条高置信度致命攻击规则已命中。
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

# 证据白名单 / 黑名单：决定哪些字段可以进入 Prompt（安全边界，务必保守）
DROP_EVIDENCE_KEYS = {"request", "rules", "snippets", "message", "signals", "matched_pattern",
                      "false_positive_hint", "remediation"}
SAFE_STRING_KEYS = {"detector", "rule_source", "category", "category_name", "cwe", "owasp",
                    "confidence", "severity", "suppressed_reason", "threshold_count"}
SAFE_LIST_KEYS = {"rule_ids", "categories_hit", "matched_targets", "rule_sources"}

SYSTEM_PROMPT = """你是企业流量安全运营中心的告警研判助手。
你会收到一条结构化告警（JSON），请判断它是「真实攻击」还是「误报」，并给出处置建议。

系统检测能力说明：
- 规则引擎：内置 Web 攻击知识库（SQL 注入 / XSS / 命令注入 / 文件包含 / 上传 / XXE / SSTI /
  Webshell 等 17 大类）+ 开源规则（Sigma、Suricata-ET），命中高置信度致命规则时会标记
  direct_alert=true 并立即告警；
- 统计检测：EWMA + 稳健 Z-score 基线，用于端口扫描、认证端口暴破、非标准端口高频访问、
  突发流量峰值等；
- 机器学习：Isolation Forest 对多维行为向量做离群确认（behavior_anomaly）；
- 聚合评分：滑动窗口内多条信号累计的 risk_score 超过阈值时才会告警（抑制告警风暴）。

告警字段含义：
- category/severity：攻击大类与级别（critical > high > medium > low）；
- score：检测器自身的归一化置信度（0~1）；risk_score：窗口聚合风险分；
- direct_alert：是否由直达机制触发（单条致命攻击规则命中）；
- contributing_rules：参与本次聚合的规则 ID 列表；
- evidence：检测器给出的结构化证据（zscore / baseline_mean_pps / hit 次数等）。

研判规则：
- 若 direct_alert=true，表示单条高置信度致命攻击规则已命中，研判应倾向于 confirm；
- 若为聚合告警，需综合评估多个 signal 的证据一致性：证据互相印证（如端口多样性 + SYN 占比高）
  倾向 confirm；只有单一弱证据（如轻微偏离基线）倾向 suspect 或 dismiss；
- 无法判断时输出 unknown，不要臆测。

只输出 JSON（不要任何解释文本），格式：
{"verdict": "confirm|suspect|dismiss|unknown",
 "confidence": 0.0-1.0,
 "suggestion": "block|watch|ignore",
 "reason": "一句话中文研判理由（<=120 字）"}
"""


def build_alert_digest(alert: Dict[str, Any], mask_internal_ip: bool = True) -> Dict[str, Any]:
    """把告警压缩成"结构化摘要"（唯一允许进入 Prompt 的内容）。

    注意：这里只取白名单字段 —— 任何原始 URL / payload / UA 都不会被带出去。
    """
    evidence = alert.get("evidence") or {}
    return {
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "score": _round(alert.get("score")),
        "risk_score": _round(alert.get("risk_score")),
        "direct_alert": bool(alert.get("direct_alert")),
        "contributing_rules": list(alert.get("contributing_rules") or [])[:10],
        "source_ip": mask_ip(alert.get("source_ip"), mask_internal_ip),
        "dest_port": alert.get("dest_port"),
        "protocol": alert.get("protocol"),
        "detector": alert.get("detector"),
        "evidence_summary": _evidence_summary(evidence),
        "history": alert.get("history") or {},
    }


def build_messages(alert: Dict[str, Any], mask_internal_ip: bool = True) -> List[Dict[str, str]]:
    digest = build_alert_digest(alert, mask_internal_ip)
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "请研判以下告警：\n" + json.dumps(digest, ensure_ascii=False)},
    ]


def _evidence_summary(evidence: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """只取"安全"证据字段进入 Prompt（结构化数值 / 白名单字符串）。

    为什么这么严：Web 攻击证据里的 `snippet` / `request.query` / `rule.pattern` 全部来自
    攻击者可控输入，直接塞进 Prompt 等于开放提示注入（"ignore previous instructions…"）。
    """
    if not isinstance(evidence, dict) or depth > 2:
        return {}
    summary: Dict[str, Any] = {}
    for key, value in evidence.items():
        name = str(key)
        if name in DROP_EVIDENCE_KEYS:
            continue
        if isinstance(value, (int, float, bool)) or value is None:
            summary[name] = value
        elif isinstance(value, str):
            if name in SAFE_STRING_KEYS:
                summary[name] = value[:32]
        elif isinstance(value, list):
            if name in SAFE_LIST_KEYS:
                summary[name] = [str(item)[:32] for item in value[:8]]
            else:
                numbers = [item for item in value if isinstance(item, (int, float, bool))]
                if numbers and len(numbers) == len(value):
                    summary[name] = numbers[:8]
        elif isinstance(value, dict):
            nested = _evidence_summary(value, depth + 1)
            if nested:
                summary[name] = nested
    # 顶层字段过多时截断，控制 Prompt 体积（无关字段对研判没有增益）
    return dict(list(summary.items())[:24])


def evidence_refs(alert: Dict[str, Any]) -> List[str]:
    """给前端展示的"研判依据"（结构化 key=value 列表，便于人工快速核对）。"""
    refs: List[str] = []
    if alert.get("risk_score"):
        refs.append(f"risk_score={alert.get('risk_score')}")
    if alert.get("score") is not None:
        refs.append(f"score={alert.get('score')}")
    if alert.get("direct_alert"):
        refs.append("direct_alert=true（单条致命规则命中）")
    if alert.get("contributing_rules"):
        refs.append("rules=" + ",".join(str(item) for item in alert["contributing_rules"][:6]))
    evidence = alert.get("evidence") or {}
    for key in ("zscore", "baseline_mean_pps", "unique_dst_ports", "port_entropy", "hits",
                "threshold", "syn_ratio", "pps", "pps_zscore"):
        if key in evidence and isinstance(evidence[key], (int, float)):
            refs.append(f"{key}={evidence[key]}")
    if alert.get("detector"):
        refs.append(f"detector={alert.get('detector')}")
    return refs[:10]


def mask_ip(value: Any, mask: bool = True) -> str:
    """内网 IP 脱敏：10.x → 10.x.x.0/24 段位保留、后缀清零，避免把内网拓扑交给外部 API。"""
    text = str(value or "")
    if not mask or not text:
        return text
    parts = text.split(".")
    if len(parts) != 4:
        return text
    if (parts[0] == "10" or (parts[0] == "192" and parts[1] == "168")
            or parts[0] == "127"
            or (parts[0] == "172" and parts[1].isdigit() and 16 <= int(parts[1]) <= 31)):
        return ".".join(parts[:2] + ["0", "0"])
    return text


def _round(value: Any) -> Any:
    try:
        return round(float(value), 3)
    except (TypeError, ValueError):
        return value
