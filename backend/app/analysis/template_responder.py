"""静态模板研判（降级链第三级）。

为什么需要它：LLM API 不可用时，运维仍然需要"人话结论"。模板按攻击大类给出
预设的判定倾向与处置建议，并把检测器证据（阈值、命中次数、评分）插进理由里 ——
**降级但不说谎**：结果里带 `degraded=True`，前端会显示"已降级到本地研判"提示条。
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# 每个大类的模板：verdict（判定倾向）/ suggestion（处置动作）/ reason（中文理由模板）
TEMPLATES: Dict[str, Dict[str, Any]] = {
    "port_scan": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "检测到单源在短时间内访问多个目的端口（{unique_dst_ports} 个，端口熵 {port_entropy}），"
                  "符合端口扫描特征；本地规则判定为 {severity} 级别。",
    },
    "brute_force": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "检测到对认证端口 {dest_port} 的 {hits} 次高频访问（阈值 {threshold}），"
                  "符合暴力破解 / 凭证填充特征。",
    },
    "nonstandard_port": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "非标准端口 {dest_port} 出现高频访问（{pps} pps），可能是后门服务或隧道；"
                  "需确认该端口对应的业务进程。",
    },
    "traffic_spike": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "整机流量 {total_bps} bps 显著偏离基线（Z={bps_zscore}），"
                  "可能是业务高峰、备份窗口、DDoS 或数据外泄。",
    },
    "behavior_anomaly": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "主机多维行为向量偏离历史画像（IF 分数 {if_score}），"
                  "建议核对业务变更后再决定处置。",
    },
    "web_sql_injection": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中 SQL 注入规则 {rule_ids}，属于高危应用层攻击。",
    },
    "web_sql_injection_blind": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中 SQL 盲注规则 {rule_ids}（延时 / 布尔判定特征）。",
    },
    "web_xss_reflected": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "请求命中反射型 XSS 规则 {rule_ids}，回显类漏洞易被批量扫描，建议确认是否为扫描器行为。",
    },
    "web_xss_stored": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中存储型 XSS 规则 {rule_ids}，恶意内容可能已入库。",
    },
    "web_command_injection": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中命令注入 / RCE 规则 {rule_ids}，属于高置信度致命攻击。",
    },
    "web_file_inclusion": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中文件包含规则 {rule_ids}，可能读取敏感文件或加载远程代码。",
    },
    "web_file_upload": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中恶意文件上传规则 {rule_ids}，需确认上传目录是否已有脚本落地。",
    },
    "web_brute_force": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "登录接口在窗口内累计 {threshold} 次失败访问，符合暴力破解特征。",
    },
    "web_csrf": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "请求缺少 CSRF Token / 来源校验，命中规则 {rule_ids}，需确认是否属于跨站诱导。",
    },
    "web_insecure_captcha": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "验证码接口出现异常频次访问，命中规则 {rule_ids}。",
    },
    "web_path_traversal": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中目录穿越规则 {rule_ids}，可能读取 Web 根之外的敏感文件。",
    },
    "web_ssrf": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中 SSRF 规则 {rule_ids}，可能已访问内网服务或云元数据接口。",
    },
    "web_xxe": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中 XXE 规则 {rule_ids}，XML 解析器可能加载了外部实体。",
    },
    "web_webshell": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中 Webshell 访问规则 {rule_ids}，主机可能已被控制，需立即取证。",
    },
    "web_ssti": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中服务端模板注入规则 {rule_ids}，可能导致远程代码执行。",
    },
    "web_ldap_nosql_injection": {
        "verdict": "confirm",
        "suggestion": "block",
        "reason": "请求命中 LDAP / NoSQL 注入规则 {rule_ids}，账号数据可能被遍历。",
    },
    "web_crlf_injection": {
        "verdict": "suspect",
        "suggestion": "watch",
        "reason": "请求命中 CRLF 注入规则 {rule_ids}，响应头可能被注入。",
    },
}


def render(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """按大类渲染模板；无匹配模板返回 None（交由上一级/下一级处理）。"""
    template = TEMPLATES.get(str(alert.get("category") or ""))
    if template is None:
        return None
    fields = _fields(alert)
    try:
        reason = str(template["reason"]).format(**fields)
    except (KeyError, IndexError, ValueError):
        reason = str(template["reason"])
    return {
        "verdict": template["verdict"],
        "suggestion": template["suggestion"],
        "confidence": 0.6,
        "reason": reason[:200],
    }


def _fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    """把告警字段摊平成模板变量（缺省值保证 format 永不失败）。"""
    evidence = alert.get("evidence") or {}
    fields = {
        "severity": alert.get("severity") or "unknown",
        "dest_port": alert.get("dest_port") or "-",
        "rule_ids": ",".join(str(item) for item in (alert.get("contributing_rules") or
                                                    [alert.get("rule_id") or "-"])[:3]),
        "risk_score": alert.get("risk_score") or 0,
    }
    for key in ("unique_dst_ports", "port_entropy", "hits", "threshold", "pps", "reward",
                "bps_zscore", "pps_zscore", "total_bps", "duration_sec", "if_score"):
        fields[key] = evidence.get(key, "-")
    return fields
