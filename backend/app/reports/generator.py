"""安全事件报告生成器（自包含 HTML，可用浏览器打印为 PDF）。

不引入 reportlab/weasyprint：输出单文件 HTML（内联 CSS、无外链），
既能在服务器离线保存，也能直接发给业务方；所有动态字段渲染前统一转义。
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import select

from ..config import Settings, get_settings
from ..database import session_scope
from ..timeutil import iso_local, text_local
from ..models import Alert, BlockReport, BlockRule, ThreatEvent, utcnow

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


# ---------------------------------------------------------------- 攻击特征高亮
# 与前端 dashboard/js/ui.js 的 ATK_RULES 保持同一套特征（命令执行 / SQL 注入 /
# XSS / 目录穿越 / 反序列化等），报告与页面看到的高亮位置一致。
# 只收录「正常业务文本里几乎不会出现」的特征，避免整篇报告被刷成红色。
_ATK_RULES: Sequence[str] = (
    # 命令执行 / 敏感文件读取
    r"(?:cat|tac|head|tail|more|less|nl|strings)\s+(?:-\w+\s+)*(?:/etc/|/proc/|[A-Za-z]:\\Windows)",
    r"/etc/(?:passwd|shadow|group|sudoers|hosts|issue|motd)",
    r"\betc/(?:passwd|shadow|group|sudoers)",
    r"/proc/self/(?:environ|cmdline|status|maps)",
    r"(?:[;|]|&&|\|\|)\s{0,3}(?:cat|ls|id|whoami|uname|pwd|hostname|ifconfig|ipconfig|netstat"
    r"|wget|curl|nc|ncat|netcat|socat|bash|sh|zsh|cmd|powershell|python|perl|php|chmod|chown"
    r"|rm|mv|cp|echo|touch|base64|telnet|ftp|scp|ssh|ping|sleep|nslookup|dig|reg|net|kill|ps)"
    r"\b(?![=\w-])",
    r"\$\s*\([^)\n]{0,80}\)",
    r"`[^`\n]{1,80}`",
    r"(?:nc|ncat|netcat)\s+-\w*e\b",
    r"/bin/(?:ba|z|da)?sh\b",
    r"/dev/tcp/",
    r"mkfifo",
    r"base64\s+(?:-d|--decode)",
    r"cmd\.exe",
    r"powershell(?:\.exe)?\s+-\w",
    r"net\s+(?:user|localgroup|group)\b",
    r"whoami\b",
    r"uname\s+-a",
    r"(?:wget|curl)\s+(?:-\w+\s+)*https?://",
    # SQL 注入
    r"\b(?:union\s+(?:all\s+)?)?select\b[\s\S]{0,80}?\bfrom\b",
    r"union\s+(?:all\s+)?select",
    r"['\"]\s*(?:or|and)\s+['\"]?\d",
    r"\b(?:or|and)\b\s+\d+\s*=\s*\d+",
    r"\b(?:or|and)\b\s+\d+\s*>\s*\d+",
    r"\b(?:or|and)\b\s+(?:exists|ascii|char|substr|substring|length|sleep|benchmark|if"
    r"|version|database|user)\s*\(",
    r"\b1\s*=\s*1\b",
    r"sleep\s*\(\s*\d+",
    r"benchmark\s*\(",
    r"pg_sleep\s*\(",
    r"waitfor\s+delay",
    r"information_schema",
    r"xp_cmdshell",
    r"load_file\s*\(",
    r"into\s+(?:out|dump)file",
    r"updatexml\s*\(",
    r"extractvalue\s*\(",
    r"group_concat\s*\(",
    r"\b(?:drop|truncate)\s+table\b",
    r"\bdelete\s+from\b",
    r"\binsert\s+into\b",
    # XSS / 脚本注入
    r"</?script\b",
    r"<svg\b",
    r"<iframe\b",
    r"<img[^>]{0,80}on\w+\s*=",
    r"javascript\s*:",
    r"on(?:error|load|click|mouseover|focus|submit)\s*=",
    r"document\.cookie",
    r"fromCharCode",
    r"alert\s*\((?=\s*[\d'\"])",
    r"eval\s*\(",
    # 目录穿越 / 文件包含
    r"(?:\.\./){2,}",
    r"(?:\.\.\\){2,}",
    r"(?:%2e%2e)(?:%2f|/)",
    r"\.\.%2f",
    r"php://(?:input|filter)",
    r"phar://",
    r"expect://",
    # 其他常见攻击面
    r"\$\{jndi:",
    r"\$\{(?:[^{}]{1,40})\}",
    r"\{\{[\s\S]{1,40}?\}\}",
    r"phpinfo\s*\(",
    r"shell_exec",
    r"passthru\s*\(",
    r"system\s*\(",
    r"assert\s*\(",
    r"(?:^|[?&;])(?:cmd|exec|shell)\s*=",
    r"%0d%0a",
    r"%00",
    r"<!ENTITY",
    r"\$(?:ne|gt|gte|lt|where|regex|nin)\b",
)

_ATK_RE = re.compile("|".join(_ATK_RULES), re.IGNORECASE | re.MULTILINE)


def _pct_decode(text: str) -> tuple:
    """URL 解码并保留「解码后位置 -> 原文位置」映射。

    WAF / 代理日志里的攻击载荷绝大多数是 URL 编码的（``%27%20union%20select``），
    直接在原文上匹配会漏标。这里先解码再匹配，再用映射把命中回填到原文区间，
    高亮仍然覆盖原始（编码形态）文本，不会改动报告内容。
    """
    out: List[str] = []
    index_map: List[int] = []
    total = len(text)
    position = 0
    while position < total:
        char = text[position]
        if char == "%" and position + 2 < total:
            try:
                out.append(chr(int(text[position + 1:position + 3], 16)))
            except ValueError:
                pass
            else:
                index_map.append(position)
                position += 3
                continue
        if char == "+":
            out.append(" ")
            index_map.append(position)
            position += 1
            continue
        out.append(char)
        index_map.append(position)
        position += 1
    index_map.append(total)
    return "".join(out), index_map


def _atk_spans(text: str) -> List[tuple]:
    """所有需要高亮的区间（原文坐标），已排序并合并重叠部分。"""
    spans = [(m.start(), m.end()) for m in _ATK_RE.finditer(text) if m.end() > m.start()]
    if "%" in text or "+" in text:
        decoded, index_map = _pct_decode(text)
        if decoded != text:
            for match in _ATK_RE.finditer(decoded):
                start, end = index_map[match.start()], index_map[match.end()]
                if end > start:
                    spans.append((start, end))
    spans.sort()
    merged: List[tuple] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _hl(value: Any, limit: Optional[int] = None) -> str:
    """转义 + 攻击特征高亮：命中片段包 <mark class="atk">，其余照常转义。

    在「原始文本」上匹配、按片段分别转义，因此输出与整串 `_esc()` 完全等价，
    不会破坏 HTML 结构，也不会漏转义（报告里大量字段来自不可信流量）。
    """
    text = "" if value is None else str(value)
    if limit is not None:
        text = text[:limit]
    if not text:
        return ""
    spans = _atk_spans(text)
    if not spans:
        return _esc(text)
    parts: List[str] = []
    last = 0
    for start, end in spans:
        if start > last:
            parts.append(_esc(text[last:start]))
        parts.append(f'<mark class="atk">{_esc(text[start:end])}</mark>')
        last = end
    parts.append(_esc(text[last:]))
    return "".join(parts)


def _fmt_time(value: Any, *, stored: str = "utc") -> str:
    """统一输出本地时间（stored="local" 表示库里本来就是本地时间）。"""
    return text_local(value, stored=stored) or "-"


def _sha256(payload: Any) -> str:
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _table(headers: List[str], rows: List[List[Any]], empty: str = "无记录",
           raw_cols: Optional[Sequence[int]] = None) -> str:
    """渲染表格；``raw_cols`` 里的列视为「已转义好的 HTML」（用于高亮单元格）。"""
    if not rows:
        return f'<p class="empty">{_esc(empty)}</p>'
    raw = set(raw_cols or ())
    head = "".join(f"<th>{_esc(item)}</th>" for item in headers)
    body = ""
    for row in rows:
        cells = "".join(
            f"<td>{cell if index in raw else _esc(cell)}</td>"
            for index, cell in enumerate(row)
        )
        body += f"<tr>{cells}</tr>"
    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def _counter_rows(counter: Counter, label: str) -> List[List[Any]]:
    return [[key or "unknown", value] for key, value in counter.most_common(20)]


def _block_rows(blocks: List[BlockRule]) -> List[List[Any]]:
    return [[
        item.ip, item.reason, item.category, item.severity, item.source,
        item.operator, _fmt_time(item.created_at), _fmt_time(item.expires_at),
        "是" if item.dry_run else "否", item.hits,
    ] for item in blocks]


def _collect(ip: str, settings: Settings) -> Dict[str, Any]:
    """汇总封禁、威胁事件、告警与统计（时间范围：封禁前 24h → 当前/解封）。"""
    with session_scope() as session:
        blocks = session.scalars(
            select(BlockRule).where(BlockRule.ip == ip).order_by(BlockRule.created_at.desc())
        ).all()
        if not blocks:
            raise ValueError(f"{ip} 没有封禁记录，无法生成报告")
        latest = blocks[0]
        start = (latest.created_at or utcnow()) - timedelta(hours=24)
        end = latest.released_at or utcnow()
        events = session.scalars(
            select(ThreatEvent).where(
                ThreatEvent.source_ip == ip,
                ThreatEvent.ts >= start,
                ThreatEvent.ts <= end,
            ).order_by(ThreatEvent.ts.desc()).limit(int(settings.report_max_events))
        ).all()
        alerts = session.scalars(
            select(Alert).where(
                Alert.source_ip == ip, Alert.ts >= start, Alert.ts <= end,
            ).order_by(Alert.ts.desc()).limit(200)
        ).all()
        block_dicts = [{
            "id": row.id, "ip": row.ip, "reason": row.reason, "category": row.category,
            "severity": row.severity, "source": row.source, "operator": row.operator,
            "backend": row.backend, "rule_spec": row.rule_spec, "hits": row.hits,
            "dry_run": bool(row.dry_run), "active": bool(row.active),
            "created_at": _fmt_time(row.created_at),
            "expires_at": _fmt_time(row.expires_at),
            "released_at": _fmt_time(row.released_at),
        } for row in blocks]
        event_dicts = [{
            "id": row.id, "ts": _fmt_time(row.ts), "category": row.category,
            "severity": row.severity, "rule_id": row.rule_id, "rule_pack": row.rule_pack,
            "tier": row.tier, "direction": row.direction, "method": row.method,
            "path": row.path, "status_code": row.status_code,
            "capture_level": row.capture_level, "message": row.message,
            "triage_verdict": row.triage_verdict, "triage_reason": row.triage_reason,
            "request_head": row.request_head, "request_body": row.request_body,
        } for row in events]
        alert_dicts = [{
            "id": row.id, "ts": _fmt_time(row.ts, stored="local"), "category": row.category,
            "severity": row.severity, "risk_score": row.risk_score,
            "status": row.status, "blocked": bool(row.blocked),
            "direct": bool(row.direct_alert), "message": row.message,
        } for row in alerts]
    return {
        "ip": ip, "blocks": block_dicts, "events": event_dicts, "alerts": alert_dicts,
        "range": {"start": iso_local(start), "end": iso_local(end)},
        "generated_at": iso_local(utcnow()),
    }


_STYLE = """
<style>
body{font-family:"Microsoft YaHei","Noto Sans SC",Arial,sans-serif;margin:0;background:#f4f6f8;color:#1f2937;line-height:1.6;font-size:15px}
main{max-width:1080px;margin:0 auto;padding:32px;background:#fff}
h1{font-size:28px;margin:0 0 6px} h2{font-size:19px;margin:28px 0 10px;border-left:4px solid #2563eb;padding-left:10px}
h4{margin:10px 0 6px;font-size:15px} .meta{color:#6b7280;font-size:14px}
.summary{background:#eff6ff;border:1px solid #bfdbfe;padding:14px 16px;border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:14px;margin:8px 0}
th,td{border:1px solid #e5e7eb;padding:7px 8px;text-align:left;vertical-align:top}
th{background:#f3f4f6} .empty{color:#6b7280}
pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:13px;line-height:1.65}
.evidence{margin:12px 0} .grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.footer{margin-top:30px;border-top:1px solid #e5e7eb;padding-top:12px;font-size:13px;color:#6b7280;word-break:break-all}
/* 攻击特征高亮：浅色报告用深红字 + 淡红底，保证打印后仍清晰 */
mark.atk{background:#ffe3e6;color:#c01527;font-weight:700;padding:0 2px;border-radius:3px;box-shadow:inset 0 -1px 0 #f3a0aa}
pre mark.atk{background:rgba(255,77,94,.24);color:#ff9aa5;box-shadow:none}
@media print{body{background:#fff}main{max-width:none;padding:0}h2{break-after:avoid}pre{white-space:pre-wrap}mark.atk{background:#ffe3e6;color:#b3121f}}
</style>
"""


def _stats(data: Dict[str, Any]) -> Dict[str, Any]:
    events = data["events"]
    return {
        "categories": Counter(item["category"] for item in events),
        "severities": Counter(item["severity"] for item in events),
        "directions": Counter(item["direction"] for item in events),
        "rules": Counter(item["rule_id"] for item in events if item["rule_id"]),
        "paths": Counter(item["path"] for item in events if item["path"]),
        "verdicts": Counter(item["triage_verdict"] for item in events if item["triage_verdict"]),
        "timeline": Counter(item["ts"][:16] for item in events),
        "first_ts": events[-1]["ts"] if events else "-",
        "last_ts": events[0]["ts"] if events else "-",
        "worst": max((item["severity"] for item in events), default="low",
                     key=lambda value: SEVERITY_ORDER.get(value, 0)),
        "top_events": sorted(
            events, key=lambda item: (SEVERITY_ORDER.get(item["severity"], 0), item["ts"]),
            reverse=True)[:10],
    }



def render_html(data: Dict[str, Any], digest: str) -> str:
    stats = _stats(data)
    events, alerts = data["events"], data["alerts"]
    blocked = any(block["active"] for block in data["blocks"])
    block_rows = [[
        item["ip"], item["reason"], item["category"], item["severity"], item["source"],
        item["operator"], item["created_at"], item["expires_at"],
        "是" if item["dry_run"] else "否",
    ] for item in data["blocks"]]
    event_rows = [[
        item["ts"], item["category"], item["severity"], item["rule_id"],
        item["direction"], item["method"], _hl(item["path"]), item["status_code"],
        item["capture_level"],
    ] for item in stats["top_events"]]
    alert_rows = [[
        item["ts"], item["category"], item["severity"], item["risk_score"],
        item["status"], "是" if item["blocked"] else "否", _hl(item["message"], limit=200),
    ] for item in alerts[:30]]
    summary = (
        f"在 {stats['first_ts']} 至 {stats['last_ts']} 期间，源 IP {data['ip']} 触发 "
        f"{len(events)} 条威胁事件、{len(alerts)} 条聚合告警；最高严重度为 {stats['worst']}。"
        f"该 IP 当前{'仍处于' if blocked else '不在'}封禁状态。"
    )
    if not events:
        summary += "（该时间范围内未留存威胁事件，可能仅封禁了历史告警或事件已过留存期。）"

    evidence = []
    for item in stats["top_events"][:5]:
        request = (item.get("request_head") or "")
        if item.get("request_body"):
            request += "\n\n" + item["request_body"]
        evidence.append(
            f"<div class='evidence'><h4>事件 #{_esc(item['id'])} · {_esc(item['rule_id'])}"
            f"（{_esc(item['capture_level'])}）</h4>"
            f"<pre>{_hl(request) if request else _esc('当前采集模式未包含请求快照')}</pre></div>"
        )

    timeline_rows = [[key, value] for key, value in sorted(stats["timeline"].items())][-60:]
    html_text = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>安全事件报告 · {_esc(data['ip'])}</title>{_STYLE}</head><body><main>
<h1>安全事件报告</h1>
<p class="meta">源 IP：{_esc(data['ip'])} ｜ 生成时间：{_esc(data['generated_at'])} ｜ 证据指纹：{_esc(digest)}</p>
<h2>1. 报告摘要</h2><p class="summary">{_esc(summary)}</p>
<h2>2. 封禁信息</h2>{_table(['IP','原因','类别','级别','来源','操作人','创建时间','到期时间','DRY-RUN'], block_rows)}
<h2>3. 攻击概览</h2>
<div class="grid"><div>{_table(['类别','事件数'], _counter_rows(stats['categories'], '类别'))}</div>
<div>{_table(['严重度','事件数'], _counter_rows(stats['severities'], '严重度'))}
{_table(['方向','事件数'], _counter_rows(stats['directions'], '方向'))}</div></div>
<p>时间跨度：{_esc(stats['first_ts'])} → {_esc(stats['last_ts'])} ｜ 事件数：{len(events)} ｜ 告警数：{len(alerts)}</p>
<h2>4. 攻击时间线（按分钟）</h2>{_table(['分钟','事件数'], timeline_rows)}
<h2>5. 代表性事件（Top 10）</h2>{_table(['时间','类别','级别','规则','方向','方法','路径','状态码','保真度'], event_rows, raw_cols=[6])}
<h2>6. 请求/响应证据</h2>
<p class="meta">红色标注为命中的攻击特征（命令执行 / SQL 注入 / XSS / 目录穿越 / 反序列化等）。</p>
{''.join(evidence) or '<p class="empty">当前采集模式未包含请求快照。</p>'}
<h2>7. 影响评估</h2>
<p>涉及业务路径：{_hl(', '.join(path for path, _ in stats['paths'].most_common(5)) or '未记录')}</p>
<p>命中 Top 规则：{_esc(', '.join(f'{rule}×{count}' for rule, count in stats['rules'].most_common(5)) or '未记录')}</p>
<p>研判分布：{_esc(', '.join(f'{key}×{value}' for key, value in stats['verdicts'].most_common()) or '未启用研判')}</p>
<p>是否疑似成功利用：需结合响应状态码与业务日志人工确认；本报告不自动给出“已失陷”结论。</p>
<h2>8. 处置与建议</h2>
<p>已执行动作：{'已下发封禁（DRY-RUN 时仅记录）' if data['blocks'] else '无'}；告警关联 {len(alerts)} 条。</p>
<p>加固建议：核对命中规则对应漏洞（参数化查询/上传白名单/命令执行白名单）；检查同源 IP 是否仍有访问；
确认封禁 TTL 与白名单；对 2xx/3xx 响应路径做业务侧日志复核。</p>
<h2>9. 附录</h2>{_table(['告警时间','类别','级别','风险分','状态','已封禁','消息'], alert_rows, raw_cols=[6])}
<div class="footer">证据摘要 SHA-256：{_esc(digest)}<br>
本报告由智能流量安全检测与分析系统自动生成；结论基于规则命中与留存证据，不替代人工取证。</div>
</main></body></html>"""
    return html_text



def generate_block_report(ip: str, operator: str = "system",
                          settings: Optional[Settings] = None) -> Dict[str, Any]:
    """生成报告、落盘并登记数据库；返回 report_id / 下载地址 / SHA-256。"""
    cfg = settings or get_settings()
    data = _collect(str(ip or "").strip(), cfg)
    digest = _sha256({
        "ip": data["ip"], "blocks": data["blocks"], "events": data["events"],
        "alerts": data["alerts"], "range": data["range"],
    })
    content = render_html(data, digest)
    folder = Path(cfg.report_path)
    folder.mkdir(parents=True, exist_ok=True)
    safe_ip = str(data["ip"]).replace(":", "_").replace("/", "_")
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    path = (folder / f"block-{safe_ip}-{stamp}.html").resolve()
    path.write_text(content, encoding="utf-8")
    block_id = data["blocks"][0]["id"] if data["blocks"] else None
    with session_scope() as session:
        row = BlockReport(block_id=block_id, ip=data["ip"], path=str(path), format="html",
                          evidence_sha256=digest, operator=operator or "system")
        session.add(row)
        session.flush()
        report_id = row.id
    return {
        "report_id": report_id, "ip": data["ip"], "sha256": digest,
        "path": str(path), "file_name": path.name,
        "view_url": f"/api/v1/reports/{report_id}",
        "download_url": f"/api/v1/reports/{report_id}/download",
        "event_count": len(data["events"]), "alert_count": len(data["alerts"]),
    }

