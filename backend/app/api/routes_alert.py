"""告警接口：列表、滚动播报、统计与人工处置。"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from ..collector.service import CollectorService
from ..database import session_scope
from ..detection.engine import CATEGORY_TEXT, SEVERITY_ORDER, SEVERITY_TEXT
from ..models import Alert, Signal, utcnow
from ..response.blocker import Blocker
from ..schemas import ActionResult, AlertOut, SignalOut
from ..timeutil import iso_local, now_local
from .deps import blocker_dep, require_token, service_dep

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_model=List[AlertOut], summary="告警列表")
def list_alerts(limit: int = Query(default=50, ge=1, le=500),
                severity: str = Query(default=""),
                category: str = Query(default=""),
                status: str = Query(default=""),
                min_score: float = Query(default=0.0, ge=0.0,
                                         description="按聚合风险分下限过滤（v2 新增）"),
                direct_only: bool = Query(default=False,
                                          description="只看直达告警（单条致命规则命中）"),
                service: CollectorService = Depends(service_dep)) -> List[AlertOut]:
    with session_scope() as session:
        query = select(Alert).order_by(Alert.ts.desc()).limit(limit)
        if severity:
            query = query.where(Alert.severity == severity)
        if category:
            query = query.where(Alert.category == category)
        if status:
            query = query.where(Alert.status == status)
        if min_score > 0:
            query = query.where(Alert.risk_score >= min_score)
        if direct_only:
            query = query.where(Alert.direct_alert.is_(True))
        rows = session.scalars(query).all()
        return [AlertOut.model_validate(row) for row in rows]


@router.get("/alerts/feed", summary="告警播报流（大屏滚动列表用，含类型中文）")
def alerts_feed(limit: int = Query(default=20, ge=1, le=100),
                service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    with session_scope() as session:
        rows = session.scalars(select(Alert).order_by(Alert.ts.desc()).limit(limit)).all()
    return {
        "total": len(rows),
        "items": [{
            "id": row.id,
            "ts": iso_local(row.ts, stored="local"),
            "source_ip": row.source_ip,
            "dest_port": row.dest_port,
            "category": row.category,
            "category_text": CATEGORY_TEXT.get(row.category, row.category),
            "severity": row.severity,
            "severity_text": SEVERITY_TEXT.get(row.severity, row.severity),
            "message": row.message,
            "blocked": row.blocked,
            "risk_score": row.risk_score,
            "direct_alert": bool(row.direct_alert),
        } for row in rows],
    }


@router.get("/alerts/stats", summary="告警统计（按类型/级别/来源分布）")
def alert_stats(hours: int = Query(default=24, ge=1, le=720),
                service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    # Alert.ts / Signal.ts 落库是本地时间，窗口起点也要用本地时间，否则统计窗口整体偏 8 小时
    since = now_local() - timedelta(hours=hours)
    with session_scope() as session:
        category_rows = session.execute(
            select(Alert.category, func.count(Alert.id)).where(Alert.ts >= since).group_by(Alert.category)
        ).all()
        severity_rows = session.execute(
            select(Alert.severity, func.count(Alert.id)).where(Alert.ts >= since).group_by(Alert.severity)
        ).all()
        src_rows = session.execute(
            select(Alert.source_ip, func.count(Alert.id))
            .where(Alert.ts >= since, Alert.source_ip != "")
            .group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(10)
        ).all()
        total = session.scalar(select(func.count(Alert.id)).where(Alert.ts >= since)) or 0
        blocked = session.scalar(
            select(func.count(Alert.id)).where(Alert.ts >= since, Alert.blocked.is_(True))
        ) or 0
        direct = session.scalar(
            select(func.count(Alert.id)).where(Alert.ts >= since, Alert.direct_alert.is_(True))
        ) or 0
        risk_avg = session.scalar(
            select(func.avg(Alert.risk_score)).where(Alert.ts >= since)
        ) or 0.0
        signals_total = session.scalar(select(func.count(Signal.id)).where(Signal.ts >= since)) or 0
        signals_suppressed = session.scalar(
            select(func.count(Signal.id)).where(Signal.ts >= since, Signal.suppressed.is_(True))
        ) or 0
    return {
        "window_hours": hours,
        "total": int(total),
        "blocked": int(blocked),
        "direct": int(direct),
        "avg_risk_score": round(float(risk_avg), 3),
        "signals": {"total": int(signals_total), "suppressed": int(signals_suppressed)},
        "by_category": [{"category": row[0], "category_text": CATEGORY_TEXT.get(row[0], row[0]),
                         "count": int(row[1])} for row in category_rows],
        "by_severity": [{"severity": row[0], "severity_text": SEVERITY_TEXT.get(row[0], row[0]),
                         "count": int(row[1])} for row in severity_rows],
        "top_sources": [{"ip": row[0], "count": int(row[1])} for row in src_rows],
        "severity_order": SEVERITY_ORDER,
    }


@router.get("/alerts/{alert_id}", summary="告警详情（含证据快照，供处置抽屉使用）")
def get_alert(alert_id: int, service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    with session_scope() as session:
        row = session.get(Alert, alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail="告警不存在")
        return {
            "id": row.id,
            "ts": iso_local(row.ts, stored="local"),
            "source_ip": row.source_ip,
            "dest_ip": row.dest_ip,
            "dest_port": row.dest_port,
            "protocol": row.protocol,
            "category": row.category,
            "category_text": CATEGORY_TEXT.get(row.category, row.category),
            "severity": row.severity,
            "severity_text": SEVERITY_TEXT.get(row.severity, row.severity),
            "score": row.score,
            "message": row.message,
            "evidence": row.evidence or {},
            "status": row.status,
            "blocked": row.blocked,
            "region": row.region,
            "disposed_by": row.disposed_by,
            "disposed_at": iso_local(row.disposed_at),
            "suggestion": _suggestion(row.category, row.severity),
            # ---- v2：评分 / 直达 / 窗口 / AI 研判（老字段一个都没动）----
            "risk_score": row.risk_score,
            "contributing_rules": list(row.contributing_rules or []),
            "direct_alert": bool(row.direct_alert),
            "signal_window_id": row.signal_window_id,
            "suppressed": bool(row.suppressed),
            "suppressed_reason": row.suppressed_reason,
            "aggregation": (row.evidence or {}).get("aggregation", {}),
            "signals": _window_signals(row),
            "llm_analysis": row.llm_analysis,
            "llm_source": (row.llm_analysis or {}).get("source", "pending"),
            "llm_ready": row.llm_analysis is not None,
        }


def _window_signals(alert: Alert) -> List[Dict[str, Any]]:
    """该告警所属窗口内的全部 signals（直达告警窗口长度为 1，同样保留该字段）。"""
    window_id = alert.signal_window_id
    if not window_id:
        return []
    with session_scope() as session:
        rows = session.scalars(
            select(Signal).where(Signal.signal_window_id == window_id).order_by(Signal.ts.asc())
        ).all()
        return [{
            "id": row.id,
            "ts": iso_local(row.ts, stored="local"),
            "rule_id": row.rule_id,
            "category": row.category,
            "severity": row.severity,
            "confidence": row.confidence,
            "weight": row.weight,
            "direct_alert": bool(row.direct_alert),
            "suppressed": bool(row.suppressed),
            "suppressed_reason": row.suppressed_reason,
        } for row in rows]


@router.post("/alerts/{alert_id}/reanalyze", response_model=ActionResult,
             summary="重新研判告警（走 AI 研判降级链）")
def reanalyze_alert(alert_id: int, _: None = Depends(require_token),
                    service: CollectorService = Depends(service_dep)) -> ActionResult:
    """同步触发一次研判（完整降级链），结果写回 llm_analysis 并返回。"""
    result = service.enricher.enrich(alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="告警不存在")
    return ActionResult(
        success=True,
        message=f"研判完成：来源 {result.get('source')}，结论 {result.get('verdict')}"
                + ("（已降级）" if result.get("degraded") else ""),
        code="degraded" if result.get("degraded") else "ok",
        detail={"analysis": result},
    )


@router.get("/signals", response_model=List[SignalOut], summary="检测信号（评分聚合的原子输入）")
def list_signals(limit: int = Query(default=50, ge=1, le=500),
                 source_ip: str = Query(default=""),
                 category: str = Query(default=""),
                 suppressed_only: bool = Query(default=False),
                 service: CollectorService = Depends(service_dep)) -> List[SignalOut]:
    """信号列表：既含已告警的信号，也含被抑制的信号（降级可见，禁止静默丢弃）。"""
    with session_scope() as session:
        query = select(Signal).order_by(Signal.ts.desc()).limit(limit)
        if source_ip:
            query = query.where(Signal.source_ip == source_ip)
        if category:
            query = query.where(Signal.category == category)
        if suppressed_only:
            query = query.where(Signal.suppressed.is_(True))
        rows = session.scalars(query).all()
        return [SignalOut.model_validate(row) for row in rows]


@router.get("/signals/window/{source_ip}", summary="某个源 IP 当前评分窗口内的信号")
def signal_window(source_ip: str, service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    window = service.aggregator.window(source_ip)
    return {
        "source_ip": source_ip,
        "window_sec": service.aggregator.window_sec,
        "threshold": service.aggregator.threshold,
        "total": len(window),
        "items": [{
            "rule_id": item.rule_id, "category": item.category, "severity": item.severity,
            "confidence": item.confidence, "weight": item.weight,
            "direct_alert": bool(item.direct_alert), "suppressed": bool(item.suppressed),
            "suppressed_reason": item.suppressed_reason,
            "ts": iso_local(item.ts, stored="local"),
        } for item in window],
    }


@router.get("/scoring/config", summary="评分与直达机制当前配置（含运行态统计）")
def scoring_config(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    aggregator = service.aggregator
    return {
        "window_sec": aggregator.window_sec,
        "threshold": aggregator.threshold,
        "direct_alert_enabled": aggregator.direct_enabled,
        "direct_alert_weight": aggregator.direct_weight,
        "cooldown_sec": int(aggregator.cooldown_sec),
        "max_signals_per_window": aggregator.max_signals,
        "bonus": {
            "multi_category_2": aggregator.bonus_2,
            "multi_category_3": aggregator.bonus_3,
            "critical": aggregator.critical_bonus,
        },
        "weight_table": {"critical": 5.0, "high": 3.0, "medium": 1.5, "low": 0.5},
        "confidence_factor": {"high": 1.2, "medium": 1.0, "low": 0.8},
        "stats": service.scoring_stats(),
        "note": "直达机制（direct_alert）不参与自适应阈值调整：规则固有属性，不随误报反馈变化。",
    }


def _suggestion(category: str, severity: str) -> str:
    """给运维的处置建议（页面上直接展示，降低使用门槛）。"""
    tips = {
        "port_scan": "确认该源 IP 是否为授权的巡检系统；若不是，建议立即封禁并排查其后续横向探测行为。",
        "brute_force": "立即封禁源 IP，并检查被攻击服务的登录日志（auth.log / 安全事件），必要时临时关闭密码登录、启用密钥或双因素。",
        "nonstandard_port": "确认该端口对应的业务进程是否为已知服务（netstat -tunlp | grep <端口>）；非已知服务建议封禁源 IP 并排查是否存在后门。",
        "traffic_spike": "先确认是否为业务高峰或备份窗口；若非预期，检查是否存在 DDoS、数据外泄或挖矿流量，必要时在边界限速/清洗。",
        "behavior_anomaly": "该主机行为偏离历史画像，建议人工核对其业务变更，必要时加入观察名单并提高该主机告警灵敏度。",
        # ---- Web 攻击类（知识库：backend/data/web_attack_rules.json）----
        "web_sql_injection": "定位被攻击接口并改用参数化查询；封禁来源 IP，核查数据库是否被拖库（binlog / 慢查询 / 审计日志）。",
        "web_sql_injection_blind": "盲注通常伴随大量相似请求：封禁来源网段、检查数据库负载与出网行为，并修复注入点。",
        "web_xss_reflected": "修复回显参数的输出编码；对来源 IP 限速，排查是否在批量扫描搜索/投票类接口。",
        "web_xss_stored": "清理已入库的恶意内容（留言/昵称/资料），对输出做上下文转义，并封禁提交者。",
        "web_command_injection": "立即隔离主机取证：检查进程、计划任务、反弹 Shell；封禁来源 IP 并修复命令拼接逻辑。",
        "web_file_inclusion": "确认被包含的文件范围，检查 Web 根是否出现异常文件；关闭 allow_url_include 并封禁来源 IP。",
        "web_file_upload": "检查上传目录是否已有脚本落地（Webshell），禁止该目录执行脚本；封禁来源并轮换相关凭据。",
        "web_brute_force": "封禁来源 IP；检查登录日志与失败账号；对登录接口启用验证码、失败锁定与双因素认证。",
        "web_insecure_captcha": "验证码改为服务端强校验（一次性 + 有效期 + 会话绑定）；对验证码接口限速。",
        "web_path_traversal": "确认是否可读取敏感文件；路径参数改为白名单映射；轮换可能已泄露的密钥。",
        "web_csrf": "确认对应接口是否缺少 CSRF Token；补齐 Token + SameSite；核查该来源是否为恶意诱导页面。",
        "web_ssrf": "确认内网目标与云元数据是否可达；收紧出站白名单；封禁来源 IP 并核查是否已读取凭据。",
        "web_xxe": "确认 XML 解析是否开启外部实体并改为安全解析器；排查已泄露文件与凭据。",
        "web_webshell": "高度疑似主机已被控制：立即封禁来源、隔离主机、定位删除后门文件并轮换凭据。",
        "web_ssti": "定位模板渲染点并改为数据与模板分离；封禁来源 IP，检查是否已执行系统命令。",
        "web_ldap_nosql_injection": "对 LDAP/Mongo 查询做参数化与类型校验；封禁来源 IP，检查账号数据是否被遍历。",
        "web_crlf_injection": "对进入响应头的参数做 CR/LF 过滤；封禁来源 IP，检查是否已注入假 Cookie 或跳转。",
    }
    base = tips.get(category, "建议人工核对流量与主机日志后再决定处置动作。")
    return base + ("该事件为高危/紧急级别，建议 30 分钟内响应。" if severity in ("high", "critical") else "")


@router.post("/alerts/{alert_id}/ack", response_model=ActionResult, summary="确认告警")
def ack_alert(alert_id: int, operator: str = Query(default="admin"),
              _: None = Depends(require_token),
              service: CollectorService = Depends(service_dep)) -> ActionResult:
    with session_scope() as session:
        row = session.get(Alert, alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail="告警不存在")
        row.status = "closed"
        row.disposed_by = operator
        row.disposed_at = utcnow()
    return ActionResult(success=True, message=f"告警 {alert_id} 已确认关闭")


@router.post("/alerts/{alert_id}/block", response_model=ActionResult, summary="一键封禁告警源 IP")
def block_alert_source(alert_id: int, ttl_sec: Optional[int] = Query(default=None),
                       operator: str = Query(default="admin"),
                       _: None = Depends(require_token),
                       blocker: Blocker = Depends(blocker_dep)) -> ActionResult:
    with session_scope() as session:
        row = session.get(Alert, alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail="告警不存在")
        source_ip, message, category, severity = row.source_ip, row.message, row.category, row.severity

    if not source_ip:
        raise HTTPException(status_code=400, detail="该告警没有可封禁的源 IP")

    result = blocker.block(ip=source_ip, reason=f"[人工确认] {message}", category=category,
                           severity=severity, ttl_sec=ttl_sec, source="manual", operator=operator)
    return ActionResult(success=bool(result.get("success")), message=str(result.get("message")), detail=result)


@router.get("/disposals", summary="处置时间线（封禁/解封/扫描流水）")
def disposal_timeline(limit: int = Query(default=30, ge=1, le=200),
                      blocker: Blocker = Depends(blocker_dep)) -> Dict[str, Any]:
    items = blocker.disposal_logs(limit)
    return {"total": len(items), "items": items}

