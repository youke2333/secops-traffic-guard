"""ORM 数据模型：资产、告警、封禁、白名单、漏洞、流量时序样本、处置日志。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def utcnow() -> datetime:
    """统一使用 naive UTC，避免 SQLite/PostgreSQL 混用时的时区歧义。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Asset(Base):
    """资产台账：由流量特征 + 主动探测持续更新，关联告警/漏洞。"""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    mac: Mapped[str] = mapped_column(String(32), default="")
    hostname: Mapped[str] = mapped_column(String(255), default="")
    os_guess: Mapped[str] = mapped_column(String(120), default="")
    open_ports: Mapped[list] = mapped_column(JSON, default=list)      # [22, 80, 443]
    services: Mapped[list] = mapped_column(JSON, default=list)         # [{port,name,product,version,banner}]
    risk_level: Mapped[str] = mapped_column(String(16), default="unknown")
    tags: Mapped[list] = mapped_column(JSON, default=list)             # ["web", "db", "internal"]
    pkt_in: Mapped[int] = mapped_column(BigInteger, default=0)
    pkt_out: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Alert(Base):
    """安全告警（异常端口/突发流量/长连接/扫描/暴破）。"""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    dest_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    dest_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(16), default="TCP")
    category: Mapped[str] = mapped_column(String(48), index=True)      # port_scan / brute_force / ...
    severity: Mapped[str] = mapped_column(String(16), index=True, default="medium")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    message: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open")    # open|blocked|ignored|closed
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    region: Mapped[str] = mapped_column(String(64), default="内网")
    disposed_by: Mapped[str] = mapped_column(String(64), default="")
    disposed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    # ---- 聚合评分 / 直达机制 / LLM 研判（v2 新增字段，全部可空，旧接口只增不删）----
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)          # 滑动窗口聚合风险分
    contributing_rules: Mapped[list] = mapped_column(JSON, default=list)   # 参与聚合的规则 ID
    direct_alert: Mapped[bool] = mapped_column(Boolean, default=False)     # 是否由直达机制触发
    signal_window_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)       # 是否被冷却抑制
    suppressed_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    llm_analysis: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    __table_args__ = (Index("ix_alerts_ts_category", "ts", "category"),)

    @property
    def is_direct(self) -> bool:
        return bool(self.direct_alert)


class Signal(Base):
    """检测信号：告警聚合的原子输入（未达阈值的信号同样落库，保证"降级可见"）。"""

    __tablename__ = "signals"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    rule_id: Mapped[str] = mapped_column(String(128), index=True, default="")
    category: Mapped[str] = mapped_column(String(64), index=True, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    weight: Mapped[float] = mapped_column(Float, default=0.0)
    direct_alert: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed_reason: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    score_contribution: Mapped[float] = mapped_column(Float, default=0.0)
    signal_window_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    alert_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)


class ThresholdConfig(Base):
    """维度化检测阈值（自适应基线的落地形态：detection_type × asset_class × time_bucket）。"""

    __tablename__ = "threshold_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    dimension: Mapped[str] = mapped_column(String(32), index=True, default="detection_type")
    dimension_key: Mapped[str] = mapped_column(String(64), index=True, default="")
    detection_type: Mapped[str] = mapped_column(String(32), default="", index=True)
    asset_class: Mapped[str] = mapped_column(String(32), default="unknown")
    time_bucket: Mapped[str] = mapped_column(String(16), default="workhour")
    static_value: Mapped[float] = mapped_column(Float, default=0.0)      # 配置里的静态基准
    threshold_value: Mapped[float] = mapped_column(Float, default=0.0)   # 生效阈值
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    true_positive_count: Mapped[int] = mapped_column(Integer, default=0)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)
    manual_override: Mapped[bool] = mapped_column(Boolean, default=False)
    override_reason: Mapped[str] = mapped_column(String(255), default="")
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("detection_type", "asset_class", "time_bucket",
                         name="uq_threshold_dimension"),
    )


class BlockRule(Base):
    """封禁记录（与防火墙实际规则一一对应，支持 TTL 自动解封）。"""

    __tablename__ = "block_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(48), default="")
    severity: Mapped[str] = mapped_column(String(16), default="high")
    backend: Mapped[str] = mapped_column(String(24), default="")
    rule_spec: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(32), default="auto")    # auto|manual|api
    operator: Mapped[str] = mapped_column(String(64), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    released_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)


class WhitelistEntry(Base):
    """白名单（支持单 IP 与 CIDR 网段），封禁前强制校验。"""

    __tablename__ = "whitelist"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    note: Mapped[str] = mapped_column(String(255), default="")
    operator: Mapped[str] = mapped_column(String(64), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Vulnerability(Base):
    """漏洞扫描结果与修复建议（CVE 知识库匹配）。"""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_ip: Mapped[str] = mapped_column(String(64), index=True)
    port: Mapped[int] = mapped_column(Integer, default=0)
    service: Mapped[str] = mapped_column(String(120), default="")
    cve: Mapped[str] = mapped_column(String(32), index=True, default="")
    title: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    fixed_version: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(16), default="open")     # open|fixing|fixed|ignored
    found_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    # ---- 发现途径与研判可信度 ----
    # scan：端口/版本 + CVE 知识库；web：Web 应用配置与暴露面体检；
    # traffic_rule / traffic_ai：由捕获到的攻击请求+响应研判得出（后者经模型复核）
    source: Mapped[str] = mapped_column(String(16), default="scan", index=True)
    # confirmed：响应里有客观证据；suspected：仅有请求特征或证据不充分
    confidence: Mapped[str] = mapped_column(String(16), default="")
    # ---- AI 修复建议（v3 新增；可空，旧库迁移后为空表示尚未生成）----
    ai_advice: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ai_source: Mapped[str] = mapped_column(String(32), default="")


class TrafficSample(Base):
    """整机流量时序样本（同时写入 InfluxDB 备查）。"""

    __tablename__ = "traffic_samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    iface: Mapped[str] = mapped_column(String(64), default="")
    bps_in: Mapped[float] = mapped_column(Float, default=0.0)
    bps_out: Mapped[float] = mapped_column(Float, default=0.0)
    pps_in: Mapped[float] = mapped_column(Float, default=0.0)
    pps_out: Mapped[float] = mapped_column(Float, default=0.0)
    conns: Mapped[int] = mapped_column(Integer, default=0)
    unique_src: Mapped[int] = mapped_column(Integer, default=0)
    unique_dst_ports: Mapped[int] = mapped_column(Integer, default=0)


class PortTrafficSample(Base):
    """端口级流量样本，用于"异常端口 TOP"与端口基线。"""

    __tablename__ = "port_traffic_samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(8), default="TCP")
    is_standard: Mapped[bool] = mapped_column(Boolean, default=True)
    conns: Mapped[int] = mapped_column(Integer, default=0)
    bps: Mapped[float] = mapped_column(Float, default=0.0)
    pps: Mapped[float] = mapped_column(Float, default=0.0)
    top_source: Mapped[str] = mapped_column(String(64), default="")


class DisposalLog(Base):
    """处置流水：封禁/解封/扫描/白名单变更，用于大屏时间线与审计。"""

    __tablename__ = "disposal_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    action: Mapped[str] = mapped_column(String(32))     # block|unblock|extend|whitelist_add|scan
    target: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    operator: Mapped[str] = mapped_column(String(64), default="system")
    success: Mapped[bool] = mapped_column(Boolean, default=True)


class User(Base):
    """登录用户（密码只存 scrypt 派生值，永不落明文）。"""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(16), default="viewer", index=True)  # admin|analyst|viewer
    display_name: Mapped[str] = mapped_column(String(128), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class UserSession(Base):
    """服务端会话（Cookie 里是随机 token，库中只存 sha256，便于即时踢下线）。"""

    __tablename__ = "sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")


class AuditLog(Base):
    """安全审计：登录、退出、封禁、规则、报告、导出等敏感动作。"""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="", index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    success: Mapped[bool] = mapped_column(Boolean, default=True)

    __table_args__ = (Index("ix_audit_user_ts", "username", "ts"),)


class ThreatEvent(Base):
    """一次规则命中的原始记录（聚合前落库：被抑制的命中同样可追溯）。"""

    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    alert_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    source_port: Mapped[int] = mapped_column(Integer, default=0)
    dest_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    dest_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(16), default="TCP")
    direction: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    category: Mapped[str] = mapped_column(String(64), default="", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    confidence: Mapped[str] = mapped_column(String(16), default="medium")
    rule_id: Mapped[str] = mapped_column(String(128), default="", index=True)
    rule_pack: Mapped[str] = mapped_column(String(32), default="")
    tier: Mapped[str] = mapped_column(String(16), default="")
    triage_verdict: Mapped[str] = mapped_column(String(16), default="")
    triage_rule_id: Mapped[str] = mapped_column(String(64), default="")
    triage_reason: Mapped[str] = mapped_column(Text, default="")
    score_delta: Mapped[float] = mapped_column(Float, default=0.0)
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    method: Mapped[str] = mapped_column(String(16), default="")
    host: Mapped[str] = mapped_column(String(255), default="")
    path: Mapped[str] = mapped_column(Text, default="")
    query: Mapped[str] = mapped_column(Text, default="")
    request_head: Mapped[str] = mapped_column(Text, default="")
    request_body: Mapped[str] = mapped_column(Text, default="")
    response_head: Mapped[str] = mapped_column(Text, default="")
    response_body: Mapped[str] = mapped_column(Text, default="")
    request_bytes: Mapped[int] = mapped_column(Integer, default=0)
    response_bytes: Mapped[int] = mapped_column(Integer, default=0)
    capture_source: Mapped[str] = mapped_column(String(24), default="")
    capture_level: Mapped[str] = mapped_column(String(8), default="L0")
    iface: Mapped[str] = mapped_column(String(64), default="")
    src_mac: Mapped[str] = mapped_column(String(32), default="")
    dst_mac: Mapped[str] = mapped_column(String(32), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (
        Index("ix_threat_src_ts", "source_ip", "ts"),
        Index("ix_threat_cat_ts", "category", "ts"),
        Index("ix_threat_dir_ts", "direction", "ts"),
        Index("ix_threat_sev_ts", "severity", "ts"),
        Index("ix_threat_rule_ts", "rule_id", "ts"),
    )


class ThreatTag(Base):
    """威胁事件标签（精确筛选，避免 JSON LIKE 全表扫描）。"""

    __tablename__ = "threat_tags"

    event_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tag: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)


class BlockReport(Base):
    """封禁证据报告（自包含 HTML，库存放路径与证据 SHA-256）。"""

    __tablename__ = "block_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    block_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    path: Mapped[str] = mapped_column(Text)
    format: Mapped[str] = mapped_column(String(16), default="html")
    evidence_sha256: Mapped[str] = mapped_column(String(64), default="")
    operator: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)



