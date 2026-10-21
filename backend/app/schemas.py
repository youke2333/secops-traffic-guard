"""Pydantic 出参 / 入参模型（API 契约）。"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------- 指标 ----------------
class MetricPoint(BaseModel):
    ts: float = Field(description="Unix 时间戳（秒，含毫秒）")
    bps_in: float = 0.0
    bps_out: float = 0.0
    pps_in: float = 0.0
    pps_out: float = 0.0
    conns: int = 0
    unique_src: int = 0
    unique_dst_ports: int = 0


class KpiOverview(BaseModel):
    iface: str = ""
    mode: str = "demo"
    uptime_sec: float = 0.0
    bps_in: float = 0.0
    bps_out: float = 0.0
    bandwidth_util: float = Field(default=0.0, description="带宽利用率 %")
    pps: float = 0.0
    conns: int = 0
    packets_total: int = 0
    bytes_total: int = 0
    alerts_total: int = 0
    alerts_open: int = 0
    blocked_total: int = 0
    blocked_active: int = 0
    assets_total: int = 0
    vulns_open: int = 0
    risk_score: float = 0.0
    firewall_backend: str = "none"
    dry_run: bool = True


class PortTrafficOut(BaseModel):
    port: int
    protocol: str = "TCP"
    pps: float = 0.0
    bps: float = 0.0
    conns: int = 0
    is_standard: bool = True
    top_source: str = ""
    anomaly: bool = False
    score: float = 0.0


class TrendOut(BaseModel):
    window_sec: int
    interval_ms: int
    points: List[MetricPoint] = []


# ---------------- 检测 ----------------
class AnomalyOut(BaseModel):
    category: str
    severity: str
    score: float
    source_ip: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    protocol: str = "TCP"
    message: str = ""
    evidence: Dict[str, Any] = {}
    detector: str = ""


# ---------------- 告警 ----------------
class AlertOut(ORMModel):
    id: int
    ts: datetime
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    category: str
    severity: str
    score: float
    message: str
    evidence: Dict[str, Any] = {}
    status: str
    blocked: bool
    region: str = "内网"
    disposed_by: str = ""
    disposed_at: Optional[datetime] = None
    # ---- v2 新增（全部可空/有默认值：老客户端不受影响，只增不删）----
    risk_score: float = 0.0
    contributing_rules: List[str] = []
    direct_alert: bool = False
    signal_window_id: Optional[str] = None
    suppressed: bool = False
    suppressed_reason: Optional[str] = None
    llm_analysis: Optional[Dict[str, Any]] = None

    @field_validator("contributing_rules", mode="before")
    @classmethod
    def _none_to_list(cls, value: Any) -> Any:
        """旧库迁移后列值可能为 NULL：统一归一化成 []，避免 500。"""
        return value if value is not None else []

    @field_validator("evidence", mode="before")
    @classmethod
    def _none_to_dict(cls, value: Any) -> Any:
        return value if value is not None else {}


class AlertFeedItem(BaseModel):
    """大屏滚动列表用的精简结构。"""

    id: int
    ts: datetime
    source_ip: str
    dest_port: int
    category: str
    category_text: str
    severity: str
    message: str


# ---------------- 评分 / 信号 / 阈值（v2 新增接口的出入参） ----------------
class SignalOut(ORMModel):
    id: int
    ts: datetime
    source_ip: str = ""
    dst_port: int = 0
    rule_id: str = ""
    category: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    weight: float = 0.0
    direct_alert: bool = False
    suppressed: bool = False
    suppressed_reason: Optional[str] = None
    score_contribution: float = 0.0
    signal_window_id: Optional[str] = None
    alert_id: Optional[int] = None


class ThresholdOverride(BaseModel):
    threshold_value: float = Field(description="人工覆盖后的阈值")
    reason: str = Field(default="", description="覆盖原因（写入审计）")
    operator: str = Field(default="admin")


# ---------------- 封禁 ----------------
class BlockCreate(BaseModel):
    ip: str
    reason: str = "人工封禁"
    category: str = "manual"
    severity: str = "high"
    ttl_sec: Optional[int] = Field(default=None, description="留空使用全局默认值")
    operator: str = "admin"

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, value: str) -> str:
        from ipaddress import ip_address, ip_network

        value = value.strip()
        try:
            if "/" in value:
                ip_network(value, strict=False)
            else:
                ip_address(value)
        except ValueError as exc:  # 阻断命令注入与非法输入
            raise ValueError(f"非法 IP/CIDR: {value}") from exc
        return value


class BlockOut(ORMModel):
    id: int
    ip: str
    reason: str
    category: str
    severity: str
    backend: str
    source: str
    operator: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    released_at: Optional[datetime] = None
    active: bool
    hits: int
    dry_run: bool
    remaining_sec: Optional[int] = None


class WhitelistCreate(BaseModel):
    cidr: str
    note: str = ""
    operator: str = "admin"

    @field_validator("cidr")
    @classmethod
    def _check_cidr(cls, value: str) -> str:
        from ipaddress import ip_network

        value = value.strip()
        try:
            ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError(f"非法 CIDR: {value}") from exc
        return value


class WhitelistOut(ORMModel):
    id: int
    cidr: str
    note: str
    operator: str
    created_at: datetime


# ---------------- 资产 ----------------
class AssetOut(ORMModel):
    id: int
    ip: str
    mac: str = ""
    hostname: str = ""
    os_guess: str = ""
    open_ports: List[int] = []
    services: List[Dict[str, Any]] = []
    risk_level: str
    tags: List[str] = []
    bytes_in: int = 0
    bytes_out: int = 0
    alert_count: int = 0
    vuln_count: int = 0
    first_seen: datetime
    last_seen: datetime


# ---------------- 漏洞 ----------------
class VulnOut(ORMModel):
    id: int
    asset_ip: str
    port: int
    service: str
    cve: str
    title: str
    severity: str
    cvss: float
    evidence: str
    recommendation: str
    fixed_version: str
    status: str
    found_at: datetime
    # scan=端口/版本+CVE，web=Web 配置与暴露面，traffic_rule/traffic_ai=攻击流量研判
    source: str = "scan"
    # confirmed=响应中有客观证据，suspected=仅有请求特征
    confidence: str = ""
    ai_advice: Optional[Dict[str, Any]] = None
    ai_source: str = ""


class WebAppScanRequest(BaseModel):
    """Web 应用漏扫请求（直接给业务访问地址）。"""

    url: str = Field(..., description="如 http://192.168.1.20:8080/app/")
    port: Optional[int] = Field(default=None, description="留空从 URL 解析")


class ScanRequest(BaseModel):
    targets: List[str] = Field(default=[], description="留空则扫描已知资产与其开放端口")
    ports: str = Field(default="", description="nmap 端口表达式，如 1-1024")
    use_nmap: bool = True
    sync_hint: bool = Field(default=False, description="目标很少时允许同步等待（仅小型验证用）")


class ScanSummary(BaseModel):
    targets: int
    services_found: int
    vulns_found: int
    duration_sec: float
    details: List[Dict[str, Any]] = []


# ---------------- 处置 / 时间线 ----------------
class DisposalOut(ORMModel):
    id: int
    ts: datetime
    action: str
    target: str
    detail: str
    operator: str
    success: bool


class ActionResult(BaseModel):
    """统一动作返回。

    ``code`` 用于承载语义化结果，便于前端/调用方做分支处理：
    ok / whitelisted / duplicated / firewall_failed / invalid ...
    """

    success: bool
    message: str
    code: str = "ok"
    detail: Dict[str, Any] = {}


class HealthOut(BaseModel):
    status: str = "ok"
    version: str
    capture_mode: str
    firewall_backend: str
    dry_run: bool
    channels: List[str] = []
    db: str = ""


# ---------------- Web 攻击检测 ----------------
class WebRequestIn(BaseModel):
    """单条 HTTP 请求（外部投递 / 规则自测）。

    传 ``path`` 时可带查询串（``/a?b=1``），会自动拆分到 ``query``。
    """

    src_ip: str = Field(default="", description="请求来源 IP")
    dst_ip: str = Field(default="", description="被访问主机 IP")
    src_port: int = 0
    dst_port: int = 80
    method: str = "GET"
    path: str = "/"
    query: str = Field(default="", description="查询串（不含 ?）")
    body: str = Field(default="", description="请求体（表单 / multipart / XML / JSON）")
    headers: Dict[str, str] = Field(default={}, description="请求头，键名建议小写（user-agent/referer/cookie/content-type）")
    status: int = Field(default=0, description="响应状态码，用于 401/403 类频次规则")
    response_head: str = Field(default="", description="响应头快照（脱敏后，可选）")
    response_body: str = Field(default="", description="文本响应体快照（截断后，可选）")
    ts: Optional[float] = Field(default=None, description="事件时间戳（留空取服务端当前时间）")
    source: str = Field(default="api", description="数据来源标记：log|demo|api|waf")


class WebRequestsIn(BaseModel):
    """批量投递（WAF / 反向代理一次上报多条请求）。"""

    requests: List[WebRequestIn] = Field(default=[], description="最多 200 条，超出部分忽略")

