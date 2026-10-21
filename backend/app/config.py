"""全局配置。

所有可调参数集中于此，支持环境变量 / .env 文件覆盖（容器部署推荐全部走环境变量）。
命名与 docker-compose.yml 中的 environment 段一一对应。
"""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


def _split_env_list(value: object) -> object:
    """允许 WHITELIST_CIDRS=10.0.0.0/8,192.168.1.1 这种逗号分隔写法。

    说明：默认 pydantic-settings 会对复杂类型先做 JSON 解码，``10.0.0.0/8`` 这类值会直接报错，
    因此这里关闭了解码（见 model_config.enable_decoding），统一由本函数解析。
    """
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return []
        if raw.startswith("["):      # 兼容 JSON 数组写法
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return [item.strip() for item in raw.strip("[]").split(",") if item.strip()]
        return [item.strip() for item in raw.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        enable_decoding=False,   # 关闭复杂类型 JSON 解码，交给我们自己的逗号分隔解析器
    )

    # ---------- 基础 ----------
    app_name: str = "智能流量安全检测与分析系统"
    app_version: str = "3.0.0"
    debug: bool = False
    api_token: str = Field(default="", description="X-API-Token 值，为空表示内网免认证")
    cors_origins: str = "*"
    dashboard_dir: str = Field(default="", description="大屏静态目录，留空自动定位 <repo>/dashboard")

    # ---------- 存储 ----------
    db_url: str = "sqlite:///./data/secops.db"
    influx_url: str = Field(default="", description="InfluxDB v2 地址，如 http://influxdb:8086")
    influx_token: str = ""
    influx_org: str = "secops"
    influx_bucket: str = "traffic"

    # ---------- 采集 ----------
    capture_mode: str = Field(default="auto", description="auto|ebpf|scapy|demo")
    capture_iface: str = Field(default="", description="网卡名，留空自动挑选默认路由网卡")
    bpf_filter: str = "ip and (tcp or udp)"
    tick_interval_ms: int = Field(default=500, ge=50, description="聚合/推送周期，毫秒")
    link_speed_mbps: int = Field(default=1000, ge=1, description="网卡标称带宽，用于计算带宽利用率")
    trend_points: int = Field(default=600, ge=60, description="趋势图保留点数")
    conn_idle_timeout_sec: int = 120

    # ---------- 检测 ----------
    zscore_threshold: float = 3.5
    anomaly_warmup_ticks: int = 20
    port_scan_unique_ports: int = 60
    port_scan_window_sec: int = 10
    brute_force_attempts: int = 40
    standard_ports: List[int] = Field(
        default=[
            20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143, 161, 389, 443, 465, 514,
            587, 636, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379,
            8000, 8080, 8443, 9000, 9200, 27017,
        ],
        description="标准端口白名单（非此类端口的高频访问才会被判为疑似恶意）",
    )
    brute_force_ports: List[int] = Field(
        default=[21, 22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017]
    )
    # 突发流量告警基线 = 100Mbps 起报、200Mbps 直达：
    #   spike_min_abs_bps    —— 告警基线，低于该值一律不判突发（默认 100Mbps）；
    #   spike_bps_threshold  —— 硬阈值 / 直达线，达到即 critical 并可直接触发自动封禁（默认 200Mbps）；
    #   两者之间（100~200Mbps）按 Z 偏离给 high / medium，保留分级处置空间。
    spike_bps_threshold: int = Field(
        default=200 * 1024 * 1024, description="突发峰值硬阈值 bps（默认 200Mbps，达到即 critical 直达）"
    )
    spike_detect_enabled: bool = Field(
        default=True, description="是否启用「整机流量突发」统计检测（关闭后仅保留端口/连接类检测）"
    )
    spike_min_abs_bps: int = Field(
        default=100 * 1024 * 1024,
        ge=0,
        description="突发流量告警基线 bps（默认 100Mbps）：低于该值即使 Z 分数超阈也不告警",
    )
    iforest_enabled: bool = True
    iforest_contamination: float = 0.05
    detect_ignore_ips: List[str] = Field(
        default=[],
        description="流量检测忽略的源 IP/CIDR（传感器自身、授权扫描器、本机回环），用于抑制自扫描误报",
    )

    # ---------- 响应（封禁） ----------
    auto_block_enabled: bool = True
    auto_block_min_severity: str = Field(default="high", description="critical|high|medium|low")
    block_ttl_sec: int = Field(default=1800, description="自动封禁存活时间，到期自动解封")
    firewall_backend: str = Field(default="auto", description="auto|iptables|nftables|firewalld|none")
    dry_run: bool = Field(default=True, description="True=只记录不真正下发防火墙规则（安全默认）")
    firewall_chain: str = "INPUT"

    # ---------- 白名单 ----------
    whitelist_cidrs: List[str] = Field(
        default=["127.0.0.1/32", "::1/128", "169.254.0.0/16", "224.0.0.0/4"],
        description="永不封禁的网段（本地回环/组播/链路本地）",
    )

    # ---------- 告警通道 ----------
    alert_channels: List[str] = Field(default=["log"], description="log|webhook|email|syslog，可多选")
    dingtalk_webhook: str = ""
    wecom_webhook: str = ""
    generic_webhook: str = ""
    syslog_address: str = Field(default="", description="host:514")
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_ssl: bool = True
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_sender: str = ""
    smtp_recipients: List[str] = Field(default=[])
    alert_cooldown_sec: int = Field(default=60, description="同一 (源IP, 类型) 告警抑制窗口")

    # ---------- 统一规则层（内置知识库 + 开源规则库） ----------
    rules_dir: str = Field(default="", description="规则根目录，留空自动定位 backend/data")
    sigma_rules_enabled: bool = Field(default=True, description="是否加载 data/sigma_rules/*.yml")
    et_rules_enabled: bool = Field(default=True, description="是否加载 data/et_rules/*.rules")
    cve_ext_enabled: bool = Field(default=True, description="是否加载 cve_rules_extended.json")
    rule_reload_interval_sec: int = Field(default=300, ge=0, description="规则热加载间隔（0=关闭）")

    # ---------- 告警聚合评分（滑动窗口 + 直达机制） ----------
    alert_score_threshold: float = Field(default=6.0, description="聚合评分告警阈值")
    scoring_window_sec: int = Field(default=300, ge=5, description="评分滑动窗口（秒）")
    scoring_max_signals_per_window: int = Field(default=1000, ge=10, description="窗口信号上限（防御性）")
    multi_category_bonus_2: float = Field(default=1.2, description="命中 ≥2 个攻击大类时的加成")
    multi_category_bonus_3: float = Field(default=1.5, description="命中 ≥3 个攻击大类时的加成")
    critical_bonus: float = Field(default=1.3, description="窗口内存在 critical 信号时的加成")
    direct_alert_enabled: bool = Field(default=True, description="是否启用直达告警机制")
    direct_alert_weight: float = Field(default=6.0, description="单信号权重直达阈值（默认等价 critical+high）")

    # ---------- 自适应阈值 ----------
    adaptive_threshold_enabled: bool = Field(default=True, description="检测阈值是否随误报反馈自适应")
    adaptive_auto_recompute: bool = Field(default=True, description="是否后台定时重算阈值")
    threshold_recompute_interval_sec: int = Field(default=21600, ge=60, description="阈值重算周期（秒）")
    threshold_lookback_days: int = Field(default=14, ge=1, description="阈值重算回看天数")
    threshold_fp_high: float = Field(default=0.5, description="误报率高于该值时收紧阈值")
    threshold_fp_low: float = Field(default=0.1, description="误报率低于该值时放松阈值")
    threshold_tighten_factor: float = Field(default=1.3)
    threshold_loosen_factor: float = Field(default=0.9)
    threshold_min_factor: float = Field(default=0.5, description="相对静态基准的最小倍数")
    threshold_max_factor: float = Field(default=2.0, description="相对静态基准的最大倍数")

    # ---------- LLM 研判（DeepSeek 等 OpenAI 兼容接口）+ 降级链 ----------
    llm_enabled: bool = Field(default=True, description="是否启用 LLM 研判（关闭则直接走本地规则/模板）")
    llm_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com/v1"
    llm_model: str = "deepseek-v4-flash"
    llm_timeout_sec: float = Field(default=3.0, description="单次研判超时（必须远小于告警节奏）")
    llm_max_retries: int = Field(default=1, ge=0)
    llm_cache_ttl_sec: int = Field(default=3600, ge=0, description="同源同类研判结果缓存时长")
    llm_mask_internal_ip: bool = Field(default=True, description="发送给 LLM 前脱敏内网 IP")
    llm_worker_threads: int = Field(default=1, ge=1, le=4, description="异步研判工作线程数")
    llm_queue_size: int = Field(default=200, ge=8, description="研判队列上限（满则丢弃并标记待人工）")

    # ---------- 扫描 / CVE ----------
    scanner_enabled: bool = Field(
        default=True,
        description="主动扫描总开关；关闭后 /vulns/scan、/assets/{ip}/rescan、/scanner/webapp "
                    "一律返回 409，只保留被动资产学习与攻击流量研判",
    )
    nmap_path: str = "nmap"
    scan_timeout_sec: int = 300
    scan_targets: List[str] = Field(default=[], description="资产扫描目标，如 192.168.1.0/24")
    cve_rules_file: str = ""

    # ---------- Web 攻击检测（知识库 backend/data/web_attack_rules.json） ----------
    web_detect_enabled: bool = Field(default=True, description="是否启用 HTTP 侧 Web 攻击检测")
    web_attack_rules_file: str = Field(default="", description="留空使用 backend/data/web_attack_rules.json")
    web_detect_source: str = Field(
        default="auto",
        description="auto|log|demo|api|off：auto 表示配置了 WEB_LOG_PATH 就 tail 访问日志，否则用仿真请求",
    )
    web_log_path: str = Field(default="", description="nginx/Apache combined 访问日志路径（log 模式）")
    web_log_poll_sec: float = Field(default=1.0, ge=0.2, description="访问日志轮询间隔（秒）")
    web_demo_interval_sec: float = Field(default=2.5, ge=0.2, description="仿真 Web 请求间隔（秒）")
    web_detect_batch: int = Field(default=200, ge=1, description="每个 tick 最多检测的请求条数")
    web_queue_size: int = Field(default=2000, ge=64, description="Web 请求队列上限（超出丢弃最旧）")
    web_brute_force_attempts: int = Field(
        default=10, ge=1, description="登录接口暴力破解判定次数（覆盖知识库中的阈值）"
    )

    # ---------- Web 检测的通用补充配置 ----------
    web_strict_rules_file: str = Field(
        default="", description="高置信度直达规则文件，留空使用 backend/data/web_strict_rules.json"
    )
    web_ignore_ips: List[str] = Field(
        default=[],
        description="Web 检测忽略的源 IP/CIDR（传感器自身、管理机、测试主机），用于抑制自访问误报",
    )
    web_default_dst_ip: str = Field(
        default="", description="访问日志缺少目的地址时使用的默认业务地址（被防护的业务主机）"
    )
    web_default_dst_port: int = Field(
        default=8080, ge=1, le=65535, description="访问日志缺少目的端口时使用的默认业务端口"
    )
    web_auto_block_requires_direct: bool = Field(
        default=True,
        description="Web 攻击自动封禁必须由直达规则确认（单条高置信度规则），避免签名类误报导致误封",
    )

    # ---------- Web 应用漏扫（通用只读检查） ----------
    webapp_scan_enabled: bool = Field(
        default=True, description="漏洞扫描时是否探测 Web 应用（指纹 + 配置缺陷 + 暴露面）"
    )
    webapp_scan_timeout_sec: float = Field(
        default=3.0, ge=0.5, le=30.0, description="单个 Web 探测请求超时（秒）"
    )
    webapp_scan_max_pages: int = Field(
        default=24, ge=1, le=200, description="单次 Web 漏扫最多访问的页面数（同主机有界爬取）"
    )
    webapp_scan_max_seconds: float = Field(
        default=20.0, ge=2.0, le=180.0, description="单次 Web 漏扫的总耗时上限（秒）"
    )
    webapp_scan_username: str = Field(
        default="", description="需要登录才能扫描时的账号（留空则只扫匿名可见页面，不内置任何默认口令）"
    )
    webapp_scan_password: str = Field(
        default="", description="需要登录才能扫描时的口令（仅用于授权的只读漏扫）"
    )

    # ---------- 攻击流量证据 → 漏洞判定 ----------
    web_vuln_infer_enabled: bool = Field(
        default=True,
        description="是否用捕获到的攻击请求/响应研判应用层漏洞（主动漏扫看不到注入点，靠这一层补齐）",
    )
    web_vuln_infer_ai: bool = Field(
        default=True,
        description="研判时是否调用 LLM 复核；关闭或未配置 Key 时只用响应特征规则判定",
    )
    web_vuln_infer_limit: int = Field(
        default=200, ge=10, le=2000,
        description="单次研判回看的 Web 攻击事件条数（越大越全，代价是查询与模型调用变多）",
    )

    # ---------- 登录、会话与审计（v6 P0） ----------
    auth_enabled: bool = Field(
        default=True,
        description="是否启用登录/会话鉴权。关闭时退回仅 X-API-Token（不推荐，仅供内网应急）",
    )
    admin_initial_password: str = Field(
        default="", description="首次启动创建 admin 的初始密码；留空则生成随机密码并打印到启动日志"
    )
    session_ttl_sec: int = Field(default=43200, ge=300, description="会话绝对有效期（默认 12h）")
    session_idle_sec: int = Field(default=1800, ge=60, description="会话空闲超时（默认 30min）")
    login_max_fails: int = Field(default=10, ge=1, description="连续登录失败锁定阈值")
    login_lock_sec: int = Field(default=900, ge=60, description="账号锁定时长（秒）")
    password_min_len: int = Field(default=10, ge=8, le=128)
    cookie_secure: bool = Field(default=False, description="HTTPS 部署时置 true（Cookie 仅经 TLS 传输）")

    # ---------- 威胁事件留存（v6 P1） ----------
    threat_store_enabled: bool = Field(default=True, description="是否把每次规则命中落库为威胁事件")
    threat_retention_days: int = Field(default=7, ge=1, le=365, description="威胁事件保留天数")
    threat_request_max_bytes: int = Field(default=16384, ge=512, description="请求快照落库上限（字节）")
    threat_response_max_bytes: int = Field(default=8192, ge=256, description="响应快照落库上限（字节）")
    threat_mask_secrets: bool = Field(default=True, description="请求快照落库前脱敏 Cookie/Authorization")
    threat_rate_limit_per_min: int = Field(default=6000, ge=0, description="每分钟最多落库威胁事件数（0=不限）")
    threat_export_max_rows: int = Field(default=100000, ge=100, description="CSV 导出最大行数")

    # ---------- 安全事件报告（v6 P1） ----------
    report_dir: str = Field(default="", description="报告落盘目录，留空使用 data/reports")
    report_max_events: int = Field(default=200, ge=10, le=2000, description="单份报告最多引用的威胁事件数")

    # ---------- 规则包 / 分层 / 匹配引擎（v6 P2） ----------
    rulesets_enabled: bool = Field(default=True, description="是否加载 backend/data/rulesets 规则包")
    rulesets_dir: str = Field(default="", description="规则包目录，留空使用 backend/data/rulesets")
    rules_tiers: List[str] = Field(
        default=["core"], description="启用的规则档位：core / extended / lab（逗号分隔，可多选）"
    )
    rules_shadow_mode: bool = Field(
        default=False, description="影子模式：规则命中只记录威胁事件，不告警、不封禁（误报标定用）"
    )
    rules_max_count: int = Field(default=10000, ge=100, description="Web 规则总数上限（防御性）")
    rules_unknown_category: str = Field(
        default="reject", description="reject|warn：规则包出现未定义类别时拒绝加载或仅告警"
    )
    match_backend: str = Field(default="auto", description="auto|python|re2：多模式匹配后端")
    re2_max_mem_mb: int = Field(default=64, ge=8, le=1024, description="RE2 索引内存上限（MB）")
    triage_enabled: bool = Field(default=False, description="是否启用研判规则执行器（P3）")
    flow_rules_enabled: bool = Field(
        default=False,
        description="流级规则执行器开关（P3 尚未实现，当前版本无对应执行器，保持 false）",
    )
    malware_scan_enabled: bool = Field(default=False, description="是否扫描上传体病毒特征（P3）")

    # ---------- 受保护网段 / 方向判定（v6 P4 轻量落地） ----------
    protected_cidrs: List[str] = Field(
        default=[], description="受保护网段（如 192.168.152.0/24），用于判定外到内/内到外方向"
    )

    # ---------- 校验器 ----------
    @field_validator(
        "standard_ports", "brute_force_ports", "whitelist_cidrs", "alert_channels",
        "smtp_recipients", "scan_targets", "web_ignore_ips", "detect_ignore_ips",
        "rules_tiers", "protected_cidrs", mode="before",
    )
    @classmethod
    def _parse_list(cls, value: object) -> object:
        return _split_env_list(value)

    @field_validator("whitelist_cidrs", "protected_cidrs", mode="after")
    @classmethod
    def _check_cidr(cls, value: List[str]) -> List[str]:
        for item in value:
            ipaddress.ip_network(item, strict=False)  # 非法 CIDR 直接 fail-fast
        return value

    @field_validator("rules_tiers", mode="after")
    @classmethod
    def _check_tiers(cls, value: List[str]) -> List[str]:
        allowed = {"core", "extended", "lab"}
        cleaned: List[str] = []
        for item in value:
            tier = str(item).strip().lower()
            if tier and tier not in allowed:
                raise ValueError(f"RULES_TIERS 只能是 {sorted(allowed)} 的子集")
            if tier and tier not in cleaned:
                cleaned.append(tier)
        return cleaned or ["core"]

    @field_validator("rules_unknown_category", mode="after")
    @classmethod
    def _check_unknown_category(cls, value: str) -> str:
        if value not in {"reject", "warn"}:
            raise ValueError("RULES_UNKNOWN_CATEGORY 必须是 reject 或 warn")
        return value

    @field_validator("match_backend", mode="after")
    @classmethod
    def _check_match_backend(cls, value: str) -> str:
        if value not in {"auto", "python", "re2"}:
            raise ValueError("MATCH_BACKEND 必须是 auto|python|re2")
        return value

    @field_validator("firewall_backend", mode="after")
    @classmethod
    def _check_backend(cls, value: str) -> str:
        allowed = {"auto", "iptables", "nftables", "firewalld", "none"}
        if value not in allowed:
            raise ValueError(f"firewall_backend 必须是 {sorted(allowed)} 之一")
        return value

    @field_validator("web_detect_source", mode="after")
    @classmethod
    def _check_web_source(cls, value: str) -> str:
        allowed = {"auto", "log", "demo", "api", "off"}
        if value not in allowed:
            raise ValueError(f"web_detect_source 必须是 {sorted(allowed)} 之一")
        return value

    # ---------- 派生属性 ----------
    @property
    def tick_interval_sec(self) -> float:
        return self.tick_interval_ms / 1000.0

    @property
    def dashboard_path(self) -> Path:
        return Path(self.dashboard_dir).resolve() if self.dashboard_dir else REPO_ROOT / "dashboard"

    @property
    def cve_rules_path(self) -> Path:
        return Path(self.cve_rules_file).resolve() if self.cve_rules_file else Path(__file__).resolve().parents[1] / "data" / "cve_rules.json"

    @property
    def web_attack_rules_path(self) -> Path:
        return (Path(self.web_attack_rules_file).resolve() if self.web_attack_rules_file
                else Path(__file__).resolve().parents[1] / "data" / "web_attack_rules.json")

    @property
    def web_strict_rules_path(self) -> Path:
        return (Path(self.web_strict_rules_file).resolve() if self.web_strict_rules_file
                else Path(__file__).resolve().parents[1] / "data" / "web_strict_rules.json")

    @property
    def rulesets_path(self) -> Path:
        return (Path(self.rulesets_dir).resolve() if self.rulesets_dir
                else Path(__file__).resolve().parents[1] / "data" / "rulesets")

    @property
    def report_path(self) -> Path:
        return (Path(self.report_dir).resolve() if self.report_dir
                else Path(__file__).resolve().parents[1] / "data" / "reports")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    """测试用：清缓存后重新加载。"""
    get_settings.cache_clear()
    return get_settings()
