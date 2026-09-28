"""检测引擎：把滑动窗口聚合出的「流量快照」翻译成结构化安全告警。

覆盖需求中的 4 类异常：
1. ``traffic_spike``     突发流量峰值（全局 bps 的 EWMA-Z 超阈 + 绝对阈值兜底）
2. ``nonstandard_port``  非标准端口高频访问（端口级基线 Z-score + 标准端口白名单）
3. ``port_scan``         端口扫描（单源目的端口多样性 + 端口熵）
4. ``brute_force``       认证端口暴力破解（单源对高价值端口的高频访问）
外加 ``behavior_anomaly`` 作为 Isolation Forest 的多维补充确认。
"""

from __future__ import annotations

import ipaddress
import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..config import Settings, get_settings
from .adaptive_threshold import AdaptiveThresholdManager
from .iforest import FEATURE_NAMES, IsolationForestDetector
from .scoring import DETECTOR_CONFIDENCE, compute_weight, rule_id_of
from .zscore import RollingStats, ZScoreDetector

logger = logging.getLogger(__name__)

CATEGORY_TEXT = {
    "traffic_spike": "突发流量峰值",
    "nonstandard_port": "非标准端口高频访问",
    "port_scan": "端口扫描探测",
    "brute_force": "认证端口暴力破解",
    "behavior_anomaly": "多维行为异常(ML)",
    "manual": "人工封禁",
    # ---- Web 攻击检测（HTTP 侧，规则见 backend/data/web_attack_rules.json）----
    "web_sql_injection": "Web-SQL 注入",
    "web_sql_injection_blind": "Web-SQL 盲注",
    "web_xss_reflected": "Web-反射型 XSS",
    "web_xss_stored": "Web-存储型 XSS",
    "web_command_injection": "Web-命令注入",
    "web_file_inclusion": "Web-文件包含",
    "web_file_upload": "Web-恶意文件上传",
    "web_brute_force": "Web-暴力破解",
    "web_csrf": "Web-CSRF",
    "web_insecure_captcha": "Web-不安全验证码",
    "web_path_traversal": "Web-目录穿越",
    "web_ssrf": "Web-SSRF",
    "web_xxe": "Web-XXE",
    "web_webshell": "Web-Webshell 访问",
    "web_ssti": "Web-模板注入",
    "web_ldap_nosql_injection": "Web-LDAP/NoSQL 注入",
    "web_crlf_injection": "Web-CRLF 注入",
}

SEVERITY_TEXT = {"critical": "紧急", "high": "高危", "medium": "中危", "low": "低危"}
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(slots=True)
class PortSample:
    port: int
    protocol: str = "TCP"
    pps: float = 0.0
    bps: float = 0.0
    conns: int = 0
    is_standard: bool = True
    top_source: str = ""


@dataclass(slots=True)
class SourceSample:
    ip: str
    pps: float = 0.0
    bps: float = 0.0
    packets: int = 0
    nbytes: int = 0
    unique_dst_ports: int = 0
    unique_dst_ips: int = 0
    conns: int = 0
    syn_packets: int = 0
    dst_port_hits: Dict[int, int] = field(default_factory=dict)

    @property
    def avg_packet_size(self) -> float:
        return self.nbytes / self.packets if self.packets else 0.0

    @property
    def syn_ratio(self) -> float:
        return self.syn_packets / self.packets if self.packets else 0.0

    @property
    def port_entropy(self) -> float:
        total = sum(self.dst_port_hits.values())
        if total <= 0:
            return 0.0
        entropy = 0.0
        for count in self.dst_port_hits.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy


@dataclass(slots=True)
class ConnRecord:
    key: Tuple[str, int, str, int, str]
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    first_seen: float
    last_seen: float
    src_port: int = 0
    packets: int = 0
    nbytes: int = 0

    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen


@dataclass(slots=True)
class TrafficSnapshot:
    """一个 tick 的聚合结果（由 CollectorService 生成，检测引擎只读）。"""

    ts: float
    interval: float
    total_pps: float = 0.0
    total_bps: float = 0.0
    bps_in: float = 0.0
    bps_out: float = 0.0
    pps_in: float = 0.0
    pps_out: float = 0.0
    conns: int = 0
    unique_src: int = 0
    unique_dst_ports: int = 0
    ports: List[PortSample] = field(default_factory=list)
    sources: List[SourceSample] = field(default_factory=list)


@dataclass(slots=True)
class Anomaly:
    category: str
    severity: str
    score: float
    message: str
    source_ip: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    protocol: str = "TCP"
    detector: str = "stat"
    evidence: Dict[str, object] = field(default_factory=dict)
    # ---- 规则与评分链路（新增字段均为默认安全值，旧调用方零改动）----
    rule_id: str = ""                       # 命中的主规则 ID（流量侧为内置伪规则 ID）
    confidence: str = "medium"              # 规则置信度（决定评分权重）
    direct_alert: bool = False              # 是否直达（单条命中即告警，绕过聚合投票）
    weight: float = 0.0                     # 评分权重（由 detection.scoring.compute_weight 计算）
    rule_source: str = "native"             # 规则来源：native / sigma / et

    @property
    def category_text(self) -> str:
        return CATEGORY_TEXT.get(self.category, self.category)

    def to_dict(self) -> Dict[str, object]:
        return {
            "category": self.category,
            "category_text": self.category_text,
            "severity": self.severity,
            "severity_text": SEVERITY_TEXT.get(self.severity, self.severity),
            "score": self.score,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "message": self.message,
            "detector": self.detector,
            "evidence": self.evidence,
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "direct_alert": self.direct_alert,
            "weight": round(self.weight, 2),
            "rule_source": self.rule_source,
        }


def human_bps(value: float) -> str:
    """把 bps 转成人类可读带宽，用于告警文案。"""
    if value >= 1e9:
        return f"{value / 1e9:.2f}Gbps"
    if value >= 1e6:
        return f"{value / 1e6:.2f}Mbps"
    if value >= 1e3:
        return f"{value / 1e3:.2f}Kbps"
    return f"{value:.0f}bps"


class DetectionEngine:
    """无状态化程度尽量高的检测引擎：输入快照 → 输出告警列表。"""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        cfg = self.settings
        # 检测忽略名单（传感器自身/授权扫描器/回环）：只抑制「这些源」的统计检测，避免自扫描误报
        self._ignored_ips, self._ignored_networks = self._parse_ignored(
            getattr(cfg, "detect_ignore_ips", None) or [])
        # 全局带宽/包速率基线：floor_std 抑制稳定流量下的数值放大
        # min_absolute（默认 1Mbps）是绝对下限：正常业务流量在低基线上 Z 值极易超阈，
        # 必须用绝对下限兜底，避免「492Kbps 超 26Kbps 基线」这类误报（2026-10 真实环境反馈）。
        # 该下限与总开关均可通过环境变量调整：SPIKE_MIN_ABS_BPS / SPIKE_DETECT_ENABLED。
        self.global_bps = ZScoreDetector(
            threshold=cfg.zscore_threshold, warmup=cfg.anomaly_warmup_ticks,
            floor_std=64 * 1024, min_absolute=cfg.spike_min_abs_bps,
        )
        self.global_pps = ZScoreDetector(
            threshold=cfg.zscore_threshold, warmup=cfg.anomaly_warmup_ticks,
            floor_std=20.0, min_absolute=200.0,
        )
        # 端口级基线：非标准端口的高频访问靠它发现
        self.port_pps = ZScoreDetector(
            threshold=cfg.zscore_threshold + 0.5, warmup=cfg.anomaly_warmup_ticks,
            floor_std=2.0, min_absolute=30.0,
        )
        self.src_pps = ZScoreDetector(
            threshold=cfg.zscore_threshold, warmup=cfg.anomaly_warmup_ticks,
            floor_std=2.0, min_absolute=60.0,
        )
        self.spike_stats = RollingStats(maxlen=240)
        self.iforest = IsolationForestDetector(
            contamination=cfg.iforest_contamination, enabled=cfg.iforest_enabled
        )
        # 自适应阈值（方案第 3 层）：每 tick 按维度刷新统计型检测器的阈值
        self.adaptive = AdaptiveThresholdManager(cfg)
        self.thresholds: Dict[str, float] = {}
        self._thresholds_refreshed_at = 0.0
        self._thresholds_ttl = 30.0
        self._cooldowns: Dict[Tuple[str, str], float] = {}
        self._cooldown_rank: Dict[Tuple[str, str], int] = {}   # 冷却期内已发过的最高严重度
        self.counters: Counter = Counter()
        self.last_evaluated_at: float = 0.0

    # ------------------------------------------------------------------ #
    # 对外入口
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_ignored(values) -> Tuple[set, list]:
        ips, networks = set(), []
        for item in values or []:
            text = str(item or "").strip()
            if not text:
                continue
            try:
                if "/" in text:
                    networks.append(ipaddress.ip_network(text, strict=False))
                else:
                    ips.add(str(ipaddress.ip_address(text)))
            except ValueError:
                logger.warning("忽略非法的 DETECT_IGNORE_IPS 项：%s", text)
        return ips, networks

    def _ignored(self, source_ip: str) -> bool:
        text = str(source_ip or "").strip()
        if not text:
            return False
        if text in self._ignored_ips:
            return True
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        return any(address in network for network in self._ignored_networks)

    def evaluate(self, snapshot: TrafficSnapshot) -> List[Anomaly]:
        self._refresh_thresholds(snapshot.ts)
        found: List[Anomaly] = []
        spike = self._detect_global_spike(snapshot)
        if spike is not None:
            found.append(spike)
        found.extend(self._detect_ports(snapshot))
        found.extend(self._detect_sources(snapshot))
        found.extend(self._detect_ml(snapshot))
        for anomaly in found:
            self._stamp_signal(anomaly)
        self.last_evaluated_at = snapshot.ts
        return self._apply_cooldown(found, snapshot.ts)

    def _refresh_thresholds(self, now: float) -> None:
        """按维度刷新阈值（带 30s 节流，避免每 tick 查库）。

        静态基准来自 config；自适应开启且存在对应维度记录时用记录值覆盖。
        直达机制（direct_alert / DIRECT_ALERT_WEIGHT）**不参与**这里的调整。
        """
        if now - self._thresholds_refreshed_at < self._thresholds_ttl and self.thresholds:
            return
        self._thresholds_refreshed_at = now
        cfg = self.settings
        self.thresholds = {
            "traffic_spike": self.adaptive.threshold_for(
                "traffic_spike", now=now, default=cfg.zscore_threshold),
            "nonstandard_port": self.adaptive.threshold_for(
                "nonstandard_port", now=now, default=cfg.zscore_threshold + 0.5),
            "port_scan": self.adaptive.threshold_for(
                "port_scan", now=now, default=max(5, cfg.port_scan_unique_ports)),
            "brute_force": self.adaptive.threshold_for(
                "brute_force", now=now, default=max(5, cfg.brute_force_attempts)),
        }
        self.global_bps.threshold = self.thresholds["traffic_spike"]
        self.global_pps.threshold = self.thresholds["traffic_spike"]
        self.port_pps.threshold = self.thresholds["nonstandard_port"]
        self.src_pps.threshold = self.thresholds["traffic_spike"]

    def _stamp_signal(self, anomaly: Anomaly) -> None:
        """为异常补齐"规则 + 评分"元数据（统一在此处计算，检测器本身不关心评分）。

        * 命中规则 ID：Web 侧由知识库给出（`web_knowledge` 已填好），流量侧用内置伪规则 ID；
        * 置信度：Web 侧取规则置信度；流量侧按检测器经验值；
        * 权重与直达标记：权重由 严重度 × 置信度 计算，直达标记来自规则（流量侧一律 False）。
        """
        if not anomaly.rule_id:
            anomaly.rule_id = rule_id_of(anomaly.category)
            anomaly.confidence = DETECTOR_CONFIDENCE.get(anomaly.detector, "medium")
        if not anomaly.weight:
            anomaly.weight = round(compute_weight(anomaly.severity, anomaly.confidence), 3)

    @property
    def stats(self) -> Dict[str, object]:
        return {
            "evaluated_at": self.last_evaluated_at,
            "cooldown_entries": len(self._cooldowns),
            "iforest_ready": self.iforest.trained,
            "iforest_available": self.iforest.available,
            "adaptive_enabled": self.adaptive.enabled,
            "thresholds": {key: round(value, 3) for key, value in self.thresholds.items()},
            **{f"alerts.{k}": v for k, v in self.counters.items()},
        }

    def reset(self) -> None:
        self.__init__(self.settings)  # type: ignore[misc]

    # ------------------------------------------------------------------ #
    # 规则 1：突发流量峰值
    # ------------------------------------------------------------------ #
    def _detect_global_spike(self, snapshot: TrafficSnapshot) -> Optional[Anomaly]:
        cfg = self.settings
        # 先取历史分位，再纳入当前样本 —— 否则平稳高水位下当前值会自己确认自己，
        # p95 一路跟着涨，100~200Mbps 的"起报区"永远过不了稳健分位这一关。
        p95 = self.spike_stats.percentile(0.95)
        # 分位基线只采样「间隔正常」的 tick：启动首个 tick / 长暂停后的补偿 tick 间隔远小于标称值，
        # 用缩水的 interval 去除字节数会把 bps 放大数倍（实测首 tick 5MB/s 被算成 128Mbps），
        # 一旦落进 240 点滑窗，p95 会被抬高约 2 分钟，反而把真实突发压制掉。
        sample_ok = snapshot.interval >= cfg.tick_interval_sec * 0.5
        if sample_ok:
            self.spike_stats.add(snapshot.total_bps)
        if not cfg.spike_detect_enabled:
            # 总开关关闭：只维护 p95 统计（便于随时重新打开），不产生任何异常
            return None
        detail = self.global_pps.observe("global", snapshot.total_pps)
        bps_detail = self.global_bps.observe("global", snapshot.total_bps)
        hard_hit = snapshot.total_bps >= cfg.spike_bps_threshold
        # 告警基线（默认 100Mbps）：低于该值一律不判突发。
        # 注意必须在这里统一拦截 —— pps 通道的绝对下限是「包/秒」，无法表达带宽基线，
        # 只在 bps 通道设下限时，20Mbps / 9万pps 的小包洪水仍会被判为突发。
        # 基线统计（p95、EWMA）在上面已照常更新，不因拦截而失去学习能力。
        if not hard_hit and snapshot.total_bps < cfg.spike_min_abs_bps:
            return None

        # 起报区（min_abs ~ hard_threshold）的判级不依赖"Z 是否超阈"：
        # EWMA 基线 alpha=0.15，约 7 拍就能把持续 130Mbps 学成"新常态"，
        # 只靠 Z 会让持续突发在 2~3 秒后自我消失。基线在这里只用于分级：
        #   ≥1.5×基线 且未达直达线      -> high（相对业务常态明显抬升）
        #   否则（基线附近或稳健分位内） -> medium（靠聚合窗口累计，三拍过 6.0）
        if not hard_hit and p95 > 0 and snapshot.total_bps < p95 * 1.2:
            soft_band = True    # 稳健分位：未明显高于近 2 分钟常态，只降级不丢弃
        else:
            soft_band = False
        score = 0.5
        if bps_detail:
            score = max(score, float(bps_detail["score"]))
        if hard_hit:
            score = max(score, min(1.0, snapshot.total_bps / (cfg.spike_bps_threshold * 2)))
        # 严重度口径：critical 只由硬阈值决定（默认 200Mbps 直达）。
        # 基线（默认 100Mbps）～硬阈值之间属于"起报区"，按相对偏离给中/高危，
        # 否则平稳基线下 Z 分数会直接打满，100~200M 全被判成 critical 直达，失去分级意义。
        if hard_hit:
            severity = "critical"
        elif soft_band:
            severity = "medium"
        elif score >= 0.65 or snapshot.total_bps >= cfg.spike_min_abs_bps * 1.5:
            severity = "high"
        else:
            severity = "medium"

        return Anomaly(
            category="traffic_spike",
            severity=severity,
            score=round(score, 4),
            message=(
                f"整机流量 {human_bps(snapshot.total_bps)} 超出基线 "
                f"{human_bps(self.global_bps.baseline('global').mean)}"
                f"（Z={bps_detail['zscore'] if bps_detail else 'N/A'}），疑似突发攻击或数据外泄"
            ),
            detector="ewma-zscore",
            evidence={
                "total_bps": round(snapshot.total_bps, 2),
                "total_pps": round(snapshot.total_pps, 2),
                "bps_zscore": bps_detail["zscore"] if bps_detail else None,
                "pps_zscore": detail["zscore"] if detail else None,
                "baseline_mean_bps": round(self.global_bps.baseline("global").mean, 2),
                "p95_bps": round(p95, 2),
                "soft_band": soft_band,
                "hard_threshold_hit": hard_hit,
                "threshold_bps": cfg.spike_bps_threshold,
            },
        )

    # ------------------------------------------------------------------ #
    # 规则 2：非标准端口高频访问
    # ------------------------------------------------------------------ #
    def _detect_ports(self, snapshot: TrafficSnapshot) -> List[Anomaly]:
        cfg = self.settings
        results: List[Anomaly] = []
        for sample in snapshot.ports:
            if sample.top_source and self._ignored(sample.top_source):
                continue
            detail = self.port_pps.observe(sample.port, sample.pps)
            if sample.is_standard:
                continue    # 标准端口只积累基线，不产生告警
            if detail is None and not (sample.pps >= 120 and sample.conns >= 30):
                continue
            score = float(detail["score"]) if detail else 0.55
            if sample.pps >= 600 or sample.conns >= 120:
                severity = "high"
                score = max(score, 0.7)
            elif score >= 0.6:
                severity = "medium"
            else:
                severity = "medium"
            if score >= 0.9 and sample.pps >= 1000:
                severity = "critical"

            results.append(
                Anomaly(
                    category="nonstandard_port",
                    severity=severity,
                    score=round(score, 4),
                    source_ip=sample.top_source,
                    dest_ip="",
                    dest_port=sample.port,
                    protocol=sample.protocol,
                    message=(
                        f"非标准端口 {sample.port}/{sample.protocol} 出现高频访问 "
                        f"{sample.pps:.0f} pps（{sample.conns} 连接，主要来源 {sample.top_source or '未知'}）"
                    ),
                    detector="port-baseline-zscore",
                    evidence={
                        "port": sample.port,
                        "protocol": sample.protocol,
                        "pps": round(sample.pps, 2),
                        "bps": round(sample.bps, 2),
                        "conns": sample.conns,
                        "top_source": sample.top_source,
                        "zscore": detail["zscore"] if detail else None,
                        "baseline_mean_pps": round(self.port_pps.baseline(sample.port).mean, 3),
                        "is_standard_port": sample.is_standard,
                    },
                )
            )
        return results

    # ------------------------------------------------------------------ #
    # 规则 3/4：端口扫描 与 认证端口暴破
    # ------------------------------------------------------------------ #
    def _detect_sources(self, snapshot: TrafficSnapshot) -> List[Anomaly]:
        cfg = self.settings
        results: List[Anomaly] = []
        brute_ports = set(cfg.brute_force_ports)
        # 阈值可能被自适应机制调整过（见 _refresh_thresholds）
        scan_ports = int(self.thresholds.get("port_scan") or cfg.port_scan_unique_ports)
        brute_attempts = int(self.thresholds.get("brute_force") or cfg.brute_force_attempts)

        for source in snapshot.sources:
            if self._ignored(source.ip):
                continue
            self.src_pps.observe(source.ip, source.pps)
            if source.packets < 20:
                continue

            # ---- 端口扫描：目的端口多样性 + 端口熵双重判定 ----
            entropy = source.port_entropy
            if source.unique_dst_ports >= scan_ports and entropy >= 3.0:
                top_ports = ", ".join(str(p) for p, _ in Counter(source.dst_port_hits).most_common(5))
                severity = "critical" if source.unique_dst_ports >= scan_ports * 3 else "high"
                results.append(
                    Anomaly(
                        category="port_scan",
                        severity=severity,
                        score=round(min(1.0, source.unique_dst_ports / (scan_ports * 3)), 4),
                        source_ip=source.ip,
                        dest_port=max(source.dst_port_hits, key=source.dst_port_hits.get) if source.dst_port_hits else 0,
                        message=(
                            f"源 {source.ip} 在 {cfg.port_scan_window_sec}s 内探测 "
                            f"{source.unique_dst_ports} 个目的端口（熵 {entropy:.2f}），判定为端口扫描"
                        ),
                        detector="port-diversity",
                        evidence={
                            "unique_dst_ports": source.unique_dst_ports,
                            "port_entropy": round(entropy, 3),
                            "unique_dst_ips": source.unique_dst_ips,
                            "syn_ratio": round(source.syn_ratio, 3),
                            "sample_ports": top_ports,
                            "window_sec": cfg.port_scan_window_sec,
                            "threshold": scan_ports,
                        },
                    )
                )

            # ---- 暴破：单个高价值端口被高频访问 ----
            for port, hits in source.dst_port_hits.items():
                if port not in brute_ports or hits < brute_attempts:
                    continue
                severity = "critical" if hits >= brute_attempts * 3 else "high"
                results.append(
                    Anomaly(
                        category="brute_force",
                        severity=severity,
                        score=round(min(1.0, hits / (brute_attempts * 3)), 4),
                        source_ip=source.ip,
                        dest_port=port,
                        message=(
                            f"源 {source.ip} 对端口 {port} 发起 {hits} 次访问，"
                            f"疑似暴力破解/凭证填充"
                        ),
                        detector="auth-port-frequency",
                        evidence={
                            "hits": hits,
                            "port": port,
                            "pps": round(source.pps, 2),
                            "threshold": brute_attempts,
                            "syn_ratio": round(source.syn_ratio, 3),
                        },
                    )
                )
        return results

    # ------------------------------------------------------------------ #
    # 规则 5：Isolation Forest 多维行为确认
    # ------------------------------------------------------------------ #
    def _detect_ml(self, snapshot: TrafficSnapshot) -> List[Anomaly]:
        if not self.iforest.available:
            return []
        results: List[Anomaly] = []
        for source in snapshot.sources:
            if source.packets < 30 or self._ignored(source.ip):
                continue    # 样本太少或来源在忽略名单，ML 无意义
            # 正常业务画像直接跳过：低 SYN 占比 + 单一目的端口 + 少量连接时，
            # IF 分数偶发越界（如 -0.71 但 SYN 占比仅 0.03）不构成行为异常，避免误报
            if (source.syn_ratio < 0.3 and source.unique_dst_ports < 8
                    and source.conns < 50):
                continue
            features = [
                source.pps,
                source.bps,
                float(source.unique_dst_ports),
                float(source.unique_dst_ips),
                source.avg_packet_size,
                float(source.conns),
                source.syn_ratio,
                source.nbytes / max(1, source.conns),
            ]
            detail = self.iforest.observe(features)
            if detail is None:
                continue
            severity = "high" if source.syn_ratio > 0.7 else "medium"
            results.append(
                Anomaly(
                    category="behavior_anomaly",
                    severity=severity,
                    score=float(detail["score"]),
                    source_ip=source.ip,
                    message=(
                        f"源 {source.ip} 的多维行为向量偏离正常画像"
                        f"（IF 分数 {detail['if_score']}，SYN 占比 {source.syn_ratio:.2f}）"
                    ),
                    detector="isolation-forest",
                    evidence={
                        **dict(zip(FEATURE_NAMES, [round(v, 3) for v in features])),
                        **detail,
                    },
                )
            )
        return results

    # ------------------------------------------------------------------ #
    # 告警抑制：同一 (类型, 源) 在冷却窗口内只报一次，避免告警风暴
    # ------------------------------------------------------------------ #
    def _apply_cooldown(self, found: List[Anomaly], now: float) -> List[Anomaly]:
        cooldown = float(self.settings.alert_cooldown_sec)
        emitted: List[Anomaly] = []
        for anomaly in found:
            key = (anomaly.category, anomaly.source_ip or anomaly.dest_ip or "global")
            last = self._cooldowns.get(key, 0.0)
            rank = SEVERITY_ORDER.get(anomaly.severity, 0)
            # 升级不受冷却抑制：中危信号刚发过告警时，紧接着出现的严重事件不能被静默，
            # 否则「先中危、后致命」的升级链路会被一个冷却窗口吞掉（默认 60s）。
            # 同级别仍按冷却限流，保证告警风暴防护不受影响。
            if now - last < cooldown and rank <= self._cooldown_rank.get(key, -1):
                self.counters["suppressed"] += 1
                continue
            self._cooldowns[key] = now
            self._cooldown_rank[key] = rank
            self.counters[anomaly.category] += 1
            emitted.append(anomaly)

        if len(self._cooldowns) > 4096:  # 定期清理过期冷却键
            cutoff = now - cooldown * 4
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if v >= cutoff}
            self._cooldown_rank = {k: v for k, v in self._cooldown_rank.items() if k in self._cooldowns}
        return emitted


def meets_min_severity(severity: str, minimum: str) -> bool:
    """判断严重程度是否达到自动封禁门槛。"""
    return SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER.get(minimum, 3)



