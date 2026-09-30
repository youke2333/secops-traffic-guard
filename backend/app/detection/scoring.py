"""滑动窗口增量评分 + 直达机制（方案第 2 层）。

核心设计（每一条都对应方案里的硬约束）：

1. **同步、立即返回**：每个 signal 到达时立刻评估，不等待窗口到期 —— 告警延迟最坏只等于
   一个 TICK（默认 500ms），满足"P99 < 2s"的要求；
2. **直达机制**：`signal.direct_alert=True` **或** `signal.weight >= DIRECT_ALERT_WEIGHT`
   时绕过聚合投票，单条命中立即告警（默认 6.0 = critical(5.0) × high(1.2)）；
3. **冷却期复用 `ALERT_COOLDOWN_SEC`**：不引入新配置项，避免运维负担；冷却期内的信号会被
   记录为 `suppressed`（前端可见，禁止静默降级）；
4. **窗口重算是 O(window_size)**：典型规模下可忽略，优先保证正确性与可读性；
5. **直达机制不参与自适应阈值调整**（见 `adaptive_threshold.py`）：直达是规则固有属性，
   不能被误报率反馈削弱，否则致命攻击的响应能力会被"调优"掉。
"""

from __future__ import annotations

import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Sequence

from ..config import Settings, get_settings
from ..models import Signal

WEIGHT_TABLE = {
    "critical": 5.0,
    "high": 3.0,
    "medium": 1.5,
    "low": 0.5,
}
CONFIDENCE_FACTOR = {
    "high": 1.2,
    "medium": 1.0,
    "low": 0.8,
}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SUPPRESS_COOLDOWN = "cooldown"
SUPPRESS_BELOW_THRESHOLD = "below_threshold"

# 流量侧检测器没有规则文件，用内置伪规则 ID 表示（便于前端/审计统一展示"命中规则"）
TRAFFIC_RULE_IDS = {
    "traffic_spike": "STAT-TRAFFIC-SPIKE",
    "nonstandard_port": "STAT-NONSTANDARD-PORT",
    "port_scan": "STAT-PORT-SCAN",
    "brute_force": "STAT-BRUTE-FORCE",
    "behavior_anomaly": "ML-IFOREST",
}

# 检测器 → 默认置信度（决定评分权重；Web 知识库规则用规则自身的 confidence）
DETECTOR_CONFIDENCE = {
    "ewma-zscore": "high",
    "port-scan": "high",
    "isolation-forest": "medium",
    "web-kb": "high",
    "manual": "high",
}


def compute_weight(severity: str, confidence: str) -> float:
    """评分权重 = 严重度权重 × 置信度系数（方案 2.5 节权重表）。"""
    return (WEIGHT_TABLE.get(str(severity or "").lower(), 0.5)
            * CONFIDENCE_FACTOR.get(str(confidence or "").lower(), 1.0))


def rule_id_of(category: str, rule_id: str = "") -> str:
    """命中规则 ID：Web 侧来自知识库；流量侧用内置伪规则 ID 兜底。"""
    if rule_id:
        return rule_id
    return TRAFFIC_RULE_IDS.get(category, f"STAT-{str(category or 'unknown').upper()}")


@dataclass(slots=True)
class AggregatedAlert:
    """聚合结果：服务层据此落库/封禁/通知/推送（不直接持有 ORM 对象，便于单测）。"""

    source_ip: str
    category: str
    severity: str
    risk_score: float
    direct_alert: bool
    contributing_rules: List[str] = field(default_factory=list)
    signal_window_id: str = ""
    signal_count: int = 1
    categories: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    message: str = ""
    window_sec: int = 0


class ScoringAggregator:
    """滑动窗口增量评分器（采集线程与 API 线程都可能触发，故内部状态按源 IP 隔离）。"""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        cfg = settings or get_settings()
        self.settings = cfg
        self.window_sec = int(getattr(cfg, "scoring_window_sec", 300))
        self.threshold = float(getattr(cfg, "alert_score_threshold", 6.0))
        self.direct_weight = float(getattr(cfg, "direct_alert_weight", 6.0))
        self.direct_enabled = bool(getattr(cfg, "direct_alert_enabled", True))
        self.cooldown_sec = float(getattr(cfg, "alert_cooldown_sec", 60))
        self.max_signals = int(getattr(cfg, "scoring_max_signals_per_window", 1000))
        self.bonus_2 = float(getattr(cfg, "multi_category_bonus_2", 1.2))
        self.bonus_3 = float(getattr(cfg, "multi_category_bonus_3", 1.5))
        self.critical_bonus = float(getattr(cfg, "critical_bonus", 1.3))
        self._windows: Dict[str, Deque[Signal]] = {}
        self._alerted_at: Dict[str, float] = {}
        self._alerted_sev: Dict[str, int] = {}      # 冷却期内该源已发过的最高严重度（升级放行用）
        self.counters: Dict[str, int] = {
            "signals": 0, "emitted": 0, "direct": 0, "aggregated": 0,
            SUPPRESS_COOLDOWN: 0, SUPPRESS_BELOW_THRESHOLD: 0,
        }

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    def add(self, signal: Signal, now: Optional[float] = None) -> Optional[AggregatedAlert]:
        """喂入一个 signal：返回 `AggregatedAlert` 表示告警；None 表示未达阈值或被冷却抑制。

        本方法**不等待**窗口到期 —— 阈值达成的瞬间就返回告警（增量评估）。
        """
        moment = float(now or time.time())
        if signal.ts is None:
            # 与 Alert.ts 保持同一时间基（本地时间 naive），窗口淘汰计算依赖它
            signal.ts = datetime.fromtimestamp(moment)
        self.counters["signals"] += 1
        source_ip = signal.source_ip or "-"

        if self.direct_enabled and (signal.direct_alert or float(signal.weight) >= self.direct_weight):
            if self._in_cooldown(source_ip, moment, signal.severity):
                self._suppress(signal, SUPPRESS_COOLDOWN)
                return None
            alert = self._build(source_ip, [signal], float(signal.weight), direct=True)
            self._mark_alerted(source_ip, moment, signal.severity)
            self.counters["direct"] += 1
            self.counters["emitted"] += 1
            return alert

        window = self._windows.setdefault(source_ip, deque())
        window.append(signal)
        self._evict(window, moment)
        while len(window) > self.max_signals:      # 防御性上限：防止单源刷爆内存
            window.popleft()

        score = self.compute_score(window)
        signal.score_contribution = round(score, 3)
        if score < self.threshold:
            self._suppress(signal, SUPPRESS_BELOW_THRESHOLD)
            return None
        if self._in_cooldown(source_ip, moment, signal.severity):
            self._suppress(signal, SUPPRESS_COOLDOWN)
            return None

        alert = self._build(source_ip, list(window), score, direct=False)
        self._mark_alerted(source_ip, moment, signal.severity)
        self.counters["aggregated"] += 1
        self.counters["emitted"] += 1
        return alert

    # ------------------------------------------------------------------ #
    # 窗口与评分
    # ------------------------------------------------------------------ #
    def _evict(self, window: Deque[Signal], now: float) -> None:
        cutoff = now - self.window_sec
        while window and _timestamp(window[0].ts) < cutoff:
            window.popleft()

    def compute_score(self, window: Sequence[Signal]) -> float:
        """窗口评分：基础权重和 × 多类别加成 × critical 加成（方案 2.3 / 2.5 节）。"""
        base = float(sum(float(item.weight or 0.0) for item in window))
        categories = {item.category for item in window}
        if len(categories) >= 3:
            base *= self.bonus_3
        elif len(categories) >= 2:
            base *= self.bonus_2
        if any(str(item.severity) == "critical" for item in window):
            base *= self.critical_bonus
        return round(base, 3)

    def _in_cooldown(self, source_ip: str, now: float, severity: str = "") -> bool:
        """冷却判定：同源冷却窗口内只报一次，但**升级放行**。

        例：某源 5 秒前因中危信号发过告警，此时出现 critical 直达事件 —— 若按原逻辑一并对齐
        冷却，致命告警会被前面的中危告警吞掉（默认冷却 60s），这是运维上不可接受的信息丢失。
        因此严重度高于冷却期内已发过的级别时直接放行；同级别或降级仍按冷却限流。
        """
        last = self._alerted_at.get(source_ip)
        if last is None or (now - last) >= self.cooldown_sec:
            return False
        rank = SEVERITY_RANK.get(str(severity), 0)
        return rank <= self._alerted_sev.get(source_ip, -1)

    def _mark_alerted(self, source_ip: str, now: float, severity: str) -> None:
        self._alerted_at[source_ip] = now
        self._alerted_sev[source_ip] = SEVERITY_RANK.get(str(severity), 0)

    def _suppress(self, signal: Signal, reason: str) -> None:
        signal.suppressed = True
        signal.suppressed_reason = reason
        self.counters[reason] = self.counters.get(reason, 0) + 1

    def _build(self, source_ip: str, signals: List[Signal], score: float,
               direct: bool) -> AggregatedAlert:
        worst = max(signals, key=lambda item: SEVERITY_RANK.get(str(item.severity), 2))
        categories = sorted({item.category for item in signals})
        return AggregatedAlert(
            source_ip=source_ip,
            category=signals[-1].category,
            severity=str(worst.severity),
            risk_score=round(score, 3),
            direct_alert=direct,
            contributing_rules=[str(item.rule_id) for item in signals],
            signal_window_id=signals[-1].signal_window_id or self.new_window_id(),
            signal_count=len(signals),
            categories=categories,
            evidence={
                "aggregation": {
                    "direct_alert": direct,
                    "risk_score": round(score, 3),
                    "threshold": self.threshold,
                    "window_sec": self.window_sec,
                    "signal_count": len(signals),
                    "categories": categories,
                    "contributing_rules": [str(item.rule_id) for item in signals],
                },
                "signals": [_signal_brief(item) for item in signals],
            },
            message=self._message(signals, score, direct),
            window_sec=self.window_sec,
        )

    def _message(self, signals: List[Signal], score: float, direct: bool) -> str:
        if direct:
            top = signals[0]
            return (f"直达告警：命中规则 {top.rule_id}（{top.severity}，权重 "
                    f"{round(float(top.weight or 0.0), 1)}）—— 单条高置信度致命攻击，立即响应")
        categories = sorted({item.category for item in signals})
        rules = sorted({str(item.rule_id) for item in signals})
        return (f"聚合告警：{self.window_sec}s 内 {len(signals)} 条信号累计风险分 {round(score, 2)}"
                f"（阈值 {self.threshold}），涉及 {len(categories)} 类攻击"
                f"（{','.join(categories)}），命中规则 {','.join(rules[:6])}")

    # ------------------------------------------------------------------ #
    # 可观测性 / 维护
    # ------------------------------------------------------------------ #
    @staticmethod
    def new_window_id() -> str:
        return uuid.uuid4().hex[:16]

    def window(self, source_ip: str, now: Optional[float] = None) -> List[Signal]:
        """查看某源 IP 当前窗口内的 signals（供 GET /signals 使用）。"""
        moment = float(now or time.time())
        window = self._windows.get(source_ip)
        if not window:
            return []
        self._evict(window, moment)
        return list(window)

    def purge(self, now: Optional[float] = None) -> None:
        """清理过期窗口与冷却记录（长期运行避免内存膨胀）。"""
        moment = float(now or time.time())
        for source_ip in list(self._windows):
            window = self._windows[source_ip]
            self._evict(window, moment)
            if not window:
                self._windows.pop(source_ip, None)
        cutoff = moment - max(self.cooldown_sec, self.window_sec) * 4
        self._alerted_at = {key: value for key, value in self._alerted_at.items() if value >= cutoff}
        self._alerted_sev = {k: v for k, v in self._alerted_sev.items() if k in self._alerted_at}

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "window_sec": self.window_sec,
            "threshold": self.threshold,
            "direct_alert_enabled": self.direct_enabled,
            "direct_alert_weight": self.direct_weight,
            "cooldown_sec": int(self.cooldown_sec),
            "active_windows": len(self._windows),
            "cooldown_keys": len(self._alerted_at),
            **{f"signals.{key}": value for key, value in self.counters.items()},
        }

    def reset(self) -> None:
        self.__init__(self.settings)      # type: ignore[misc]


def _signal_brief(signal: Signal) -> Dict[str, Any]:
    return {
        "rule_id": signal.rule_id,
        "category": signal.category,
        "severity": signal.severity,
        "confidence": signal.confidence,
        "weight": round(float(signal.weight or 0.0), 2),
        "direct_alert": bool(signal.direct_alert),
        "suppressed": bool(signal.suppressed),
        "suppressed_reason": signal.suppressed_reason,
        "evidence": signal.evidence or {},
    }


def _timestamp(value: Any) -> float:
    """ORM DateTime → Unix 时间戳。

    约定：本项目所有时间字段（Alert.ts / Signal.ts）都是**本地时间的 naive datetime**
    （由 `datetime.fromtimestamp(now)` 生成），因此这里按本地时区反向换算，
    与窗口时间轴（time.time()）保持同一坐标系。
    """
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return value.timestamp()
    except Exception:      # pragma: no cover - 防御性
        return 0.0
