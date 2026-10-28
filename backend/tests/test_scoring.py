"""滑动窗口增量评分 + 直达机制测试（方案第 2 层）。

关键断言不变量：
* 直达：单条 critical+high（权重 6.0）立刻告警，不进入窗口；
* 增量：多条 medium 累计超阈时，**第 N 条 signal 到达的瞬间**就告警（不等窗口到期）；
* 抑制：冷却期内的重复告警带 `suppressed_reason=cooldown` 落库（降级可见）；
* 加成：多类别 / critical 加成按方案权重表生效。
"""

from __future__ import annotations

import time
from datetime import datetime

import pytest

from app.detection.scoring import (
    CONFIDENCE_FACTOR,
    WEIGHT_TABLE,
    ScoringAggregator,
    compute_weight,
)
from app.models import Signal


@pytest.fixture()
def aggregator(settings) -> ScoringAggregator:
    instance = ScoringAggregator(settings)
    instance.cooldown_sec = 300          # 默认与 ALERT_COOLDOWN_SEC 一致
    return instance


def make_signal(category: str = "port_scan", severity: str = "medium",
                confidence: str = "medium", source_ip: str = "203.0.113.7",
                direct_alert: bool = False, weight: float | None = None,
                now: float | None = None) -> Signal:
    moment = float(now or time.time())
    return Signal(
        ts=datetime.fromtimestamp(moment), source_ip=source_ip, dst_port=22,
        rule_id=f"TEST-{category.upper()}", category=category, severity=severity,
        confidence=confidence, direct_alert=direct_alert,
        weight=weight if weight is not None else compute_weight(severity, confidence),
    )


# --------------------------------------------------------------------------- #
# 权重表
# --------------------------------------------------------------------------- #
def test_weight_table_boundaries():
    assert compute_weight("critical", "high") == pytest.approx(6.0), "直达边界"
    assert compute_weight("critical", "medium") == pytest.approx(5.0)
    assert compute_weight("high", "high") == pytest.approx(3.6)
    assert compute_weight("medium", "medium") == pytest.approx(1.5)
    assert compute_weight("unknown", "unknown") == pytest.approx(0.5)
    assert WEIGHT_TABLE["critical"] == 5.0 and CONFIDENCE_FACTOR["high"] == 1.2


# --------------------------------------------------------------------------- #
# 直达机制
# --------------------------------------------------------------------------- #
def test_direct_alert_bypasses_aggregation(aggregator):
    """critical + high 的单条 signal 立即告警，不进入窗口。"""
    alert = aggregator.add(make_signal(severity="critical", confidence="high",
                                       direct_alert=True))
    assert alert is not None and alert.direct_alert is True
    assert alert.risk_score == pytest.approx(6.0)
    assert alert.evidence["aggregation"]["signal_count"] == 1
    assert aggregator.window("203.0.113.7") == [], "直达告警不应把 signal 留在窗口里"


def test_direct_alert_weight_threshold(aggregator):
    """未标记 direct_alert 但权重 ≥ 6.0 的 signal 同样直达。"""
    alert = aggregator.add(make_signal(severity="critical", confidence="high"))
    assert alert is not None and alert.direct_alert is True


def test_direct_alert_disabled_falls_back_to_aggregation(settings):
    settings_copy = settings.model_copy(update={"direct_alert_enabled": False})
    aggregator = ScoringAggregator(settings_copy)
    alert = aggregator.add(make_signal(severity="critical", confidence="high"))
    # 关闭直达后：窗口内单条 6.0 ≥ 阈值 6.0 → 走聚合路径告警
    assert alert is not None and alert.direct_alert is False


def test_direct_alert_respects_cooldown(aggregator):
    first = aggregator.add(make_signal(severity="critical", confidence="high",
                                       direct_alert=True))
    second_signal = make_signal(severity="critical", confidence="high", direct_alert=True)
    second = aggregator.add(second_signal)
    assert first is not None and second is None
    assert second_signal.suppressed is True
    assert second_signal.suppressed_reason == "cooldown"
    assert aggregator.counters["cooldown"] == 1


def test_cooldown_expiry_re_alert(aggregator):
    """冷却期结束后，持续的致命攻击必须重新告警（不做静默丢弃）。"""
    aggregator.cooldown_sec = 1.0
    now = time.time()
    assert aggregator.add(make_signal(direct_alert=True, severity="critical",
                                      confidence="high"), now) is not None
    assert aggregator.add(make_signal(direct_alert=True, severity="critical",
                                      confidence="high"), now + 0.5) is None
    again = aggregator.add(make_signal(direct_alert=True, severity="critical",
                                       confidence="high"), now + 1.5)
    assert again is not None and again.direct_alert is True


# --------------------------------------------------------------------------- #
# 聚合路径（增量评估）
# --------------------------------------------------------------------------- #
def test_single_medium_rule_no_alert(aggregator):
    """单条 medium（1.5 < 6.0）不告警，只记录 signal。"""
    signal = make_signal(severity="medium", confidence="medium")
    assert aggregator.add(signal) is None
    assert signal.suppressed is True and signal.suppressed_reason == "below_threshold"
    assert aggregator.window("203.0.113.7"), "未达阈值的 signal 必须留在窗口里等待累计"


def test_incremental_alert_no_window_delay(aggregator):
    """多条 medium signal 累计超阈时，第 N 条到达即告警（不需要等窗口到期）。"""
    now = time.time()
    emitted = []
    for index in range(12):                      # 12 × 1.5 = 18 ≥ 6.0，第 4 条就该告警
        alert = aggregator.add(make_signal(severity="medium", confidence="medium"), now + index)
        if alert is not None:
            emitted.append((index, alert))
    assert emitted, "累计超阈必须产生告警"
    first_index, first_alert = emitted[0]
    assert first_index == 3, f"应在第 4 条 signal 时立即告警，实际第 {first_index + 1} 条"
    assert first_alert.direct_alert is False
    assert first_alert.risk_score >= aggregator.threshold
    assert "聚合告警" in first_alert.message
    assert first_alert.signal_window_id


def test_multi_category_bonus(aggregator):
    """命中 ≥3 个不同大类时叠加 1.5 倍加成。"""
    now = time.time()
    for category in ("port_scan", "brute_force", "nonstandard_port"):
        aggregator.add(make_signal(category=category, severity="medium",
                                   confidence="medium"), now)
    assert aggregator.compute_score(aggregator.window("203.0.113.7", now)) == pytest.approx(
        round(3 * 1.5 * 1.5, 3))


def test_two_category_bonus(aggregator):
    now = time.time()
    for category in ("port_scan", "brute_force"):
        aggregator.add(make_signal(category=category, severity="medium",
                                   confidence="medium"), now)
    assert aggregator.compute_score(aggregator.window("203.0.113.7", now)) == pytest.approx(
        round(3.0 * 1.2, 3))


def test_critical_bonus(aggregator):
    """窗口内存在 critical signal 时整体 ×1.3。"""
    now = time.time()
    aggregator.add(make_signal(category="port_scan", severity="critical",
                               confidence="low", weight=0.5), now)
    score = aggregator.compute_score(aggregator.window("203.0.113.7", now))
    assert score == pytest.approx(round(0.5 * 1.3, 3))


def test_window_eviction_after_expiry(aggregator):
    """窗口过期 signal 被正确移除，不参与后续评分。"""
    aggregator.window_sec = 10
    now = time.time()
    aggregator.add(make_signal(category="port_scan", severity="medium"), now)
    assert aggregator.window("203.0.113.7", now + 5)
    assert aggregator.window("203.0.113.7", now + 15) == []


def test_window_isolated_per_source(aggregator):
    """不同源 IP 的窗口互相隔离（一个源刷分不影响另一个源）。"""
    now = time.time()
    aggregator.add(make_signal(source_ip="203.0.113.7", severity="medium"), now)
    aggregator.add(make_signal(source_ip="198.51.100.9", severity="medium"), now)
    assert len(aggregator.window("203.0.113.7", now)) == 1
    assert len(aggregator.window("198.51.100.9", now)) == 1


def test_window_signal_cap(aggregator):
    """单源窗口有上限保护，防止刷爆内存。"""
    aggregator.max_signals = 5
    now = time.time()
    for index in range(20):
        aggregator.add(make_signal(severity="low", confidence="low",
                                   source_ip="198.51.100.77"), now + index * 0.1)
    assert len(aggregator.window("198.51.100.77", now + 5)) <= 5


def test_stats_and_purge(aggregator):
    now = time.time()
    aggregator.add(make_signal(severity="low", confidence="low"), now)
    stats = aggregator.stats
    assert stats["signals.signals"] >= 1 and stats["threshold"] == aggregator.threshold
    aggregator.window_sec = 5
    aggregator.purge(now + 60)
    assert aggregator.stats["active_windows"] == 0
