"""自适应阈值测试（方案第 3 层）。

覆盖：
1. 维度计算（asset_class / time_bucket）；
2. 误报率高 → 收紧、误报率低 → 放松、调整幅度受上下限约束；
3. 最小样本数保护（样本太少不动阈值）；
4. 人工覆盖的记录在重算时被跳过；
5. **直达机制不受自适应阈值影响**（有意为之的设计决定）。
"""

from __future__ import annotations

import time
from datetime import datetime

import pytest
from sqlalchemy import delete

from app.database import session_scope
from app.detection.adaptive_threshold import (
    ADAPTIVE_TYPES,
    MIN_SAMPLES,
    AdaptiveThresholdManager,
)
from app.detection.scoring import ScoringAggregator, compute_weight
from app.models import Alert, Signal, ThresholdConfig, utcnow

SOURCE_IP = "198.51.100.44"


def _local_now() -> datetime:
    """告警时间与生产一致：`datetime.fromtimestamp(now)`（本地时间 naive）。"""
    return datetime.fromtimestamp(time.time())


@pytest.fixture()
def manager(settings) -> AdaptiveThresholdManager:
    return AdaptiveThresholdManager(settings)


@pytest.fixture(autouse=True)
def clean_thresholds():
    """隔离：本模块会写入阈值/告警，避免影响其它用例的静态阈值假设。"""
    _cleanup()
    yield
    _cleanup()


def _cleanup() -> None:
    with session_scope() as session:
        session.execute(delete(ThresholdConfig))
        session.execute(delete(Alert).where(Alert.source_ip == SOURCE_IP))


def seed_alerts(category: str = "port_scan", total: int = 6, false_positive: bool = True,
                blocked: bool = False) -> None:
    with session_scope() as session:
        for _ in range(total):
            session.add(Alert(
                ts=_local_now(), source_ip=SOURCE_IP, category=category, severity="high",
                score=0.8, risk_score=4.5, message="阈值重算样本",
                status="closed" if false_positive else "open", blocked=blocked,
            ))


# --------------------------------------------------------------------------- #
# 维度与静态基准
# --------------------------------------------------------------------------- #
def test_dimensions_and_buckets(manager):
    asset_class, bucket = manager.dimensions("traffic_spike")
    assert asset_class == "machine" and bucket in {"workhour", "offhour"}
    assert manager.dimensions("nonstandard_port")[0] == "server"
    assert manager.classify_asset("10.1.2.3") == "unknown"        # 非白名单且无资产记录
    assert manager.classify_asset("127.0.0.1") == "office"        # 命中内置白名单
    assert manager.classify_asset("not-an-ip") == "unknown"


def test_static_base_matches_config(manager, settings):
    assert manager.static_base("traffic_spike") == settings.zscore_threshold
    assert manager.static_base("nonstandard_port") == settings.zscore_threshold + 0.5
    assert manager.static_base("port_scan") >= 5
    assert manager.static_base("brute_force") >= 5


def test_threshold_for_falls_back_to_static(manager):
    assert manager.threshold_for("port_scan", SOURCE_IP, default=60.0) == pytest.approx(60.0)


def test_disabled_manager_returns_static(settings):
    scoped = settings.model_copy(update={"adaptive_threshold_enabled": False})
    manager = AdaptiveThresholdManager(scoped)
    seed_alerts(total=10)
    manager.recompute()
    assert manager.threshold_for("port_scan", SOURCE_IP) == pytest.approx(
        manager.static_base("port_scan"))


# --------------------------------------------------------------------------- #
# 重算：收紧 / 放松 / 上下限
# --------------------------------------------------------------------------- #
def test_recompute_tightens_on_high_false_positive_rate(manager):
    seed_alerts(false_positive=True, total=10)
    report = manager.recompute()
    rows = [item for item in report["updated"] if item["detection_type"] == "port_scan"]
    assert rows, "误报样本必须产生维度记录"
    row = rows[0]
    assert row["fp_rate"] == 1.0 and row["action"] == "tighten"
    assert row["threshold"] > row["static"], "误报率高时阈值必须收紧"


def test_recompute_loosens_on_low_false_positive_rate(manager):
    seed_alerts(false_positive=False, blocked=True, total=10)
    report = manager.recompute()
    row = [item for item in report["updated"] if item["detection_type"] == "port_scan"][0]
    assert row["fp_rate"] == 0.0 and row["action"] == "loosen"
    assert row["threshold"] < row["static"], "误报率低时阈值应放松"


def test_recompute_respects_min_samples(manager):
    seed_alerts(total=MIN_SAMPLES - 1)
    report = manager.recompute()
    row = [item for item in report["updated"] if item["detection_type"] == "port_scan"][0]
    assert row["action"] == "keep", "样本不足时不应调整阈值"


def test_recompute_clamps_within_bounds(manager, settings):
    seed_alerts(total=10)                       # 100% 误报 → 每轮 ×1.3
    for _ in range(8):
        manager.recompute()
    entry = [item for item in manager.entries() if item["detection_type"] == "port_scan"][0]
    static = manager.static_base("port_scan")
    assert entry["threshold_value"] <= static * settings.threshold_max_factor + 1e-6
    assert entry["threshold_value"] >= static * settings.threshold_min_factor - 1e-6


def test_manual_override_is_skipped(manager):
    seed_alerts(total=10)
    manager.recompute()
    entry = [item for item in manager.entries() if item["detection_type"] == "port_scan"][0]
    manager.override(entry["id"], entry["threshold_value"] * 3, "业务确认", "admin")
    report = manager.recompute()
    assert any(item["reason"] == "人工覆盖" for item in report["skipped"])
    after = [item for item in manager.entries() if item["id"] == entry["id"]][0]
    assert after["manual_override"] is True
    assert after["threshold_value"] == pytest.approx(entry["threshold_value"] * 3)
    assert after["override_reason"].startswith("业务确认")


def test_override_missing_entry_returns_none(manager):
    assert manager.override(999999, 1.0, "不存在") is None


def test_recompute_only_touches_adaptive_types(manager):
    seed_alerts(category="web_sql_injection", total=10)
    report = manager.recompute()
    assert all(item["detection_type"] in ADAPTIVE_TYPES for item in report["updated"])
    assert not [item for item in report["updated"]
                if item["detection_type"] == "web_sql_injection"]


def test_threshold_cache_invalidation(manager):
    seed_alerts(total=10)
    manager.recompute()
    first = manager.threshold_for("port_scan", SOURCE_IP)
    entry = [item for item in manager.entries() if item["detection_type"] == "port_scan"][0]
    manager.override(entry["id"], first + 5.0, "测试缓存失效")
    assert manager.threshold_for("port_scan", SOURCE_IP) == pytest.approx(first + 5.0)


def test_dimensions_overview_notes_direct_alert_exclusion(manager):
    overview = manager.dimensions_overview()
    assert overview["adaptive_types"] == list(ADAPTIVE_TYPES)
    assert "直达" in overview["note"]


# --------------------------------------------------------------------------- #
# 与直达机制的解耦（关键设计决定）
# --------------------------------------------------------------------------- #
def test_direct_alert_not_affected_by_adaptive_thresholds(settings, manager):
    """直达权重是固定配置：自适应重算只动统计检测阈值，绝不动 direct_alert。"""
    seed_alerts(total=10)
    manager.recompute()
    aggregator = ScoringAggregator(settings)
    before = aggregator.direct_weight
    manager.recompute()
    assert aggregator.direct_weight == before == settings.direct_alert_weight
    signal = Signal(ts=utcnow(), source_ip="203.0.113.250", category="web_command_injection",
                    severity="critical", confidence="high", direct_alert=True,
                    weight=compute_weight("critical", "high"))
    assert aggregator.add(signal, time.time()) is not None