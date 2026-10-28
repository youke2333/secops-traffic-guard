"""检测引擎单元测试：4 类异常 + 统计基线 + ML 组件。"""

from __future__ import annotations

import time

import pytest

from app.detection.engine import PortSample, SourceSample, TrafficSnapshot
from app.detection.iforest import IsolationForestDetector
from app.detection.zscore import EwmaBaseline, RollingStats, ZScoreDetector, robust_zscore


# --------------------------------------------------------------------------- #
# 统计基线
# --------------------------------------------------------------------------- #
def test_ewma_baseline_tracks_stable_series():
    baseline = EwmaBaseline(alpha=0.2, warmup=5)
    for _ in range(30):
        baseline.update(100.0)
    assert baseline.ready
    assert baseline.mean == pytest.approx(100.0)
    assert baseline.std < 1e-6
    # 稳定序列下的小抖动不应被判为异常（floor_std 兜底起作用）
    assert baseline.zscore(100.5, floor_std=1.0) == pytest.approx(0.5)


def test_zscore_detector_flags_spike_only_after_warmup():
    detector = ZScoreDetector(threshold=3.0, warmup=10, floor_std=1.0, min_absolute=10.0)
    for _ in range(10):
        assert detector.observe("k", 50.0) is None      # 预热期不告警
    assert detector.observe("k", 52.0) is None          # 轻微抖动不告警
    hit = detector.observe("k", 300.0)                  # 数量级突增 → 告警
    assert hit is not None
    assert hit["zscore"] > 3.0
    assert 0 < hit["score"] <= 1.0


def test_robust_zscore_and_rolling_stats():
    stats = RollingStats(maxlen=50)
    for value in [10, 11, 9, 10, 10, 11, 10, 9, 10, 10]:
        stats.add(value)
    assert stats.ready
    assert abs(robust_zscore(10, stats.median(), stats.mad())) < 1
    assert robust_zscore(100, stats.median(), max(stats.mad(), 1e-6)) > 10


# --------------------------------------------------------------------------- #
# 规则 1：突发流量峰值
# --------------------------------------------------------------------------- #
def test_detect_traffic_spike_hard_threshold(engine, settings):
    spike_bps = settings.spike_bps_threshold * 2
    snapshot = TrafficSnapshot(ts=time.time(), interval=0.5, total_bps=spike_bps,
                              total_pps=120000, bps_in=spike_bps)
    anomalies = [item for item in engine.evaluate(snapshot) if item.category == "traffic_spike"]
    assert anomalies, "超过硬阈值必须产生突发流量告警"
    assert anomalies[0].severity == "critical"
    assert anomalies[0].evidence["hard_threshold_hit"] is True


# --------------------------------------------------------------------------- #
# 规则 2：非标准端口高频访问
# --------------------------------------------------------------------------- #
def test_detect_nonstandard_port(engine):
    snapshot = TrafficSnapshot(
        ts=time.time(), interval=0.5,
        ports=[PortSample(port=4444, protocol="TCP", pps=260.0, bps=120000.0,
                          conns=64, is_standard=False, top_source="45.33.32.156")],
    )
    anomalies = [item for item in engine.evaluate(snapshot) if item.category == "nonstandard_port"]
    assert anomalies, "非标准端口高频访问应被识别"
    assert anomalies[0].dest_port == 4444
    assert anomalies[0].source_ip == "45.33.32.156"


def test_standard_port_not_flagged(engine):
    snapshot = TrafficSnapshot(
        ts=time.time(), interval=0.5,
        ports=[PortSample(port=443, protocol="TCP", pps=5000.0, bps=8_000_000.0,
                          conns=900, is_standard=True, top_source="10.20.0.11")],
    )
    assert not [item for item in engine.evaluate(snapshot) if item.category == "nonstandard_port"], \
        "标准端口的大流量不应触发非标准端口告警"


# --------------------------------------------------------------------------- #
# 规则 3/4：端口扫描 与 暴破
# --------------------------------------------------------------------------- #
def test_detect_port_scan(engine):
    hits = {port: 1 for port in range(1, 121)}     # 120 个不同目的端口
    snapshot = TrafficSnapshot(
        ts=time.time(), interval=0.5,
        sources=[SourceSample(ip="203.0.113.66", pps=240.0, bps=115200.0, packets=120,
                              nbytes=7200, unique_dst_ports=120, unique_dst_ips=1,
                              conns=1, syn_packets=120, dst_port_hits=hits)],
    )
    anomalies = [item for item in engine.evaluate(snapshot) if item.category == "port_scan"]
    assert anomalies, "高目的端口多样性应判定为端口扫描"
    assert anomalies[0].evidence["unique_dst_ports"] == 120


def test_detect_brute_force(engine):
    snapshot = TrafficSnapshot(
        ts=time.time(), interval=0.5,
        sources=[SourceSample(ip="198.51.100.23", pps=140.0, bps=67200.0, packets=70,
                              nbytes=8400, unique_dst_ports=1, unique_dst_ips=1,
                              conns=1, dst_port_hits={22: 70})],
    )
    anomalies = [item for item in engine.evaluate(snapshot) if item.category == "brute_force"]
    assert anomalies, "认证端口高频访问应判定为暴破"
    assert anomalies[0].dest_port == 22


# --------------------------------------------------------------------------- #
# 告警抑制（防止告警风暴）
# --------------------------------------------------------------------------- #
def test_cooldown_suppresses_duplicate_alerts(engine):
    snapshot = TrafficSnapshot(
        ts=time.time(), interval=0.5,
        ports=[PortSample(port=31337, protocol="TCP", pps=300.0, bps=90000.0,
                          conns=80, is_standard=False, top_source="45.33.32.156")],
    )
    first = [item for item in engine.evaluate(snapshot) if item.category == "nonstandard_port"]
    second = [item for item in engine.evaluate(snapshot) if item.category == "nonstandard_port"]
    assert first and not second, "冷却窗口内的重复告警必须被抑制"


# --------------------------------------------------------------------------- #
# ML 组件
# --------------------------------------------------------------------------- #
def test_isolation_forest_trains_and_scores_outlier():
    detector = IsolationForestDetector(contamination=0.05, enabled=True, warmup=60)
    if not detector.available:
        pytest.skip("未安装 scikit-learn，统计检测链路仍可独立工作")
    import random

    for _ in range(200):
        detector.observe([random.gauss(50, 5), random.gauss(1000, 50), 3.0, 1.0,
                          800.0, 2.0, 0.05, 500.0])
    outlier = detector.observe([900.0, 90_000_000.0, 4000.0, 250.0, 64.0, 3000.0, 0.98, 30_000.0])
    assert detector.trained
    assert outlier is not None
    assert 0 <= outlier["score"] <= 1


def test_detect_ignore_ips_suppresses_self_scan():
    """传感器自身的扫描（如 127.0.0.1 扫描本机业务站点）不得产生端口扫描误报。"""
    from app.config import Settings
    from app.detection.engine import DetectionEngine

    hits = {port: 1 for port in range(1, 121)}
    snapshot = TrafficSnapshot(
        ts=time.time(), interval=0.5,
        sources=[SourceSample(ip="127.0.0.1", pps=240.0, bps=115200.0, packets=120,
                              nbytes=7200, unique_dst_ports=120, unique_dst_ips=1,
                              conns=1, syn_packets=120, dst_port_hits=hits)],
    )
    ignored = DetectionEngine(Settings(detect_ignore_ips=["127.0.0.1"]))
    assert not [item for item in ignored.evaluate(snapshot) if item.category == "port_scan"]

    normal = DetectionEngine(Settings(detect_ignore_ips=[]))
    assert [item for item in normal.evaluate(snapshot) if item.category == "port_scan"]
