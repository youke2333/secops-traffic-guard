"""接口契约测试（v2）：新增接口 + 老接口向后兼容。

契约硬约束（方案 0.2 节）：
* `/alerts`、`/blocks`、`/vulns`、`/assets` 只新增字段，不删改现有字段；
* 新增字段全部可空/有默认值；
* 所有新增功能都有开关（本文件同时验证开关关闭时的回落行为）。
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# 向后兼容
# --------------------------------------------------------------------------- #
def test_legacy_alert_contract_unchanged(client: TestClient):
    alerts = client.get(f"{API}/alerts", params={"limit": 5}).json()
    assert isinstance(alerts, list)
    for item in alerts:
        for key in ("id", "ts", "source_ip", "dest_ip", "dest_port", "protocol", "category",
                    "severity", "score", "message", "evidence", "status", "blocked", "region"):
            assert key in item, f"老字段 {key} 不能消失"
        for key in ("risk_score", "contributing_rules", "direct_alert", "signal_window_id",
                    "llm_analysis"):
            assert key in item, f"新增字段 {key} 缺失"
    feed = client.get(f"{API}/alerts/feed", params={"limit": 3}).json()
    assert feed["items"] and "direct_alert" in feed["items"][0]


def test_legacy_endpoints_still_work(client: TestClient):
    assert client.get(f"{API}/overview").json()["alerts_total"] >= 0
    assert "items" in client.get(f"{API}/blocks").json()
    assert isinstance(client.get(f"{API}/assets", params={"limit": 3}).json(), list)
    assert isinstance(client.get(f"{API}/vulns").json(), list)
    assert "kb" in client.get(f"{API}/vulns/summary").json()


def test_status_exposes_scoring_block(client: TestClient):
    status = client.get(f"{API}/status").json()
    assert "scoring" in status and "aggregator" in status["scoring"]
    assert "alerts_suppressed" in status
    assert status["engine"]["thresholds"]["port_scan"] > 0


# --------------------------------------------------------------------------- #
# 评分 / 信号
# --------------------------------------------------------------------------- #
def test_scoring_config_endpoint(client: TestClient):
    payload = client.get(f"{API}/scoring/config").json()
    assert payload["threshold"] > 0 and payload["window_sec"] > 0
    assert payload["direct_alert_weight"] == pytest.approx(6.0)
    assert payload["weight_table"]["critical"] == 5.0
    assert "直达" in payload["note"]
    assert "aggregator" in payload["stats"]


def test_signals_endpoints(client: TestClient):
    assert isinstance(client.get(f"{API}/signals", params={"limit": 5}).json(), list)
    window = client.get(f"{API}/signals/window/203.0.113.7").json()
    assert window["source_ip"] == "203.0.113.7"
    assert window["threshold"] > 0 and isinstance(window["items"], list)
    assert isinstance(client.get(f"{API}/signals", params={"suppressed_only": "true"}).json(),
                      list)


def test_rules_endpoints(client: TestClient):
    sources = client.get(f"{API}/rules/sources").json()
    names = {row["source"] for row in sources["sources"]}
    assert names == {"native", "sigma", "et", "cve_ext"}
    assert sources["direct_alert_total"] >= 5
    assert sources["web_kb"]["rules"] >= 60
    assert sources["direct_alert_categories"], "必须能看到哪些大类被标记为直达"

    listing = client.get(f"{API}/rules", params={"source": "et"}).json()
    assert listing["total"] >= 1 and listing["items"][0]["source"] == "et"
    direct = client.get(f"{API}/rules", params={"direct_only": "true"}).json()
    assert direct["total"] >= 5

    reloaded = client.post(f"{API}/rules/reload").json()
    assert reloaded["success"] is True and reloaded["code"] == "reloaded"
    assert "native=" in reloaded["message"]


# --------------------------------------------------------------------------- #
# 阈值管理
# --------------------------------------------------------------------------- #
def test_threshold_endpoints(client: TestClient):
    listing = client.get(f"{API}/thresholds").json()
    assert "items" in listing and "overview" in listing
    overview = client.get(f"{API}/thresholds/static").json()
    assert overview["adaptive_types"] and overview["bounds"]["min_factor"] < 1
    assert "直达" in overview["note"]

    recomputed = client.post(f"{API}/thresholds/recompute").json()
    assert recomputed["success"] is True and recomputed["code"] == "recomputed"
    assert "dimensions" in recomputed["detail"]

    single = client.get(f"{API}/thresholds/port_scan/port_scan").json()
    assert single["static_value"] > 0 and single["threshold_value"] > 0

    assert client.patch(f"{API}/thresholds/999999",
                        json={"threshold_value": 10, "reason": "不存在"}).status_code == 404
    items = client.get(f"{API}/thresholds").json()["items"]
    if items:
        patched = client.patch(f"{API}/thresholds/{items[0]['id']}",
                               json={"threshold_value": items[0]["threshold_value"],
                                     "reason": "接口契约测试"}).json()
        assert patched["code"] == "overridden"
        assert patched["detail"]["manual_override"] is True


# --------------------------------------------------------------------------- #
# 直达告警闭环 + 抑制可见
# --------------------------------------------------------------------------- #
def test_web_attack_direct_alert_closed_loop(client: TestClient):
    """命令注入（critical + high 置信度）必须直达：立即告警、带规则与窗口信息。"""
    response = client.post(f"{API}/web/requests", json={"requests": [{
        "method": "POST", "path": "/vulnerabilities/exec/",
        "body": "ip=127.0.0.1;cat /etc/passwd", "src_ip": "203.0.113.111",
        "dst_ip": "192.168.1.30", "status": 200}]}).json()
    assert response["alert_count"] >= 1
    alert = [item for item in response["alerts"]
             if item["category"] == "web_command_injection"][0]
    assert alert["direct_alert"] is True
    assert alert["risk_score"] >= 6.0
    assert alert["contributing_rules"]
    assert alert["signal_window_id"]
    assert "直达告警" in alert["message"]

    detail = client.get(f"{API}/alerts/{alert['alert_id']}").json()
    assert detail["direct_alert"] is True and detail["risk_score"] >= 6.0
    assert detail["signals"], "直达告警同样要保留窗口 signals（便于前端统一渲染）"
    assert detail["aggregation"]["direct_alert"] is True
    assert "llm_analysis" in detail and "llm_source" in detail

    filtered = client.get(f"{API}/alerts", params={
        "direct_only": "true", "min_score": 6, "limit": 50}).json()
    assert any(item["id"] == alert["alert_id"] for item in filtered)


def test_suppressed_signal_is_visible(client: TestClient):
    """未达阈值的信号不得静默丢弃：alerts 里没有，但 signals 里能看到抑制原因。"""
    response = client.post(f"{API}/web/requests", json={"requests": [{
        "method": "GET", "path": "/redirect",
        "query": "next=%0d%0aLocation:https://example.com", "src_ip": "203.0.113.112",
        "dst_ip": "192.168.1.30", "status": 200}]}).json()
    assert response["alert_count"] == 0, "单条 medium 类攻击不应直接告警"
    signals = client.get(f"{API}/signals", params={
        "source_ip": "203.0.113.112", "limit": 10}).json()
    assert signals, "被抑制的信号必须落库可查"
    assert signals[0]["suppressed"] is True
    assert signals[0]["suppressed_reason"] in {"below_threshold", "cooldown"}


def test_reanalyze_endpoint_degrades_without_api_key(client: TestClient):
    alerts = client.get(f"{API}/alerts", params={"limit": 1}).json()
    if not alerts:
        pytest.skip("当前无告警可研判")
    result = client.post(f"{API}/alerts/{alerts[0]['id']}/reanalyze").json()
    assert result["success"] is True
    analysis = result["detail"]["analysis"]
    assert analysis["source"] in {"deepseek_v4_flash", "local_rules", "template", "pending"}
    assert analysis["verdict"] in {"confirm", "suspect", "dismiss", "unknown"}
    # 测试环境未配置 API Key → 必然降级，且降级必须可见
    assert analysis["degraded"] is True
    assert result["code"] == "degraded"


def test_alert_stats_reports_scoring_fields(client: TestClient):
    stats = client.get(f"{API}/alerts/stats", params={"hours": 24}).json()
    for key in ("total", "blocked", "direct", "avg_risk_score", "signals"):
        assert key in stats, f"统计缺少 {key}"
    assert "suppressed" in stats["signals"]
