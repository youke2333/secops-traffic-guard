"""API 集成测试（含 SSE）。"""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


@pytest.fixture(scope="module")
def client():
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


def test_health_reports_capture_and_firewall(client: TestClient):
    payload = client.get(f"{API}/health").json()
    assert payload["status"] == "ok"
    assert payload["dry_run"] is True
    assert payload["capture_mode"] in {"demo", "scapy", "ebpf"}
    assert payload["channels"]


def test_overview_contains_dashboard_kpis(client: TestClient):
    payload = client.get(f"{API}/overview").json()
    for key in ("bps", "bandwidth_util", "pps", "conns", "alerts_total", "blocked_active",
                "assets_total", "vulns_open", "risk_score", "firewall_backend", "dry_run"):
        assert key in payload, f"缺少大屏 KPI 字段: {key}"


def test_metrics_endpoints(client: TestClient):
    trend = client.get(f"{API}/metrics/trend", params={"window_sec": 30}).json()
    assert trend["window_sec"] == 30
    assert isinstance(trend["bps_in"], list)
    ports = client.get(f"{API}/metrics/ports", params={"top": 5}).json()
    assert "items" in ports
    portfolio = client.get(f"{API}/metrics/portfolio").json()
    assert "overview" in portfolio and "trend" in portfolio


def test_block_lifecycle(client: TestClient):
    created = client.post(f"{API}/blocks", json={
        "ip": "203.0.113.200", "reason": "接口测试封禁", "category": "manual", "ttl_sec": 120,
    }).json()
    assert created["success"] is True

    listing = client.get(f"{API}/blocks", params={"active_only": True}).json()
    assert any(item["ip"] == "203.0.113.200" for item in listing["items"])

    released = client.delete(f"{API}/blocks/203.0.113.200").json()
    assert released["success"] is True

    listing_after = client.get(f"{API}/blocks", params={"active_only": True}).json()
    assert not any(item["ip"] == "203.0.113.200" for item in listing_after["items"])


def test_block_rejects_invalid_ip(client: TestClient):
    response = client.post(f"{API}/blocks", json={"ip": "192.168.1.1; rm -rf /", "reason": "注入尝试"})
    assert response.status_code == 422


def test_whitelist_lifecycle(client: TestClient):
    added = client.post(f"{API}/whitelist", json={"cidr": "203.0.113.128/25", "note": "接口测试"}).json()
    assert added["success"] is True

    blocked = client.post(f"{API}/blocks", json={"ip": "203.0.113.130", "reason": "白名单应拦截"}).json()
    assert blocked["success"] is False
    assert blocked["code"] == "whitelisted", "应返回语义化 code 便于调用方分支处理"

    removed = client.delete(f"{API}/whitelist/203.0.113.128/25").json()
    assert removed["success"] is True


def test_alerts_and_disposals(client: TestClient):
    assert isinstance(client.get(f"{API}/alerts", params={"limit": 5}).json(), list)
    feed = client.get(f"{API}/alerts/feed", params={"limit": 5}).json()
    assert "items" in feed
    stats = client.get(f"{API}/alerts/stats", params={"hours": 1}).json()
    assert "by_category" in stats and "top_sources" in stats
    timeline = client.get(f"{API}/disposals").json()
    assert "items" in timeline


def test_asset_and_vuln_endpoints(client: TestClient):
    assert isinstance(client.get(f"{API}/assets", params={"limit": 10}).json(), list)
    summary = client.get(f"{API}/assets/summary").json()
    assert "risk_distribution" in summary
    vulns = client.get(f"{API}/vulns", params={"limit": 10}).json()
    assert isinstance(vulns, list)
    vuln_summary = client.get(f"{API}/vulns/summary").json()
    assert vuln_summary["kb"]["rules"] > 0


def test_metrics_sessions_and_port_baseline(client: TestClient):
    sessions = client.get(f"{API}/metrics/sessions", params={"top": 5}).json()
    assert "items" in sessions and "conn_table" in sessions
    baseline = client.get(f"{API}/metrics/ports/baseline").json()
    assert "threshold" in baseline and "standard_ports" in baseline and "window_sec" in baseline


def test_block_extend_and_alert_detail(client: TestClient):
    client.post(f"{API}/blocks", json={"ip": "203.0.113.88", "reason": "续期测试", "ttl_sec": 300})
    extended = client.post(f"{API}/blocks/203.0.113.88/extend", params={"ttl_sec": 3600}).json()
    assert extended["success"] is True and extended["code"] == "extended"
    assert extended["detail"]["ttl_sec"] == 3600
    client.delete(f"{API}/blocks/203.0.113.88")

    missing = client.post(f"{API}/blocks/198.51.100.7/extend", params={"ttl_sec": 600})
    assert missing.status_code == 404, "未封禁的 IP 续期应返回 404"

    alerts = client.get(f"{API}/alerts", params={"limit": 1}).json()
    if alerts:
        detail = client.get(f"{API}/alerts/{alerts[0]['id']}").json()
        assert detail["suggestion"] and detail["category_text"]


def test_asset_rescan_endpoint(client: TestClient):
    result = client.post(f"{API}/assets/127.0.0.1/rescan", params={"use_nmap": "false"}).json()
    assert result["ip"] == "127.0.0.1"
    assert "open_ports" in result and "services" in result
    assert client.get(f"{API}/assets/127.0.0.1").status_code in (200, 404)


def test_scan_endpoint_single_closed_port(client: TestClient):
    """只扫一个必然关闭的端口，保证用例快速且无副作用（sync 模式便于断言）。"""
    result = client.post(f"{API}/vulns/scan",
                         params={"sync": "true"},
                         json={"targets": ["127.0.0.1"], "ports": "1", "use_nmap": False}).json()
    assert result["targets"] == 1
    assert result["engine"] == "banner-grab"
    assert result["mode"] == "sync"


def test_scan_job_async_mode_and_status(client: TestClient):
    """异步扫描：提交即返回 job_id，可通过任务接口查询进度。"""
    submitted = client.post(f"{API}/vulns/scan",
                            json={"targets": ["127.0.0.1"], "ports": "1", "use_nmap": False}).json()
    assert submitted["mode"] == "async" and submitted["job_id"].startswith("scan-")

    job = None
    for _ in range(40):                      # 最多等 8 秒
        job = client.get(f"{API}/vulns/scan/{submitted['job_id']}").json()
        if job["status"] in {"done", "error"}:
            break
        time.sleep(0.2)
    assert job is not None and job["status"] == "done", str(job)
    assert job["percent"] == 100.0

    jobs = client.get(f"{API}/vulns/scan/jobs").json()
    assert jobs["total"] >= 1 and "stats" in jobs


def test_notify_channels_and_sse_frame_contract(client: TestClient):
    """通知通道 + SSE 帧契约。

    说明：starlette 1.6.0 的 TestClient（httpx 后端，已被官方标记弃用）无法读取无限流式响应，
    因此这里只校验「帧格式」与「事件总线」两层契约；HTTP 层的真实 SSE 推送由
    `scripts/verify_runtime.py` 启动真实 uvicorn 服务端到端验证。
    """
    channels = client.get(f"{API}/notify/channels").json()
    assert "channels" in channels and "history" in channels

    from app.api.routes_metrics import sse_frame
    from app.bus import EventBus

    frame = sse_frame("metrics", {"bps_in": 1024, "中文": "正常"})
    assert frame.startswith("event: metrics\ndata: ")
    assert frame.endswith("\n\n")
    payload = json.loads(frame.split("data: ", 1)[1].strip())
    assert payload["bps_in"] == 1024 and payload["中文"] == "正常"

    bus = EventBus(maxlen=8)
    subscriber = bus.subscribe()
    bus.publish("metrics", {"a": 1})
    bus.publish("alert", {"b": 2})
    assert bus.drain(subscriber, "metrics")[0]["data"] == {"a": 1}
    assert bus.drain(subscriber, "alert")[0]["data"] == {"b": 2}
    bus.unsubscribe(subscriber)
    assert bus.drain(subscriber) == [], "退订后不应再收到事件"


def test_ai_endpoints_and_webapp_scan(client: TestClient):
    status = client.get(f"{API}/ai/status").json()
    assert "client_available" in status and "traffic_analysis" in status
    review = client.get(f"{API}/ai/traffic/review", params={"window_minutes": 5}).json()
    assert review["verdict"] in {"normal", "suspicious", "malicious", "unknown"}
    assert review["source"] and "degraded" in review

    # 不可达目标：只做指纹探测，不产生任何漏洞记录（防误报）
    result = client.post(f"{API}/scanner/webapp",
                         json={"url": "http://127.0.0.1:1/"}).json()
    assert result["fingerprint"]["title"] == "" and result["fingerprint"]["server"] == ""
    assert result["vulns"] == [] and result["vulns_found"] == 0


def test_vuln_ai_advice_falls_back_and_persists(client: TestClient):
    from app.database import session_scope
    from app.models import Vulnerability

    with session_scope() as session:
        row = Vulnerability(asset_ip="127.0.0.1", port=8080, service="http",
                            cve="WEB-005", title="环境变量文件可下载（凭据泄露）",
                            severity="high", cvss=8.1, recommendation="移出站点根目录并轮换凭据",
                            fixed_version="按安全基线整改", status="open")
        session.add(row)
        session.flush()
        vuln_id = row.id

    result = client.post(f"{API}/vulns/{vuln_id}/ai-advice").json()
    assert result["vuln_id"] == vuln_id
    assert result["source"] and result["steps"] and result["verification"]

    rows = client.get(f"{API}/vulns", params={"limit": 300}).json()
    target = [item for item in rows if item["id"] == vuln_id][0]
    assert target["ai_advice"] is not None
    assert target["ai_source"] == result["source"]
