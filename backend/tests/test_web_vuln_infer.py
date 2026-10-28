"""攻击流量证据 → 漏洞判定测试。

覆盖：
1. 响应特征研判（命令回显 / 数据库报错 / 本地文件内容 / 载荷反射 / 拦截页 / 无响应）；
2. 聚合逻辑（同一服务同一类只出一条，多端口分开）；
3. AI 复核可用与不可用两条路径，以及"规则已确认时模型不能推翻"的约束；
4. 落库与资产计数：`scan_traffic` 写入 vulnerabilities 并刷新 vuln_count；
5. 措辞通用性：漏洞名只能是类型名，不能带产品/靶场名。
"""

from __future__ import annotations

import pytest

from app.analysis import web_vuln_infer as infer_mod
from app.analysis.web_vuln_infer import (
    CONFIRMED,
    DISMISSED,
    SUSPECTED,
    Evidence,
    WebVulnInferrer,
    judge_by_response,
)
from app.database import session_scope
from app.models import Asset, ThreatEvent, Vulnerability, utcnow

SERVER = "192.168.1.50"
ATTACKER = "203.0.113.77"


def make_event(category="web_command_injection", port=80, status=200,
               response_body="", query="", path="/api/tools/ping"):
    """构造一条已落库形态的攻击事件（用于规则研判单测）。"""
    return Evidence(event_id=1, ts=utcnow(), asset_ip=SERVER, port=port, method="POST",
                    path=path, query=query, status=status, category=category,
                    request_body="ip=127.0.0.1;id", response_head="HTTP/1.1 %d OK" % status,
                    response_body=response_body)


# --------------------------------------------------------------------------- #
# 1. 响应特征研判
# --------------------------------------------------------------------------- #
def test_command_injection_confirmed_by_shell_output():
    event = make_event(response_body="<pre>uid=33(www-data) gid=33(www-data) groups=33</pre>")
    result = judge_by_response(event, "web_command_injection")
    assert result.verdict == CONFIRMED
    assert "uid=33" in result.snippet
    assert result.judged_by == "rule"


def test_sql_injection_confirmed_by_database_error():
    event = make_event(category="web_sql_injection",
                       response_body="You have an error in your SQL syntax near '1'' at line 1")
    result = judge_by_response(event, "web_sql_injection")
    assert result.verdict == CONFIRMED


def test_path_traversal_confirmed_by_passwd_content():
    event = make_event(category="web_path_traversal",
                       response_body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
    assert judge_by_response(event, "web_path_traversal").verdict == CONFIRMED


def test_reflected_xss_confirmed_when_payload_echoed():
    event = make_event(category="web_xss_reflected", query="q=<script>alert(1)</script>",
                       response_body="<div>搜索结果：<script>alert(1)</script></div>")
    assert judge_by_response(event, "web_xss_reflected").verdict == CONFIRMED


def test_blocked_response_is_dismissed():
    event = make_event(status=403, response_body="Request rejected by web application firewall")
    assert judge_by_response(event, "web_sql_injection").verdict == DISMISSED


def test_missing_response_stays_suspected():
    event = Evidence(event_id=2, ts=utcnow(), asset_ip=SERVER, port=80, method="GET",
                     path="/x", query="id=1'", status=0, category="web_sql_injection")
    result = judge_by_response(event, "web_sql_injection")
    assert result.verdict == SUSPECTED
    assert "没有响应包" in result.rationale


def test_generic_response_without_evidence_is_suspected():
    event = make_event(response_body="<html>欢迎访问</html>")
    assert judge_by_response(event, "web_command_injection").verdict == SUSPECTED


# --------------------------------------------------------------------------- #
# 2. 聚合与落库
# --------------------------------------------------------------------------- #
@pytest.fixture()
def seeded_asset():
    """造一台有 Web 服务的资产 + 三条攻击事件（两个端口、两类漏洞）。"""
    with session_scope() as session:
        session.query(Vulnerability).filter(Vulnerability.asset_ip == SERVER).delete()
        session.query(ThreatEvent).filter(ThreatEvent.dest_ip == SERVER).delete()
        session.query(Asset).filter(Asset.ip == SERVER).delete()
        session.add(Asset(ip=SERVER, hostname="app", open_ports=[80, 8080],
                          services=[{"port": 80, "name": "http", "product": "nginx",
                                     "version": "1.18.0", "banner": "nginx/1.18.0"}],
                          risk_level="low"))
        session.add_all([
            ThreatEvent(ts=utcnow(), source_ip=ATTACKER, dest_ip=SERVER, dest_port=80,
                        direction="inbound", category="web_command_injection",
                        severity="critical", method="POST", path="/api/tools/ping",
                        request_body="ip=127.0.0.1;id",
                        response_head="HTTP/1.1 200 OK",
                        response_body="uid=33(www-data) gid=33(www-data)"),
            ThreatEvent(ts=utcnow(), source_ip=ATTACKER, dest_ip=SERVER, dest_port=80,
                        direction="inbound", category="web_command_injection",
                        severity="critical", method="POST", path="/api/tools/ping",
                        request_body="ip=127.0.0.1;whoami",
                        response_head="HTTP/1.1 200 OK", response_body="www-data"),
            ThreatEvent(ts=utcnow(), source_ip=ATTACKER, dest_ip=SERVER, dest_port=8080,
                        direction="inbound", category="web_sql_injection",
                        severity="critical", method="GET", path="/item",
                        query="id=1'", response_head="HTTP/1.1 200 OK",
                        response_body="SQLSTATE[42000]: Syntax error or access violation"),
        ])
    yield SERVER


def test_infer_groups_by_port_and_category(seeded_asset):
    findings = WebVulnInferrer().infer(seeded_asset, use_ai=False)
    assert len(findings) == 2
    by_port = {item.port: item for item in findings}
    assert by_port[80].title == "命令注入" and by_port[80].confidence == CONFIRMED
    assert by_port[8080].title == "SQL 注入"
    assert by_port[80].service == "nginx 1.18.0"       # 服务名取自资产指纹
    assert len(by_port[80].event_ids) == 2             # 同类事件被合并到一条结论


def test_finding_title_is_generic(seeded_asset):
    """漏洞名只能是类型名：不得出现任何产品/靶场/站点名。"""
    findings = WebVulnInferrer().infer(seeded_asset, use_ai=False)
    banned = ("DVWA", "dvwa", "damn vulnerable", "pikachu", "bwapp")
    for item in findings:
        assert not any(word in item.title for word in banned)
        assert item.title in {"命令注入", "SQL 注入", "SQL 盲注", "文件包含", "任意文件上传"}


def test_scan_traffic_persists_and_updates_asset(seeded_asset):
    from app.config import get_settings
    from app.scanner.vulnerability import VulnerabilityScanner

    scanner = VulnerabilityScanner(get_settings())
    result = scanner.scan_traffic(seeded_asset, use_ai=False)
    assert result["vulns_found"] == 2

    with session_scope() as session:
        rows = session.query(Vulnerability).filter(
            Vulnerability.asset_ip == seeded_asset).all()
        assert len(rows) == 2
        for row in rows:
            assert row.source in {"traffic_rule", "traffic_ai"}
            assert row.confidence == "confirmed"
            assert row.cve.startswith("CWE-")
        asset = session.query(Asset).filter(Asset.ip == seeded_asset).first()
        assert asset.vuln_count == 2

    # 幂等：再跑一次不产生重复记录，但证据/时间会刷新
    scanner.scan_traffic(seeded_asset, use_ai=False)
    with session_scope() as session:
        assert session.query(Vulnerability).filter(
            Vulnerability.asset_ip == seeded_asset).count() == 2


# --------------------------------------------------------------------------- #
# 3. AI 复核
# --------------------------------------------------------------------------- #
class FakeClient:
    """可控的模型桩：只实现 inferrer 用到的两个成员。"""

    def __init__(self, reply=None, available=True):
        self._reply = reply or {}
        self.available = available
        self.calls = 0

    def chat_json(self, messages, max_tokens=400, temperature=0.0):
        self.calls += 1
        self.last_messages = messages
        return dict(self._reply)


def test_ai_can_upgrade_suspected_to_confirmed(seeded_asset):
    client = FakeClient({"verdict": "vulnerable", "confidence": 0.9,
                         "rationale": "响应体包含命令执行结果"})
    findings = WebVulnInferrer(client=client).infer(seeded_asset, use_ai=True)
    assert client.calls == 2                       # 两个类别各复核一次
    assert all(item.judged_by == "ai" for item in findings)
    assert all(item.confidence == CONFIRMED for item in findings)
    assert all(item.source == "traffic_ai" for item in findings)


def test_ai_cannot_overrule_objective_evidence(seeded_asset):
    """规则已抓到命令回显时，模型说"没打穿"也不能推翻。"""
    client = FakeClient({"verdict": "not_vulnerable", "confidence": 0.95,
                         "rationale": "看起来像正常页面"})
    findings = WebVulnInferrer(client=client).infer(seeded_asset, use_ai=True)
    assert {item.confidence for item in findings} == {CONFIRMED}


def test_ai_dismisses_high_confidence_negative():
    """请求像攻击、响应没证据时，模型高置信度否定 → 不落库。"""
    with session_scope() as session:
        session.query(ThreatEvent).filter(ThreatEvent.dest_ip == "192.168.1.51").delete()
        session.add(ThreatEvent(ts=utcnow(), source_ip=ATTACKER, dest_ip="192.168.1.51",
                                dest_port=80, category="web_command_injection",
                                method="POST", path="/ping", request_body="ip=;id",
                                response_head="HTTP/1.1 200 OK",
                                response_body="<html>参数格式正确</html>"))
    client = FakeClient({"verdict": "not_vulnerable", "confidence": 0.8,
                         "rationale": "响应为普通提示页，无命令结果"})
    assert WebVulnInferrer(client=client).infer("192.168.1.51", use_ai=True) == []


def test_ai_unavailable_falls_back_to_rules(seeded_asset):
    client = FakeClient(available=False)
    findings = WebVulnInferrer(client=client).infer(seeded_asset, use_ai=True)
    assert client.calls == 0
    assert all(item.judged_by == "rule" for item in findings)


def test_infer_can_be_disabled_by_settings(seeded_asset, monkeypatch):
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "web_vuln_infer_enabled", False, raising=False)
    assert WebVulnInferrer(settings=settings).infer(seeded_asset) == []


# --------------------------------------------------------------------------- #
# 4. 检测链路联动：攻击一发生，漏洞就挂到资产上
# --------------------------------------------------------------------------- #
def test_web_attack_creates_vuln_via_service(settings):
    """Web 攻击经采集链路命中后，应自动落一条「命令注入」到目标服务。"""
    from app.collector.service import CollectorService
    from app.models import ThreatEvent

    target = "192.168.1.60"
    with session_scope() as session:
        session.query(Vulnerability).filter(Vulnerability.asset_ip == target).delete()
        session.query(ThreatEvent).filter(ThreatEvent.dest_ip == target).delete()
        session.query(Asset).filter(Asset.ip == target).delete()
        session.add(Asset(ip=target, hostname="demo-app", open_ports=[80],
                          services=[{"port": 80, "name": "http", "product": "nginx",
                                     "version": "1.20.1", "banner": "nginx/1.20.1"}]))

    service = CollectorService(settings)
    service.ingest_web_requests([{
        "method": "POST", "path": "/api/diag/ping", "src_ip": ATTACKER,
        "dst_ip": target, "dst_port": 80,
        "body": "host=127.0.0.1;id",
        "status": 200, "response_body": "<pre>uid=33(www-data) gid=33(www-data)</pre>",
    }])

    with session_scope() as session:
        rows = session.query(Vulnerability).filter(
            Vulnerability.asset_ip == target).all()
    assert rows, "攻击命中后应产出漏洞结论"
    row = rows[0]
    assert row.title == "命令注入"
    assert row.cve == "CWE-78"
    assert row.source in {"traffic_rule", "traffic_ai"}
    assert row.service.startswith("nginx")


# --------------------------------------------------------------------------- #
# 5. 接口契约：资产详情返回「服务 → 漏洞」分组
# --------------------------------------------------------------------------- #
def test_asset_detail_returns_service_grouped_vulns():
    from fastapi.testclient import TestClient

    from app.main import create_app

    target = "192.168.1.70"
    with session_scope() as session:
        session.query(Vulnerability).filter(Vulnerability.asset_ip == target).delete()
        session.query(ThreatEvent).filter(ThreatEvent.dest_ip == target).delete()
        session.query(Asset).filter(Asset.ip == target).delete()
        session.add(Asset(ip=target, hostname="detail-app", open_ports=[80],
                          services=[{"port": 80, "name": "http", "product": "nginx",
                                     "version": "1.20.1", "banner": "nginx/1.20.1"}]))
        session.add(ThreatEvent(ts=utcnow(), source_ip=ATTACKER, dest_ip=target,
                                dest_port=80, category="web_path_traversal",
                                method="GET", path="/download", query="f=../../etc/passwd",
                                response_head="HTTP/1.1 200 OK",
                                response_body="root:x:0:0:root:/root:/bin/bash"))

    with TestClient(create_app()) as client:
        # 手动触发研判（该用例不依赖模型：无 Key 时自动回落规则判定）
        infer = client.post(f"/api/v1/assets/{target}/vuln-infer?use_ai=false")
        assert infer.status_code == 200
        assert infer.json()["vulns_found"] >= 1

        detail = client.get(f"/api/v1/assets/{target}").json()
    groups = detail["service_vulns"]
    assert groups and groups[0]["port"] == 80
    assert groups[0]["label"].startswith("80/tcp")
    titles = [item["title"] for item in groups[0]["vulns"]]
    assert "目录穿越" in titles
    assert groups[0]["confirmed"] >= 1
