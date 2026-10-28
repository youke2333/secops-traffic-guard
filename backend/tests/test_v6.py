"""v6 新增能力的回归测试：认证、威胁事件、报告、规则包、nftables。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.auth.passwords import hash_password, password_is_strong, verify_password
from app.auth.sessions import (
    authenticate,
    create_session,
    resolve_session,
    revoke_session,
)
from app.database import session_scope
from app.models import Alert, BlockRule, ThreatEvent, User, utcnow

API = "/api/v1"


def test_password_hash_and_session_lifecycle(settings):
    assert password_is_strong("StrongPass123", "tester", 10)
    assert not password_is_strong("short", "tester", 10)
    stored = hash_password("StrongPass123")
    assert stored.startswith("scrypt$")
    assert verify_password("StrongPass123", stored)
    assert not verify_password("wrong", stored)

    username = "tester_v6_session"
    with session_scope() as session:
        existing = session.scalar(select(User).where(User.username == username))
        if existing is None:
            session.add(User(username=username, password_hash=stored, role="analyst",
                             display_name="Tester", active=True, must_change_password=False,
                             created_at=utcnow()))
    user, code = authenticate(username, "StrongPass123", settings=settings)
    assert code == "ok" and user["role"] == "analyst"
    session_info = create_session(int(user["id"]), settings=settings)
    resolved = resolve_session(session_info["token"], settings=settings)
    assert resolved and resolved["username"] == username
    assert resolved["csrf_token"] == session_info["csrf_token"]
    revoke_session(session_info["token"])
    assert resolve_session(session_info["token"], settings=settings) is None


def test_threat_event_capture_and_tags(settings):
    from app.detection.engine import Anomaly
    from app.threat.store import list_tags, save_threat_event

    original = list(settings.protected_cidrs)
    settings.protected_cidrs = ["192.168.1.0/24"]
    try:
        anomaly = Anomaly(
            category="web_sql_injection", severity="critical", score=0.95,
            message="UNION SELECT 命中", source_ip="203.0.113.50",
            dest_ip="192.168.1.10", dest_port=8080, detector="web-kb",
            rule_id="INT-SQLI-001", confidence="high", direct_alert=True,
            rule_source="intrusion-pack",
            evidence={
                "category_name": "SQL 注入", "direct_alert": True, "tier": "core",
                "combination_attack": False,
                "request": {"method": "GET", "path": "/sqli", "query": "id=1",
                            "head": "GET /sqli?id=1 HTTP/1.1\nCookie: secret",
                            "body": "id=1 UNION SELECT 1", "status": 200,
                            "source": "api", "capture_level": "L1"},
            },
        )
        event_id = save_threat_event(anomaly, settings=settings)
        assert event_id
        with session_scope() as session:
            row = session.get(ThreatEvent, event_id)
            assert row.direction == "inbound"
            assert row.rule_pack == "intrusion" and row.tier == "core"
            assert row.capture_level == "L1"
            assert "UNION SELECT" in row.request_body
            assert "Cookie: secret" not in row.request_head
        tags = list_tags([event_id])[event_id]
        assert "SQL 注入" in tags and "高危直达" in tags and "core" in tags
    finally:
        settings.protected_cidrs = original


def test_intrusion_pack_and_rule_plan(settings):
    from app.detection.kb_factory import build_web_kb
    from app.rules.packs import load_intrusion_pack

    rules, categories, report = load_intrusion_pack(settings)
    assert report["loaded"] is True
    assert report["selected"] == len(rules) > 0
    assert all(item.get("tier") == "core" for item in rules)
    assert any(item["key"] == "scanner_fingerprint" for item in categories)

    kb = build_web_kb(settings)
    assert kb.matcher.name in {"python", "re2"}
    assert len(kb.rules) > 100
    assert len(kb._plans) == len(kb.rules)
    assert kb.stats["by_tier"]["core"] > 0
    assert kb.stats["matcher"]["matcher_backend"] in {"python", "re2"}


def test_report_generation_contains_nine_sections(settings, tmp_path):
    from app.reports.generator import generate_block_report

    ip = "203.0.113.77"
    original_dir = settings.report_dir
    settings.report_dir = str(tmp_path / "reports")
    try:
        with session_scope() as session:
            session.add(BlockRule(ip=ip, reason="自动封禁：SQL 注入", category="manual",
                                  severity="high", source="auto", operator="system",
                                  backend="iptables", rule_spec="iptables -I INPUT ...",
                                  created_at=utcnow(), active=True, hits=3, dry_run=True))
            session.add(ThreatEvent(
                ts=utcnow(), source_ip=ip, dest_ip="192.168.1.10", dest_port=8080,
                direction="inbound", category="web_sql_injection", severity="critical",
                confidence="high", rule_id="INT-SQLI-001", rule_pack="intrusion",
                tier="core", method="GET", path="/sqli", status_code=200,
                capture_level="L1", request_head="GET /sqli HTTP/1.1",
                request_body="id=1 UNION SELECT 1", message="UNION SELECT",
                evidence={"rules": []}, created_at=utcnow(),
            ))
            session.add(Alert(ts=utcnow(), source_ip=ip, category="web_sql_injection",
                              severity="critical", score=0.95, message="告警",
                              evidence={}, direct_alert=True))
        result = generate_block_report(ip, operator="tester", settings=settings)
        assert result["sha256"] and len(result["sha256"]) == 64
        text = open(result["path"], encoding="utf-8").read()
        for index in range(1, 10):
            assert f"{index}." in text
        assert "安全事件报告" in text and ip in text
        assert "UNION SELECT" in text
    finally:
        settings.report_dir = original_dir


def test_nftables_backend_creates_drop_rule(monkeypatch):
    from app.response.firewall import NftablesBackend

    backend = NftablesBackend(dry_run=False)
    calls = []

    def fake_run(args, require=None):
        calls.append(list(args))
        return True, "ok"

    monkeypatch.setattr(backend, "_run", fake_run)
    ok, message, _args = backend.block("203.0.113.88", ttl_sec=600)
    assert ok and message == "ok"
    assert any("element" in call and "blocklist" in call
               and "203.0.113.88" in " ".join(call) for call in calls)
    assert any("rule" in call and "drop" in call for call in calls)
    assert any("@blocklist" in call for call in calls)
    assert any("chain" in call and "hook" in " ".join(call) for call in calls)
    # CIDR 必须放进 interval 集合，否则 nft "add element" 会拒绝 203.0.113.0/24
    assert any("interval,timeout" in " ".join(call) for call in calls)
    ok, message, _args = backend.block("198.51.100.0/24", ttl_sec=600)
    assert ok and message == "ok"
    assert any("blocklist_cidr" in call and "198.51.100.0/24" in " ".join(call)
               for call in calls)
    ok, message, _args = backend.unblock("198.51.100.0/24")
    assert ok and message == "ok"
    assert any("delete" in call and "blocklist_cidr" in call
               and "198.51.100.0/24" in " ".join(call) for call in calls)



def test_last_admin_cannot_be_demoted_or_disabled():
    """最后一个启用中的 admin 必须保留，否则系统会失去管理入口。"""
    from fastapi import HTTPException
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.api.routes_auth import _guard_last_admin
    from app.database import Base

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    with Session() as session:
        first = User(username="only_admin", password_hash=hash_password("Admin123456"),
                     role="admin", display_name="Only Admin", active=True,
                     must_change_password=False, created_at=utcnow())
        session.add(first)
        session.commit()

        with pytest.raises(HTTPException) as demote:
            _guard_last_admin(session, first, role="viewer")
        assert demote.value.status_code == 400
        with pytest.raises(HTTPException) as disable:
            _guard_last_admin(session, first, active=False)
        assert disable.value.status_code == 400

        second = User(username="second_admin", password_hash=hash_password("Admin123456"),
                      role="admin", display_name="Second Admin", active=True,
                      must_change_password=False, created_at=utcnow())
        session.add(second)
        session.commit()
        _guard_last_admin(session, first, role="viewer")     # 仍有其它 admin，允许降级
        _guard_last_admin(session, second, active=False)     # 仍有其它 admin，允许停用





@pytest.fixture(scope="module")
def client():
    from app.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client



def test_threat_api_and_export(client):
    with session_scope() as session:
        row = ThreatEvent(
            ts=utcnow(), source_ip="203.0.113.210", dest_ip="192.168.1.10",
            dest_port=8080, direction="inbound", category="web_command_injection",
            severity="critical", confidence="high", rule_id="INT-CMDI-001",
            rule_pack="intrusion", tier="core", method="POST", path="/exec",
            status_code=200, capture_level="L1", request_head="POST /exec HTTP/1.1",
            request_body="ip=127.0.0.1;id", message="命令注入", evidence={"rules": []},
            created_at=utcnow(),
        )
        session.add(row)
        session.flush()
        event_id = row.id
    payload = client.get(f"{API}/threats", params={"src_ip": "203.0.113.210"}).json()
    assert payload["total"] >= 1
    assert any(item["id"] == event_id for item in payload["items"])
    detail = client.get(f"{API}/threats/{event_id}").json()
    assert detail["request_body"].startswith("ip=")
    facets = client.get(f"{API}/threats/facets").json()
    assert {"category", "severity", "tags"} <= set(facets)
    exported = client.get(f"{API}/threats/export", params={"src_ip": "203.0.113.210"})
    assert exported.status_code == 200
    assert exported.content.startswith(b"\xef\xbb\xbf")




def test_auth_guard_session_and_csrf(settings):
    username = "v6_admin"
    with session_scope() as session:
        existing = session.scalar(select(User).where(User.username == username))
        if existing is None:
            session.add(User(username=username, password_hash=hash_password("Admin123456"),
                             role="admin", display_name="V6 Admin", active=True,
                             must_change_password=False, created_at=utcnow()))
    original = settings.auth_enabled
    settings.auth_enabled = True
    try:
        from app.main import create_app

        with TestClient(create_app()) as guarded:
            assert guarded.get(f"{API}/overview").status_code == 401
            login = guarded.post(f"{API}/auth/login",
                                 json={"username": username, "password": "Admin123456"})
            assert login.status_code == 200, login.text
            me = guarded.get(f"{API}/auth/me").json()
            csrf = me["csrf_token"]
            assert me["user"]["role"] == "admin"
            assert guarded.post(f"{API}/rules/reload").status_code == 403
            ok = guarded.post(f"{API}/rules/reload", headers={"X-CSRF-Token": csrf})
            assert ok.status_code == 200, ok.text
            created = guarded.post(f"{API}/users", headers={"X-CSRF-Token": csrf}, json={
                "username": "v6_viewer", "password": "ViewerPass123",
                "role": "viewer", "display_name": "只读账号",
            })
            assert created.status_code == 200, created.text
            created_id = created.json()["detail"]["id"]
            listed = guarded.get(f"{API}/users").json()
            assert any(item["username"] == "v6_viewer" for item in listed["items"])
            invalid = guarded.post(f"{API}/users", headers={"X-CSRF-Token": csrf}, json={
                "username": "bad name", "password": "ViewerPass123", "role": "viewer",
            })
            assert invalid.status_code == 400
            disabled = guarded.delete(f"{API}/users/{created_id}",
                                      headers={"X-CSRF-Token": csrf})
            assert disabled.status_code == 200, disabled.text
            enabled = guarded.patch(f"{API}/users/{created_id}",
                                    headers={"X-CSRF-Token": csrf},
                                    json={"active": True})
            assert enabled.status_code == 200, enabled.text
            assert any(item["id"] == created_id and item["active"]
                       for item in guarded.get(f"{API}/users").json()["items"])
            original_token = settings.api_token
            settings.api_token = "v6-machine-token"
            try:
                machine = guarded.post(f"{API}/web/requests", headers={
                    "X-API-Token": "v6-machine-token",
                }, json={"requests": [{"method": "GET", "path": "/health",
                                       "src_ip": "203.0.113.240", "status": 200}]})
                assert machine.status_code == 200, machine.text
            finally:
                settings.api_token = original_token
            guarded.cookies.clear()
            page = guarded.get("/", follow_redirects=False)
            assert page.status_code == 302 and "login.html" in page.headers["location"]
    finally:
        settings.auth_enabled = original



def test_report_api_generate_view_download(client, settings, tmp_path):
    ip = "203.0.113.78"
    with session_scope() as session:
        session.add(BlockRule(ip=ip, reason="报告接口测试", category="manual",
                              severity="high", source="manual", operator="tester",
                              created_at=utcnow(), active=True, hits=1, dry_run=True))
    original = settings.report_dir
    settings.report_dir = str(tmp_path / "api-reports")
    try:
        created = client.post(f"{API}/blocks/{ip}/report")
        assert created.status_code == 200, created.text
        payload = created.json()
        assert payload["report_id"] and len(payload["sha256"]) == 64
        listed = client.get(f"{API}/reports").json()
        assert any(item["id"] == payload["report_id"] for item in listed["items"])
        viewed = client.get(f"{API}/reports/{payload['report_id']}")
        assert viewed.status_code == 200 and "安全事件报告" in viewed.text
        downloaded = client.get(f"{API}/reports/{payload['report_id']}/download")
        assert downloaded.status_code == 200 and "attachment" in downloaded.headers["content-disposition"]
    finally:
        settings.report_dir = original



def test_triage_suppresses_health_probe(settings):
    from app.analysis.triage import TriageEngine
    from app.detection.engine import Anomaly

    original = settings.triage_enabled
    settings.triage_enabled = True
    try:
        engine = TriageEngine(settings)
        assert engine.rules
        anomaly = Anomaly(
            category="web_recon_scan", severity="high", score=0.7,
            message="recon", source_ip="10.0.0.8", dest_ip="10.0.0.9",
            detector="web-kb", rule_id="INT-RECON-001",
            evidence={"request": {"user_agent": "kube-probe/1.29",
                                  "path": "/health", "method": "GET"}},
        )
        result = engine.evaluate(anomaly)
        assert result is not None
        assert result["action"] == "suppress_alert"
        assert result["verdict"] == "benign"
    finally:
        settings.triage_enabled = original



def test_missing_column_planned_and_added(tmp_path):
    """旧库缺列时：计划能列出 ALTER，执行后补齐，重复执行不再产生语句。"""
    from sqlalchemy import create_engine, inspect, text

    from app.database import _add_missing_columns, plan_missing_columns

    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}", future=True)
    # 模拟"旧版本"建出来的表：缺 source / confidence / ai_advice 等后加的列
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE vulnerabilities ("
            "id INTEGER PRIMARY KEY, asset_ip VARCHAR(64), cve VARCHAR(64))"
        ))

    statements = plan_missing_columns(engine)
    joined = " ".join(statements)
    assert "ALTER TABLE vulnerabilities ADD COLUMN" in joined
    assert "ADD COLUMN source" in joined
    assert "ADD COLUMN confidence" in joined

    _add_missing_columns(engine)
    columns = {column["name"] for column in inspect(engine).get_columns("vulnerabilities")}
    assert {"source", "confidence"} <= columns
    assert plan_missing_columns(engine) == []       # 幂等


def test_scan_disabled_returns_409(client, settings):
    """SCANNER_ENABLED=false 时主动扫描接口拒绝执行，被动能力不受影响。"""
    original = settings.scanner_enabled
    settings.scanner_enabled = False
    try:
        assert client.post(f"{API}/vulns/scan", json={}).status_code == 409
        assert client.post(f"{API}/assets/192.168.1.10/rescan").status_code == 409
        assert client.post(f"{API}/scanner/webapp",
                           json={"url": "http://127.0.0.1:9/"}).status_code == 409
        assert client.get(f"{API}/assets").status_code == 200
    finally:
        settings.scanner_enabled = original
