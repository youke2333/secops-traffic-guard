"""通用能力测试：高置信直达规则 / 防误报 / Web 应用漏扫 / AI 建议降级。

这里的"被测站点"是一个自建的普通业务站点（登录、后台、演示页、敏感文件、
版本头），不模拟任何特定产品，用来验证系统只依赖通用特征即可发现漏洞。
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.analysis.traffic_advisor import TrafficAdvisor
from app.analysis.vuln_advisor import VulnAdvisor
from app.collector.http_proxy import build_event_payload
from app.config import Settings
from app.detection.web_knowledge import WebAttackDetector, WebRequestEvent
from app.scanner.cve import CveKnowledgeBase
from app.scanner.webapp import WebAppScanner


def _event(**overrides):
    payload = {
        "src_ip": "203.0.113.10", "dst_ip": "192.168.1.50", "dst_port": 8080,
        "method": "GET", "path": "/product/query", "query": "",
    }
    payload.update(overrides)
    return WebRequestEvent.from_dict(payload)


# --------------------------------------------------------------------------- #
# 高置信直达规则：只看载荷，不限定业务路径/产品
# --------------------------------------------------------------------------- #
def test_strict_rule_direct_alert_is_path_agnostic():
    detector = WebAttackDetector(Settings())

    # 任意业务路径上的明确攻击载荷都应直达，便于自动封禁
    attack = detector.evaluate(_event(
        path="/product/query", query="id=1%27+UNION+SELECT+user,password+FROM+users--+-"))
    assert attack, "UNION SELECT 载荷必须命中高置信规则"
    assert attack[0].category == "web_sql_injection"
    assert attack[0].direct_alert is True
    assert "ST-SQLI-001" in attack[0].evidence["rule_ids"]

    # 换成另一条业务路径，结论不变（不再依赖靶场目录）
    other = detector.evaluate(_event(
        src_ip="203.0.113.13", path="/api/v2/order/list",
        query="keyword=1%27+UNION+SELECT+1,2,3--+-"))
    assert other and other[0].direct_alert is True


def test_strict_rule_does_not_fire_on_normal_params():
    detector = WebAttackDetector(Settings())
    for index, query in enumerate(("id=1&Submit=Submit", "id=1", "name=guest",
                                   "q=select+box+from+catalog", "sort=price_asc")):
        assert detector.evaluate(_event(src_ip=f"203.0.113.{20 + index}", query=query)) == []


def test_web_ignore_ips_suppress_self_access():
    detector = WebAttackDetector(Settings(web_ignore_ips=["203.0.113.30"]))
    anomalies = detector.evaluate(_event(src_ip="203.0.113.30",
                                         query="id=1%27+OR+%271%27%3D%271"))
    assert anomalies == [], "忽略名单内的来源不得产生 Web 告警"
    assert detector.stats["ignored_sources"] == 1


# --------------------------------------------------------------------------- #
# CVE 匹配：版本未知不猜
# --------------------------------------------------------------------------- #
def test_unknown_version_never_guesses_cve(settings):
    kb = CveKnowledgeBase(settings.cve_rules_path, additional_rules=[{
        "cve": "TEST-UNKNOWN-1", "product_regex": "openssh", "version_lt": "9.0",
        "severity": "high", "recommendation": "升级",
    }])
    matches = kb.match(product="OpenSSH", version="", port=22, service="ssh")
    assert not [item for item in matches if item.cve == "TEST-UNKNOWN-1"]


# --------------------------------------------------------------------------- #
# Web 应用漏扫：本地普通业务站点（验证通用检查项与证据）
# --------------------------------------------------------------------------- #
class _BusinessSiteHandler(BaseHTTPRequestHandler):
    """一个"配置不够安全"的普通业务站点：缺安全头、敏感文件、后台、演示页。"""

    server_version = "Apache/2.4.20"
    sys_version = "(Ubuntu)"
    protocol_version = "HTTP/1.1"

    def _send(self, status, body="", headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.3.9")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def _authed(self) -> bool:
        return "SID=" in (self.headers.get("Cookie", "") or "")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            if self._authed():
                self._send(200, "<title>订单管理系统</title>"
                                "<a href='admin/'>后台</a><a href='demo/query.php'>查询演示</a>")
            else:
                self._send(200, "<title>订单管理系统 - 登录</title>"
                                "<form action='/login.php' method='post'>"
                                "<input type='text' name='username'>"
                                "<input type='password' name='password'>"
                                "<input type='hidden' name='csrf' value='tok123'>"
                                "</form>",
                           {"Set-Cookie": "VISITOR=1; Path=/"})
        elif path == "/login.php":
            self._send(200, "<form action='/login.php' method='post'>"
                            "<input type='password' name='password'></form>")
        elif path == "/.env":
            self._send(200, "APP_KEY=base64:xxx\nDB_PASSWORD=P@ssw0rd\nSECRET_KEY=abcd")
        elif path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n")
        elif path == "/setup.php":
            self._send(200, "<h1>Database Setup</h1><p>install wizard</p>")
        elif path == "/admin/":
            self._send(200, "<title>admin login</title>"
                            "<input type='password' name='admin_pass'>")
        elif path == "/demo/query.php":
            self._send(200, "<title>查询演示 - SQL Injection</title>"
                            "<form action='query.php' method='get'>"
                            "<input type='text' name='id'></form>")
        elif path == "/__secops_probe_404__":
            self._send(404, "Fatal error: Uncaught Error in "
                            "/var/www/html/app/index.php on line 12")
        else:
            self._send(404, "not found")

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(length)
        if path == "/login.php":
            self._send(302, "", {"Location": "/",
                                 "Set-Cookie": "SID=abc123; Path=/"})
        else:
            self._send(200, "ok")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def site_port():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BusinessSiteHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()


def _scanner(settings, port, username="tester", password="secret"):
    cfg = Settings(webapp_scan_timeout_sec=1.0,
                   webapp_scan_username=username, webapp_scan_password=password,
                   webapp_scan_max_pages=12, webapp_scan_max_seconds=8.0,
                   cve_rules_file=str(settings.cve_rules_path))
    return WebAppScanner(cfg, knowledge_base=CveKnowledgeBase(cfg.cve_rules_path))


def test_webapp_scanner_finds_generic_issues_with_evidence(settings, site_port):
    scanner = _scanner(settings, site_port)
    info, matches = scanner.scan("127.0.0.1", site_port)
    ids = {item.cve for item in matches}

    assert info["logged_in"] is True, "配置了凭据时应完成通用表单登录"
    assert info["title"].startswith("订单管理系统")
    # 通用检查项：安全头 / Cookie / 版本 / 敏感文件 / 安装脚本 / 危险方法 / 错误页 / 后台 / 演示页
    assert {"WEB-001", "WEB-002", "WEB-003", "WEB-005", "WEB-006",
            "WEB-007", "WEB-008", "WEB-009", "WEB-010", "WEB-011"} <= ids
    assert "CVE-2023-25690" in ids, "Apache 2.4.20 应命中版本区间内的 CVE"
    assert all(item.evidence for item in matches), "每条发现都必须带 HTTP 证据"


def test_webapp_scanner_reports_no_findings_on_hardened_site(settings):
    """加固过的站点不应产生上述任何检查项（避免误报）。"""

    class _HardenedHandler(BaseHTTPRequestHandler):
        server_version = "nginx"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def _send(self, status, body=""):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            for header, value in (
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
            ):
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.split("?", 1)[0] == "/":
                self._send(200, "<title>安全站点</title><a href='/about'>关于</a>")
            else:
                self._send(404, "<h1>Not Found</h1>")

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header("Allow", "GET, HEAD, OPTIONS")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _HardenedHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        scanner = _scanner(settings, server.server_address[1], username="", password="")
        info, matches = scanner.scan("127.0.0.1", server.server_address[1])
    finally:
        server.shutdown()

    ids = {item.cve for item in matches}
    assert info["server"] == "nginx"
    assert not ids & {"WEB-001", "WEB-002", "WEB-004", "WEB-005", "WEB-006",
                      "WEB-007", "WEB-008", "WEB-009", "WEB-010"}
    assert info["logged_in"] is False


def test_proxy_payload_keeps_post_body_for_detection():
    """访问日志没有 body；代理投递必须保留 POST 载荷，否则命令注入/上传会漏检。"""
    payload = build_event_payload(
        "POST", "/tools/ping?x=1",
        {"User-Agent": "curl/8", "Content-Type": "application/x-www-form-urlencoded",
         "X-Not-Forwarded": "secret"},
        b"ip=127.0.0.1%3Bcat+%2Fetc%2Fpasswd&Submit=Submit",
        src_ip="203.0.113.12", dst_ip="192.168.1.50", dst_port=8080,
        status=200, now=1700000000.0,
    )
    assert payload["path"] == "/tools/ping"
    assert payload["query"] == "x=1"
    assert "cat+%2Fetc%2Fpasswd" in payload["body"]
    assert payload["headers"] == {"user-agent": "curl/8",
                                  "content-type": "application/x-www-form-urlencoded"}
    assert payload["source"] == "api" and payload["ts"] == 1700000000.0

    hits = WebAttackDetector(Settings()).evaluate(WebRequestEvent.from_dict(payload))
    assert hits and hits[0].category == "web_command_injection"
    assert hits[0].direct_alert is True


# --------------------------------------------------------------------------- #
# AI 建议：不可用时降级且仍可执行
# --------------------------------------------------------------------------- #
class _UnavailableClient:
    available = False


def test_vuln_advisor_falls_back_to_knowledge_base(settings):
    advisor = VulnAdvisor(settings, client=_UnavailableClient())
    result = advisor.advise({
        "cve": "WEB-005", "title": "环境变量文件可下载（凭据泄露）", "severity": "high",
        "cvss": 8.1, "asset_ip": "192.168.1.50", "port": 8080,
        "recommendation": "", "fixed_version": "",
    })
    assert result["source"] == "knowledge_base" and result["degraded"] is True
    assert len(result["steps"]) >= 3
    assert "访问" in "".join(result["steps"]) or "暴露" in "".join(result["steps"])
    assert result["verification"]


def test_traffic_advisor_heuristic_verdicts(settings):
    advisor = TrafficAdvisor(settings, client=_UnavailableClient())
    bad = advisor.review({
        "window": {"bps_in": 1000, "conns": 10},
        "alerts": {"total": 2, "direct_count": 1, "high_count": 1, "max_risk_score": 9.0,
                   "categories": {"web_sql_injection": 2}},
        "signals": {}, "threshold": 6.0,
    })
    assert bad["verdict"] == "malicious" and bad["degraded"] is True
    normal = advisor.review({"window": {}, "alerts": {"total": 0}, "signals": {},
                             "threshold": 6.0})
    assert normal["verdict"] == "normal"
