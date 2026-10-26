#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web 漏扫离线自检（不依赖第三方库，可在任意 Python 3.8+ 环境运行）。

做两件事：
  1. 起一个"配置不安全的靶场式站点"（登录页、注入演示页、敏感文件、安装脚本、
     后台入口、版本头、TRACE 方法）：验证通用扫描器仍能发现这些漏洞；
  2. 起一个"已加固站点"：验证同样检查项不会误报。

用法：python scripts/verify_web_scan.py
退出码 0 表示全部通过。
"""

from __future__ import annotations

import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

# ---------------------------------------------------------------------------
# 注入轻量 app.config：扫描器只读取少量配置项，这里不引入 pydantic 依赖
# ---------------------------------------------------------------------------
if "app.config" not in sys.modules:
    import app  # noqa: F401  （确保命名空间包已加载）

    fake = types.ModuleType("app.config")

    class Settings:  # noqa: D101
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)
            self.webapp_scan_timeout_sec = kwargs.get("webapp_scan_timeout_sec", 1.5)
            self.webapp_scan_max_pages = kwargs.get("webapp_scan_max_pages", 12)
            self.webapp_scan_max_seconds = kwargs.get("webapp_scan_max_seconds", 8.0)
            self.webapp_scan_username = kwargs.get("webapp_scan_username", "tester")
            self.webapp_scan_password = kwargs.get("webapp_scan_password", "secret")
            self.web_strict_rules_file = kwargs.get("web_strict_rules_file", "")
            self.cve_rules_file = kwargs.get(
                "cve_rules_file", str(ROOT / "backend" / "data" / "cve_rules.json"))

        @property
        def cve_rules_path(self) -> Path:
            return Path(self.cve_rules_file)

        @property
        def web_strict_rules_path(self) -> Path:
            base = self.web_strict_rules_file or str(
                ROOT / "backend" / "data" / "web_strict_rules.json")
            return Path(base)

    fake.Settings = Settings
    fake.get_settings = lambda: Settings()
    sys.modules["app.config"] = fake

# scanner 包的 __init__ 会连带导入数据库依赖；这里只加载需要的子模块
if "app.scanner" not in sys.modules:
    import app  # noqa: F401

    pkg = types.ModuleType("app.scanner")
    pkg.__path__ = [str(ROOT / "backend" / "app" / "scanner")]
    sys.modules["app.scanner"] = pkg

from app.scanner.cve import CveKnowledgeBase            # noqa: E402
from app.scanner.webapp import WebAppScanner           # noqa: E402


# ---------------------------------------------------------------------------
# 靶场式站点（故意不安全）
# ---------------------------------------------------------------------------
class _LabSite(BaseHTTPRequestHandler):
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

    def _authed(self):
        return "PHPSESSID=" in (self.headers.get("Cookie", "") or "")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            if self._authed():
                self._send(200, "<title>Demo Lab</title>"
                                "<a href='vulnerabilities/sqli/'>SQL Injection</a>"
                                "<a href='admin/'>Admin</a>")
            else:
                self._send(200, "<title>Demo Lab - Login</title>"
                                "<form action='/login.php' method='post'>"
                                "<input type='text' name='username'>"
                                "<input type='password' name='password'>"
                                "<input type='hidden' name='user_token' value='tok'>"
                                "</form>",
                           {"Set-Cookie": "PHPSESSID=guest; Path=/"})
        elif path == "/login.php":
            self._send(200, "<form action='/login.php' method='post'>"
                            "<input type='password' name='password'></form>")
        elif path == "/vulnerabilities/sqli/":
            self._send(200, "<title>SQL Injection</title>"
                            "<form action='' method='get'><input name='id'></form>")
        elif path == "/.env":
            self._send(200, "DB_HOST=127.0.0.1\nDB_PASSWORD=root\nAPP_KEY=base64:abc")
        elif path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n")
        elif path == "/setup.php":
            self._send(200, "<h1>Database Setup</h1><p>install / setup</p>")
        elif path == "/admin/":
            self._send(200, "<title>admin login</title>"
                            "<input type='password' name='admin_password'>")
        elif path == "/__secops_probe_404__":
            self._send(404, "Fatal error: in /var/www/html/index.php on line 8")
        else:
            self._send(404, "not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        self.rfile.read(length)
        if self.path.split("?", 1)[0] == "/login.php":
            self._send(302, "", {"Location": "/",
                                 "Set-Cookie": "PHPSESSID=abc; Path=/"})
        else:
            self._send(200, "ok")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


# ---------------------------------------------------------------------------
# 已加固站点（不应产生检查项）
# ---------------------------------------------------------------------------
class _SafeSite(BaseHTTPRequestHandler):
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
            self._send(200, "<title>Safe Site</title><a href='/about'>About</a>")
        else:
            self._send(404, "<h1>Not Found</h1>")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def _serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> int:
    failures = []
    kb = CveKnowledgeBase(ROOT / "backend" / "data" / "cve_rules.json")

    lab = _serve(_LabSite)
    try:
        scanner = WebAppScanner(Settings(), knowledge_base=kb)
        info, matches = scanner.scan("127.0.0.1", lab.server_address[1])
    finally:
        lab.shutdown()

    ids = {item.cve for item in matches}
    print("== 靶场式站点 ==")
    print("指纹：", {k: info.get(k) for k in ("title", "server", "powered_by",
                                             "logged_in", "pages_scanned", "checks")})
    for item in matches:
        print(f"  [{item.cve}] {item.severity:8s} {item.title}")
        print(f"          证据：{item.evidence}")

    expected = {"WEB-001", "WEB-002", "WEB-003", "WEB-005", "WEB-006",
                "WEB-007", "WEB-008", "WEB-009", "WEB-010", "WEB-011"}
    missing = expected - ids
    if missing:
        failures.append("缺少检查项：" + "、".join(sorted(missing)))
    if "CVE-2023-25690" not in ids:
        failures.append("Apache 2.4.20 未命中版本区间 CVE-2023-25690")
    if not info.get("logged_in"):
        failures.append("通用表单登录未成功")
    if any(not item.evidence for item in matches):
        failures.append("存在无证据的结论")

    safe = _serve(_SafeSite)
    try:
        scanner = WebAppScanner(Settings(webapp_scan_username="", webapp_scan_password=""),
                                knowledge_base=kb)
        safe_info, safe_matches = scanner.scan("127.0.0.1", safe.server_address[1])
    finally:
        safe.shutdown()

    safe_ids = {item.cve for item in safe_matches}
    print("\n== 已加固站点 ==")
    print("指纹：", {k: safe_info.get(k) for k in ("title", "server", "logged_in")})
    print("命中：", sorted(safe_ids) or "无")
    noisy = safe_ids & {"WEB-001", "WEB-002", "WEB-004", "WEB-005", "WEB-006",
                        "WEB-007", "WEB-008", "WEB-009", "WEB-010"}
    if noisy:
        failures.append("加固站点出现误报：" + "、".join(sorted(noisy)))

    print()
    if failures:
        for item in failures:
            print("[FAIL]", item)
        return 1
    print("[OK] 通用漏扫能力验证通过：靶场式漏洞全部发现，加固站点零误报")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
