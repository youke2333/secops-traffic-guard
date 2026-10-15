"""Web 应用漏扫：通用只读探测（指纹 / 配置缺陷 / 暴露面 / 演示页面）。

设计原则（对应"不能出现误报"）：

1. **先取证、后结论**：每条发现都记录 HTTP 状态码、探测 URL、命中的页面标记，人工可复核；
2. **版本未知不猜 CVE**：只有响应头里解析出版本号时才做区间匹配；
3. **不爆破、不利用**：只发 GET / OPTIONS 与一次可选登录 POST，不做注入、命令执行验证；
4. **有界扫描**：单次最多 ``webapp_scan_max_pages`` 个页面、``webapp_scan_max_seconds`` 秒，
   只跟随同主机链接，跳过登出/删除类路径与静态资源；
5. **凭据可选**：需要登录才能看到的页面由 ``WEBAPP_SCAN_USERNAME / WEBAPP_SCAN_PASSWORD``
   提供，系统不内置任何默认账号口令。

检查项（编号即落库的 vuln.cve 字段）：

======  ==========================================
WEB-001 缺少安全响应头（CSP / XFO / XCTO / Referrer-Policy / HSTS）
WEB-002 会话 Cookie 缺少安全属性（HttpOnly / Secure / SameSite）
WEB-003 服务器或框架版本信息泄露
WEB-004 目录列举开启
WEB-005 敏感文件可下载（VCS 元数据 / 环境变量 / 备份 / 配置）
WEB-006 安装或初始化脚本残留
WEB-007 危险 HTTP 方法开启（TRACE / PUT / DELETE）
WEB-008 错误页泄露路径或堆栈
WEB-009 管理后台入口暴露
WEB-010 漏洞演示/测试页面暴露（含可交互表单）
WEB-011 明文 HTTP 传输
======  ==========================================
"""

from __future__ import annotations

import http.cookiejar
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from ..config import Settings, get_settings
from .cve import CveKnowledgeBase, CveMatch

logger = logging.getLogger(__name__)

HTTP_PORTS = {80, 81, 88, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090}

MAX_RESPONSE_BYTES = 200_000
SKIP_EXTENSIONS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".css", ".js",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".pdf",
)
SKIP_PATH_WORDS = ("logout", "signout", "log-out", "delete", "remove", "destroy", "unsubscribe")

SECURITY_HEADERS: Tuple[Tuple[str, str, bool], ...] = (
    ("content-security-policy", "Content-Security-Policy", True),
    ("x-content-type-options", "X-Content-Type-Options", True),
    ("x-frame-options", "X-Frame-Options", True),
    ("referrer-policy", "Referrer-Policy", True),
    ("strict-transport-security", "Strict-Transport-Security", False),
)

# (路径, 命中标记（任一）, 级别, CVSS, 标题, 修复建议)
SENSITIVE_PATHS: Tuple[Tuple[str, Tuple[str, ...], str, float, str, str], ...] = (
    (".git/config", ("[core]", "repositoryformatversion"), "high", 7.5,
     "Git 元数据可下载（源码与历史泄露）",
     "禁止 Web 根目录暴露 .git：把仓库放在站点根之外，或在 Nginx/Apache 中显式拒绝访问。"),
    (".env", ("app_key", "db_password", "secret_key", "db_host", "database_url"), "high", 8.1,
     "环境变量文件可下载（凭据泄露）",
     "禁止访问 .env：移动到站点根之外，并立即轮换其中出现的所有口令与密钥。"),
    (".svn/entries", ("dir", "svn"), "medium", 5.3,
     "SVN 元数据可下载（源码泄露）",
     "禁止 Web 根目录暴露 .svn；发布包使用导出（export）而不是工作副本。"),
    ("phpinfo.php", ("phpinfo()", "php version"), "medium", 5.3,
     "phpinfo 调试页面暴露（泄露配置与路径）",
     "删除 phpinfo 调试文件；如需排查，改为仅在本地 CLI 中使用 php -i。"),
    ("server-status", ("server status", "apache server status"), "medium", 5.3,
     "服务状态页暴露（泄露请求与内网地址）",
     "仅允许管理网段访问 /server-status，或直接关闭状态模块的公开访问。"),
    ("web.config", ("<configuration", "system.web"), "medium", 5.3,
     "IIS 配置文件可下载",
     "禁止下载 web.config（IIS 默认已拦截，检查是否存在静态直读或备份副本）。"),
    ("backup.zip", ("pk\x03\x04",), "high", 7.5,
     "站点备份包可下载",
     "删除或移出站点根目录的备份包，并在发布流程中禁止把备份文件留在 Web 目录。"),
    ("db.sql", ("insert into", "create table", "-- mysql dump"), "high", 7.5,
     "数据库导出文件可下载",
     "删除站点根目录下的数据库导出文件，并检查是否存在同名的 .sql.gz / .bak 副本。"),
)

INSTALL_PATHS: Tuple[Tuple[str, Tuple[str, ...], str, float, str, str], ...] = (
    ("install.php", ("install", "setup"), "high", 7.3,
     "安装脚本可访问（可被重新初始化）",
     "安装完成后删除 install 目录或加访问控制，避免被重装覆盖数据。"),
    ("setup.php", ("setup", "install", "database setup"), "high", 7.3,
     "初始化/安装页面可访问（可被重置配置）",
     "安装完成后删除 setup 页面或限制来源 IP；数据库账号使用最小权限。"),
    ("install/", ("install", "setup"), "high", 7.3,
     "安装目录可访问",
     "删除安装目录，或在 Web 服务器层面对其返回 404。"),
)

ADMIN_PATHS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("admin/", ("login", "password", "admin")),
    ("administrator/", ("login", "password", "admin")),
    ("manager/html", ("tomcat", "manager")),
    ("wp-login.php", ("wordpress", "user_login")),
    ("phpmyadmin/", ("phpmyadmin", "pma_username")),
    ("adminer.php", ("adminer", "login")),
)

DEMO_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("sql injection", "SQL 注入"),
    ("sql 注入", "SQL 注入"),
    ("cross site scripting", "XSS"),
    ("xss", "XSS"),
    ("command injection", "命令注入"),
    ("命令注入", "命令注入"),
    ("file inclusion", "文件包含"),
    ("file upload", "文件上传"),
    ("brute force", "暴力破解"),
    ("csrf", "CSRF"),
)

ERROR_MARKERS = (
    "stack trace", "traceback (most recent call last)", "fatal error", "notice: undefined",
    "warning: include", "org.springframework", "at java.", "microsoft .net framework",
    "c:\\inetpub", "c:\\xampp", "/var/www", "/usr/local/apache", "on line ",
)


@dataclass
class WebProbe:
    """一次 HTTP 探测的结果（失败时 status=0 并记录 error）。"""

    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""
    set_cookies: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class _SameHostRedirect(HTTPRedirectHandler):
    """只跟随同主机重定向，避免扫描被跳转到外部地址。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):      # noqa: D401
        target, origin = urlsplit(newurl), urlsplit(req.full_url)
        if target.hostname != origin.hostname:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class WebAppScanner:
    """通用 Web 应用漏扫器：指纹 + 配置缺陷 + 暴露面，不针对任何特定应用。"""

    def __init__(self, settings: Optional[Settings] = None,
                 knowledge_base: Optional[CveKnowledgeBase] = None) -> None:
        self.settings = settings or get_settings()
        self.kb = knowledge_base
        self.timeout = float(getattr(self.settings, "webapp_scan_timeout_sec", 3.0))
        self.max_pages = int(getattr(self.settings, "webapp_scan_max_pages", 24) or 24)
        self.max_seconds = float(getattr(self.settings, "webapp_scan_max_seconds", 20.0) or 20.0)
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------------ #
    # 基础探测
    # ------------------------------------------------------------------ #
    def _opener(self, cookies: bool = False):
        # 扫描器**不走系统代理**：环境里存在 HTTP(S)_PROXY 时，urllib 会把对内网/本机目标的
        # 探测发给代理，拿回代理自己的 502 错误页，进而被当成"站点响应"判出
        # 「缺少安全响应头」「明文 HTTP」等假漏洞（实测必然复现）。
        # 漏扫的语义是"从本机直连目标"，所以显式清空代理表。
        handlers = [ProxyHandler({}), HTTPSHandler(context=self._ssl_context), _SameHostRedirect()]
        if cookies:
            handlers.append(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        return build_opener(*handlers)

    def probe(self, url: str, data: Optional[Dict[str, str]] = None,
              opener=None, method: str = "") -> WebProbe:
        """发送一次探测；任何异常都转成 status=0 的结果，不向上抛。"""
        payload = urlencode(data).encode("utf-8") if data is not None else None
        verb = method or ("POST" if payload else "GET")
        request = Request(url, data=payload, method=verb,
                          headers={"User-Agent": "SecOps-WebScanner/3.0",
                                   "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        try:
            response = (opener or self._opener()).open(request, timeout=self.timeout)
            body = response.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="ignore")
            headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
            cookies = [str(item) for item in (response.headers.get_all("Set-Cookie") or [])]
            return WebProbe(url=response.geturl(), status=int(getattr(response, "status", 200)),
                            headers=headers, body=body, set_cookies=cookies)
        except HTTPError as exc:
            try:
                body = exc.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="ignore")
            except Exception:      # pragma: no cover - 防御性
                body = ""
            headers = {str(k).lower(): str(v) for k, v in (exc.headers or {}).items()}
            cookies = [str(item) for item in ((exc.headers or {}).get_all("Set-Cookie") or [])]
            return WebProbe(url=url, status=int(exc.code or 0), headers=headers,
                            body=body, set_cookies=cookies)
        except (URLError, OSError, TimeoutError, ValueError) as exc:
            return WebProbe(url=url, status=0, error=f"{type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------ #
    # 对外入口
    # ------------------------------------------------------------------ #
    def scan(self, ip: str, port: int, scheme: str = "") -> Tuple[Dict[str, Any], List[CveMatch]]:
        """对单个 HTTP 服务做通用漏扫（供主机扫描与按 URL 扫描共用）。"""
        proto = scheme or ("https" if port in (443, 8443) else "http")
        return self._scan_site(f"{proto}://{ip}:{int(port)}/", port)

    def scan_url(self, url: str, port: Optional[int] = None) -> Tuple[Dict[str, Any], List[CveMatch]]:
        """按完整 URL 扫描（可带业务子路径，如 http://host:8080/app/）。"""
        normalized = url if "://" in url else f"http://{url}"
        parsed = urlsplit(normalized)
        resolved_port = int(parsed.port or port or (443 if parsed.scheme == "https" else 80))
        base = normalized if normalized.endswith("/") else normalized + "/"
        return self._scan_site(base, resolved_port)

    # ------------------------------------------------------------------ #
    # 扫描主流程
    # ------------------------------------------------------------------ #
    def _scan_site(self, base: str, port: int) -> Tuple[Dict[str, Any], List[CveMatch]]:
        started = time.time()
        info: Dict[str, Any] = {
            "url": base, "title": "", "server": "", "powered_by": "",
            "logged_in": False, "pages_scanned": 0, "checks": 0, "note": "",
        }
        matches: List[CveMatch] = []

        root = self.probe(base)
        if root.status == 0:
            info["note"] = f"目标不可达：{root.error or '连接失败'}"
            return info, matches
        info.update({
            # 头值可能带尾随空白（如 BaseHTTPRequestHandler 的 "nginx "），指纹要归一化后再存/展示
            "server": root.header("server").strip(),
            "powered_by": root.header("x-powered-by").strip(),
            "title": self._title(root.body),
            "status": root.status,
        })

        opener = self._opener(cookies=True)
        home = self.probe(base, opener=opener)
        logged_in, login_note = self._login(base, home, opener)
        info["logged_in"] = logged_in
        if login_note:
            info["note"] = login_note

        checks = (
            self._check_headers(root, base, port),
            self._check_cookies(home, base, port),
            self._check_version(info, port),
            self._check_plain_http(base, port),
            self._check_methods(base, port),
            self._check_error_page(base, port),
            self._check_paths(base, port, SENSITIVE_PATHS, "WEB-005", "敏感文件可下载"),
            self._check_paths(base, port, INSTALL_PATHS, "WEB-006", "安装/初始化脚本残留"),
            self._check_admin(base, port),
            self._check_listing(base, port),
        )
        matches.extend([item for item in checks if item is not None])
        matches.extend(self._version_matches(info, port))

        pages, demo = self._crawl(base, opener, started)
        info["pages_scanned"] = pages
        if demo is not None:
            matches.append(demo)
        info["checks"] = len(matches)
        info["duration_sec"] = round(time.time() - started, 2)
        if not info["note"]:
            info["note"] = ("已按通用检查项扫描 %d 个页面（只读探测，结论均带 HTTP 证据）" % pages)
        return info, matches

    # ------------------------------------------------------------------ #
    # 单项检查
    # ------------------------------------------------------------------ #
    def _finding(self, finding_id: str, title: str, severity: str, cvss: float,
                 port: int, evidence: str, recommendation: str,
                 references: Sequence[str] = ()) -> CveMatch:
        return CveMatch(
            cve=finding_id, title=title, severity=severity, cvss=cvss,
            product="Web 应用", version="", port=port,
            recommendation=recommendation,
            fixed_version="按建议加固",
            evidence=evidence, references=list(references),
            source="web",
        )

    def _check_headers(self, root: WebProbe, base: str, port: int) -> Optional[CveMatch]:
        """WEB-001：缺少安全响应头（HTTPS 站点额外要求 HSTS）。"""
        is_https = base.lower().startswith("https://")
        missing = [label for header, label, always in SECURITY_HEADERS
                   if (always or is_https) and not root.header(header)]
        if not missing:
            return None
        return self._finding(
            "WEB-001", "缺少安全响应头（" + "、".join(missing) + "）", "medium", 5.3, port,
            f"GET {base} 返回 HTTP {root.status}，响应头中未出现：{'、'.join(missing)}",
            "按站点类型补齐安全响应头：至少设置 X-Content-Type-Options: nosniff、"
            "X-Frame-Options: DENY|SAMEORIGIN、Referrer-Policy；HTTPS 站点补 HSTS；"
            "CSP 建议先用 Report-Only 观察再收紧。",
            references=["https://owasp.org/www-project-secure-headers/"],
        )

    def _check_cookies(self, home: WebProbe, base: str, port: int) -> Optional[CveMatch]:
        """WEB-002：会话 Cookie 缺少 HttpOnly/Secure/SameSite。"""
        if not home.set_cookies:
            return None
        is_https = base.lower().startswith("https://")
        problems: List[str] = []
        for raw in home.set_cookies:
            name = raw.split("=", 1)[0].strip() or "cookie"
            lower = raw.lower()
            flags = []
            if "httponly" not in lower:
                flags.append("HttpOnly")
            if is_https and "secure" not in lower:
                flags.append("Secure")
            if "samesite" not in lower:
                flags.append("SameSite")
            if flags:
                problems.append(f"{name} 缺少 {'/'.join(flags)}")
        if not problems:
            return None
        return self._finding(
            "WEB-002", "会话 Cookie 缺少安全属性", "medium", 4.3, port,
            f"GET {base} 的 Set-Cookie 中：{'；'.join(problems[:5])}",
            "为会话 Cookie 加 HttpOnly、Secure（HTTPS 站点）与 SameSite=Lax/Strict，"
            "避免被脚本读取或在跨站请求中自动携带。",
            references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
        )

    def _check_version(self, info: Dict[str, Any], port: int) -> Optional[CveMatch]:
        """WEB-003：响应头泄露服务器/框架版本。"""
        server = info.get("server", "") or ""
        powered = info.get("powered_by", "") or ""
        leaked = [text for text in (server, powered) if re.search(r"\d+\.\d+", text or "")]
        if not leaked:
            return None
        return self._finding(
            "WEB-003", "服务器或框架版本信息泄露", "low", 3.1, port,
            f"响应头暴露版本：{'；'.join(leaked)}",
            "隐藏或泛化版本号（Nginx: server_tokens off；Apache: ServerTokens Prod 与 "
            "ServerSignature Off；PHP: expose_php = Off），减少被针对性利用的可能。",
        )

    def _check_plain_http(self, base: str, port: int) -> Optional[CveMatch]:
        """WEB-011：明文 HTTP 传输。"""
        if not base.lower().startswith("http://"):
            return None
        return self._finding(
            "WEB-011", "站点使用明文 HTTP 传输", "low", 3.7, port,
            f"访问地址为 {base}，未启用 TLS",
            "为业务启用 HTTPS 并配置 HTTP 301 跳转到 HTTPS；管理后台与登录接口优先落地。",
        )

    def _check_methods(self, base: str, port: int) -> Optional[CveMatch]:
        """WEB-007：OPTIONS 暴露 TRACE/PUT/DELETE 等危险方法。"""
        probe = self.probe(base, method="OPTIONS")
        allow = (probe.header("allow") or "").upper()
        risky = [item for item in ("TRACE", "PUT", "DELETE", "CONNECT") if item in allow]
        if not risky:
            return None
        return self._finding(
            "WEB-007", "危险 HTTP 方法开启（" + "、".join(risky) + "）", "medium", 5.3, port,
            f"OPTIONS {base} 返回 HTTP {probe.status}，Allow: {allow}",
            "在 Web 服务器/网关层关闭不需要的方法（尤其 TRACE），只保留 GET/HEAD/POST 等必要方法。",
        )

    def _check_error_page(self, base: str, port: int) -> Optional[CveMatch]:
        """WEB-008：错误页泄露绝对路径或堆栈。"""
        probe = self.probe(urljoin(base, "__secops_probe_404__"))
        if probe.status in (0, 200) or not probe.body:
            return None
        body = (probe.body or "").lower()
        hit = next((marker for marker in ERROR_MARKERS if marker in body), "")
        if not hit:
            return None
        return self._finding(
            "WEB-008", "错误页泄露路径或堆栈信息", "low", 3.1, port,
            f"GET {probe.url} 返回 HTTP {probe.status}，页面命中「{hit}」",
            "关闭生产环境详细报错（PHP: display_errors=Off；Java: 自定义错误页；"
            ".NET: customErrors=On），错误详情只写服务端日志。",
        )

    def _check_paths(self, base: str, port: int,
                     table: Sequence[Tuple[str, Tuple[str, ...], str, float, str, str]],
                     finding_id: str, fallback_title: str) -> Optional[CveMatch]:
        """WEB-005 / WEB-006：敏感文件与安装脚本（同类聚合成一条，证据列出全部命中）。"""
        hits: List[Tuple[str, str, str, float, str, str]] = []
        for path, markers, severity, cvss, title, recommendation in table:
            probe = self.probe(urljoin(base, path))
            if probe.status not in (200, 206) or not probe.body:
                continue
            body = probe.body.lower()
            marker = next((item for item in markers if item in body), "")
            if not marker:
                continue
            hits.append((path, marker, severity, cvss, title, recommendation))
        if not hits:
            return None
        title = hits[0][4] if len(hits) == 1 else fallback_title
        severity = "high" if any(item[2] == "high" for item in hits) else hits[0][2]
        cvss = max(item[3] for item in hits)
        evidence = "；".join(
            f"GET {urljoin(base, path)} → 200，命中标记「{marker}」"
            for path, marker, _severity, _cvss, _title, _rec in hits[:6]
        )
        recommendation = "；".join(dict.fromkeys(item[5] for item in hits))
        return self._finding(finding_id, title or fallback_title, severity, cvss, port,
                             evidence, recommendation)

    def _check_admin(self, base: str, port: int) -> Optional[CveMatch]:
        """WEB-009：管理后台入口暴露（只报入口存在，不判断弱口令）。"""
        hits: List[str] = []
        for path, markers in ADMIN_PATHS:
            probe = self.probe(urljoin(base, path))
            if probe.status not in (200, 401, 403):
                continue
            body = (probe.body or "").lower()
            if probe.status == 200 and not any(marker in body for marker in markers):
                continue
            hits.append(f"{urljoin(base, path)}（HTTP {probe.status}）")
        if not hits:
            return None
        return self._finding(
            "WEB-009", "管理后台入口对外暴露", "medium", 5.3, port,
            "可访问的管理入口：" + "；".join(hits[:6]),
            "管理入口限制来源网段或接入 VPN/堡垒机，并启用多因素认证；"
            "非必要不在公网暴露后台路径。",
        )

    def _check_listing(self, base: str, port: int) -> Optional[CveMatch]:
        """WEB-004：目录列举开启。"""
        probe = self.probe(base)
        body = (probe.body or "").lower()
        if probe.status != 200 or "index of /" not in body or "parent directory" not in body:
            return None
        return self._finding(
            "WEB-004", "目录列举开启", "medium", 5.3, port,
            f"GET {base} 返回 HTTP 200，页面包含「Index of /」与「Parent Directory」",
            "关闭目录自动索引（Nginx: autoindex off；Apache: Options -Indexes），"
            "并清理不需要对外提供的目录。",
        )

    # ------------------------------------------------------------------ #
    # 登录与爬取
    # ------------------------------------------------------------------ #
    def _login(self, base: str, home: WebProbe, opener) -> Tuple[bool, str]:
        """通用表单登录：定位含密码框的表单并提交一次（凭据来自配置）。"""
        username = str(getattr(self.settings, "webapp_scan_username", "") or "")
        password = str(getattr(self.settings, "webapp_scan_password", "") or "")
        form = self._find_login_form(home.body or "", base)
        if form is None:
            return False, ""
        if not username or not password:
            return False, ("检测到登录表单；未配置 WEBAPP_SCAN_USERNAME/PASSWORD，"
                           "跳过登录后才可见的页面")
        data = dict(form["hidden"])
        data[form["user_field"]] = username
        data[form["pass_field"]] = password
        self.probe(form["action"], data=data, opener=opener)
        after = self.probe(base, opener=opener)
        logged_in = self._find_login_form(after.body or "", base) is None
        return logged_in, ("" if logged_in else "登录未成功：请检查 WEBAPP_SCAN_USERNAME/PASSWORD")

    def _find_login_form(self, body: str, base: str) -> Optional[Dict[str, Any]]:
        """在 HTML 中找第一个带密码框的表单，返回 action 与字段名。"""
        if not body or "<form" not in body.lower():
            return None
        for match in re.finditer(r"<form\b[^>]*>(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
            block = match.group(0)
            if not re.search(r"type\s*=\s*['\"]?password", block, re.IGNORECASE):
                continue
            action_match = re.search(r"action\s*=\s*['\"]([^'\"]*)", block, re.IGNORECASE)
            action = urljoin(base, (action_match.group(1) if action_match else "") or "")
            pass_field = ""
            user_field = ""
            hidden: Dict[str, str] = {}
            for input_match in re.finditer(r"<input\b[^>]*>", block, re.IGNORECASE):
                tag = input_match.group(0)
                name_match = re.search(r"name\s*=\s*['\"]([^'\"]+)", tag, re.IGNORECASE)
                if not name_match:
                    continue
                name = name_match.group(1)
                kind_match = re.search(r"type\s*=\s*['\"]?([a-zA-Z]+)", tag, re.IGNORECASE)
                kind = (kind_match.group(1) if kind_match else "text").lower()
                if kind == "password" and not pass_field:
                    pass_field = name
                elif kind in ("text", "email") and not user_field:
                    user_field = name
                elif kind == "hidden":
                    value_match = re.search(r"value\s*=\s*['\"]([^'\"]*)", tag, re.IGNORECASE)
                    hidden[name] = value_match.group(1) if value_match else ""
            if not pass_field:
                continue
            return {"action": action, "user_field": user_field or "username",
                    "pass_field": pass_field, "hidden": hidden}
        return None

    def _crawl(self, base: str, opener, started: float
               ) -> Tuple[int, Optional[CveMatch]]:
        """同主机有界爬取 + 漏洞演示页检查（WEB-010）。"""
        queue: List[Tuple[str, int]] = [(base, 0)]
        seen = {base}
        pages = 0
        host = urlsplit(base).hostname
        demo_hits: List[str] = []

        while queue and pages < self.max_pages and (time.time() - started) < self.max_seconds:
            url, depth = queue.pop(0)
            probe = self.probe(url, opener=opener)
            pages += 1
            if probe.status != 200:
                continue
            hit = self._demo_page(probe, url)
            if hit and len(demo_hits) < 6:
                demo_hits.append(hit)
            if depth >= 2:
                continue
            for link in self._links(probe.body or "", url):
                if link in seen or len(seen) >= self.max_pages * 2:
                    continue
                if urlsplit(link).hostname != host:
                    continue
                seen.add(link)
                queue.append((link, depth + 1))

        if not demo_hits:
            return pages, None
        return pages, self._demo_finding(demo_hits, base)

    @staticmethod
    def _links(body: str, base: str) -> List[str]:
        """提取可爬取的站内链接（过滤静态资源与登出类路径）。"""
        links: List[str] = []
        for match in re.finditer(r"href\s*=\s*['\"]([^'\"#]+)", body or "", re.IGNORECASE):
            raw = match.group(1).strip()
            if not raw or raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(base, raw)
            parsed = urlsplit(absolute)
            if parsed.scheme not in ("http", "https"):
                continue
            path = (parsed.path or "/").lower()
            if path.endswith(SKIP_EXTENSIONS) or any(word in path for word in SKIP_PATH_WORDS):
                continue
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean += "?" + parsed.query
            if clean not in links:
                links.append(clean)
        return links

    @staticmethod
    def _demo_page(probe: WebProbe, url: str) -> str:
        """页面是否为"漏洞演示/测试页"：同时命中漏洞类别词与可交互表单。"""
        body = (probe.body or "").lower()
        if "<form" not in body and "<input" not in body:
            return ""
        for keyword, label in DEMO_KEYWORDS:
            if keyword in body:
                return f"{url}（{label}）"
        return ""

    def _demo_finding(self, hits: Sequence[str], base: str) -> CveMatch:
        port = int(urlsplit(base).port or (443 if base.startswith("https") else 80))
        return self._finding(
            "WEB-010", "暴露可交互的漏洞演示/测试页面", "high", 7.5, port,
            "页面同时包含漏洞类别关键词与可交互表单：" + "；".join(list(hits)[:6]),
            "确认这些页面是否为授权测试环境：生产环境应移除演示/测试页面，"
            "或通过访问控制限制来源；确需保留时禁止接入真实数据并隔离网络。",
            references=["https://owasp.org/www-project-top-ten/"],
        )

    # ------------------------------------------------------------------ #
    # Apache / PHP / Nginx 版本 → CVE
    # ------------------------------------------------------------------ #
    def _version_matches(self, info: Dict[str, Any], port: int) -> List[CveMatch]:
        """仅当响应头解析出版本号时才做 CVE 匹配（版本未知不猜，避免误报）。"""
        if self.kb is None:
            return []
        matches: List[CveMatch] = []
        server = info.get("server", "") or ""
        powered = info.get("powered_by", "") or ""
        for pattern, product, banner in (
            (r"apache/([0-9][0-9.]*)", "Apache httpd", server),
            (r"nginx/([0-9][0-9.]*)", "nginx", server),
            (r"php/([0-9][0-9.]*)", "PHP", powered),
        ):
            found = re.search(pattern, banner or "", re.IGNORECASE)
            if found:
                matches.extend(self.kb.match(product=product, version=found.group(1),
                                             port=port, banner=banner, service="http"))
        return matches

    @staticmethod
    def _title(body: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", match.group(1)).strip()[:120] if match else ""
