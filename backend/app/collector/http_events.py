"""HTTP 请求事件源：为 Web 攻击检测提供「请求级」输入。

三种来源（由 ``WEB_DETECT_SOURCE`` 选择，默认 auto）：

1. ``log``  —— tail nginx/Apache **combined** 访问日志（生产常用、零侵入；只能拿到 URL/UA/Referer，
   看不到请求体，因此基于 body 的规则（存储型 XSS、上传载荷等）需改用 api 投递）；
2. ``demo`` —— 业务系统仿真请求（无 Web 日志/无流量镜像时的演示联调，全链路可见）；
3. ``api``  —— 由 WAF/反向代理/业务系统通过 ``POST /web/requests`` 主动投递（可见完整请求体）。

``auto``：配置了 ``WEB_LOG_PATH`` 走 log，否则走 demo。所有来源统一回调
``on_request(WebRequestEvent)``，由采集服务聚合后送 ``WebAttackDetector`` 检测。

注意：仿真剧本里的危险载荷（Webshell / XXE）用字符串拼接构造，避免源码本身携带
可执行载荷的字面量（安全工具的代码库不应成为静态扫描的误报源）。
"""

from __future__ import annotations

import logging
import random
import re
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ..config import Settings, get_settings
from ..detection.web_knowledge import WebRequestEvent

logger = logging.getLogger(__name__)

RequestCallback = Callable[[WebRequestEvent], None]

# nginx/Apache 访问日志格式：同时支持 combined（%h %l %u）与 Apache vhost_combined
# （%v:%p %h %l %u，Ubuntu 默认的 other_vhosts_access.log 即此格式）。
LOG_PATTERN = re.compile(
    r'^(?:(?P<vhost>[^\s"]+:\d+)\s+)?'
    r'(?P<src>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Za-z]+)\s+(?P<target>\S+?)(?:\s+(?P<proto>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

SERVERS = ["192.168.1.30", "192.168.1.40", "192.168.1.50"]
ATTACKERS = ["203.0.113.66", "198.51.100.23", "45.33.32.156", "91.121.87.5", "185.199.108.153"]
NORMAL_PATHS = [
    ("GET", "/index.php", "", ""),
    ("GET", "/static/js/app.js", "", ""),
    ("GET", "/api/v1/metrics/trend", "window_sec=120", ""),
    ("GET", "/images/logo.png", "", ""),
    ("POST", "/api/v1/login", "", "username=ops&password=******&remember=1"),
    ("GET", "/api/v1/assets", "limit=20", ""),
]

# 危险载荷片段（拼接构造，源码中不出现完整可执行载荷）
PHP_TAG_OPEN = "<" + "?php"
PHP_TAG_CLOSE = "?" + ">"
XML_DECL = "<" + "?xml version=\"1.0\"?"


def php_payload(code: str) -> str:
    """拼出仿真用的 PHP 木马载荷（仅用于演示/测试场景）。"""
    return PHP_TAG_OPEN + " " + code + " " + PHP_TAG_CLOSE


def xxe_payload() -> str:
    """拼出仿真用的 XXE 载荷。"""
    return (XML_DECL + "><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
            "<root>&xxe;</root>")


def parse_access_log_line(line: str, now: Optional[float] = None) -> Optional[Dict[str, object]]:
    """解析一行 combined 访问日志，返回可构造事件的关键字段；无法解析时返回 None。"""
    match = LOG_PATTERN.match((line or "").strip())
    if not match:
        return None
    target = match.group("target")
    if target.startswith("http://") or target.startswith("https://"):
        parts = target.split("//", 1)
        target = "/" + parts[1].split("/", 1)[1] if len(parts) == 2 and "/" in parts[1] else "/"
    path, _, query = target.partition("?")
    try:
        status = int(match.group("status"))
    except (TypeError, ValueError):
        status = 0
    headers: Dict[str, str] = {}
    user_agent = (match.group("ua") or "").strip()
    referer = (match.group("referer") or "").strip()
    if user_agent and user_agent != "-":
        headers["user-agent"] = user_agent
    if referer and referer != "-":
        headers["referer"] = referer
    result: Dict[str, object] = {
        "ts": float(now or time.time()),
        "src_ip": match.group("src").split("%")[0],
        "method": match.group("method").upper(),
        "path": path or "/",
        "query": query,
        "status": status,
        "headers": headers,
        "body": "",
    }
    # vhost_combined 的 "%v:%p" 前缀顺便给出目的端口（8080 靶场可从日志直接取到）
    vhost = match.group("vhost") or ""
    if vhost:
        _, _, port_text = vhost.rpartition(":")
        if port_text.isdigit() and 0 < int(port_text) <= 65535:
            result["dst_port"] = int(port_text)
    return result


class WebRequestSource(ABC):
    """HTTP 请求事件源基类（与流量采集源 TrafficSource 同构，便于统一编排）。"""

    name = "base"
    description = ""

    def __init__(self) -> None:
        self._running = False

    @abstractmethod
    def start(self, on_request: RequestCallback) -> None:
        """启动事件源，每个请求回调一次 ``on_request``。"""

    @abstractmethod
    def stop(self) -> None:
        """停止事件源（必须幂等）。"""

    @property
    def running(self) -> bool:
        return self._running


class WebApiSource(WebRequestSource):
    """api 模式：不产生事件，只等外部通过 REST 投递（见 routes_web.py）。"""

    name = "api"
    description = "由 WAF/代理通过 POST /web/requests 主动投递请求"

    def start(self, on_request: RequestCallback) -> None:
        self._running = True
        logger.info("Web 攻击检测以 api 模式运行：等待外部投递请求事件")

    def stop(self) -> None:
        self._running = False


class AccessLogSource(WebRequestSource):
    """tail 访问日志（combined 格式）：只读、增量读取，启动时从文件末尾开始避免历史刷屏。"""

    name = "log"
    description = "tail nginx/Apache combined 访问日志"

    def __init__(self, path: str, poll_sec: float = 1.0, from_end: bool = True,
                 default_dst_ip: str = "", default_dst_port: int = 8080) -> None:
        super().__init__()
        self.path = Path(path)
        self.poll_sec = max(0.2, float(poll_sec))
        self.from_end = from_end
        self.default_dst_ip = default_dst_ip
        self.default_dst_port = int(default_dst_port or 8080)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.parsed_lines = 0
        self.skipped_lines = 0

    def start(self, on_request: RequestCallback) -> None:
        if not self.path.exists():
            raise FileNotFoundError(f"访问日志不存在: {self.path}")
        # 启动时先做一次可读性探测：/var/log/apache2 默认 640 root:adm，
        # 非 root/非 adm 组会读不到，这里快速失败并给出可操作的提示。
        try:
            with self.path.open("rb") as probe:
                probe.read(1)
        except OSError as exc:
            raise PermissionError(
                f"无权读取访问日志 {self.path}（{exc}）；请用 root 运行，"
                f"或执行 sudo usermod -aG adm $USER 后重新登录"
            ) from exc
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(on_request,),
                                        name="web-log-tail", daemon=True)
        self._thread.start()
        self._running = True
        logger.info("已开始 tail Web 访问日志: %s", self.path)

    def _loop(self, on_request: RequestCallback) -> None:
        try:
            handle = self.path.open("r", encoding="utf-8", errors="ignore")
        except OSError:
            logger.exception("打开 Web 访问日志失败（tail 线程退出）: %s", self.path)
            self._running = False
            return
        try:
            if self.from_end:
                handle.seek(0, 2)
            while not self._stop.is_set():
                line = handle.readline()
                if not line:
                    self._stop.wait(self.poll_sec)
                    continue
                parsed = parse_access_log_line(line)
                if parsed is None:
                    self.skipped_lines += 1
                    continue
                self.parsed_lines += 1
                parsed.setdefault("dst_ip", self.default_dst_ip)
                parsed.setdefault("dst_port", self.default_dst_port)
                event = WebRequestEvent.from_dict({**parsed, "source": "log",
                                                   "iface": str(self.path)})
                try:
                    on_request(event)
                except Exception:
                    logger.exception("处理访问日志事件失败")
        except Exception:
            logger.exception("Web 访问日志 tail 异常")
        finally:
            handle.close()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self._running = False


# --------------------------------------------------------------------------- #
# 仿真 Web 请求（普通业务系统路径，覆盖知识库全部大类）
# --------------------------------------------------------------------------- #
WEB_SCENARIOS: List[Dict[str, object]] = [
    {
        "name": "sql_injection", "method": "GET", "path": "/product/detail",
        "query": "id=1%27+OR+%271%27%3D%271&Submit=Submit", "status": 200, "repeat": 1,
        "ua": "sqlmap/1.7.2#stable (https://sqlmap.org)",
    },
    {
        "name": "sql_injection_blind", "method": "GET", "path": "/product/list",
        "query": "id=1%27+AND+SLEEP(5)--+-&Submit=Submit", "status": 200, "repeat": 2,
        "ua": "sqlmap/1.7.2#stable (https://sqlmap.org)",
    },
    {
        "name": "xss_reflected", "method": "GET", "path": "/search",
        "query": "name=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", "status": 200, "repeat": 1,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    },
    {
        "name": "xss_stored", "method": "POST", "path": "/guestbook",
        "body": "name=guest&message=%3Cscript%3Ealert('stored')%3C%2Fscript%3E&submit=Sign+Guestbook",
        "content_type": "application/x-www-form-urlencoded", "status": 302, "repeat": 1,
        "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    },
    {
        "name": "command_injection", "method": "POST", "path": "/tools/ping",
        "body": "ip=127.0.0.1%3Bcat+%2Fetc%2Fpasswd&Submit=Submit",
        "content_type": "application/x-www-form-urlencoded", "status": 200, "repeat": 1,
        "ua": "curl/8.4.0",
    },
    {
        "name": "file_inclusion", "method": "GET", "path": "/help/view",
        "query": "page=..%2F..%2F..%2F..%2Fetc%2Fpasswd", "status": 200, "repeat": 1,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    },
    {
        "name": "file_upload", "method": "POST", "path": "/upload/avatar",
        "body": ("--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n"
                 "Content-Type: image/jpeg\r\n\r\n" + php_payload("system($_POST['cmd']);")
                 + "\r\n--x--\r\nupload=Upload"),
        "content_type": "multipart/form-data; boundary=x", "status": 200, "repeat": 1,
        "ua": "python-requests/2.31.0",
    },
    {
        "name": "brute_force", "method": "POST", "path": "/login",
        "body": "username=admin&password=123456&Login=Login",
        "content_type": "application/x-www-form-urlencoded", "status": 200, "repeat": 12,
        "ua": "hydra/9.5",
    },
    {
        "name": "csrf", "method": "POST", "path": "/account/password",
        "body": "password_new=12345&password_conf=12345&Change=Change",
        "content_type": "application/x-www-form-urlencoded", "status": 302, "repeat": 4,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    },
    {
        "name": "insecure_captcha", "method": "POST", "path": "/account/password",
        "body": "step=2&password_new=12345&password_conf=12345&Change=Change&recaptcha_response_field=",
        "content_type": "application/x-www-form-urlencoded", "status": 302, "repeat": 9,
        "ua": "python-requests/2.31.0",
    },
    {
        "name": "path_traversal", "method": "GET", "path": "/download.php",
        "query": "file=..%2F..%2F..%2F..%2Fetc%2Fshadow", "status": 200, "repeat": 1,
        "ua": "Wget/1.21.3",
    },
    {
        "name": "ssrf", "method": "GET", "path": "/api/fetch",
        "query": "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", "status": 200, "repeat": 2,
        "ua": "curl/8.4.0",
    },
    {
        "name": "webshell", "method": "GET", "path": "/upload/shell.php",
        "query": "cmd=whoami", "status": 200, "repeat": 1,
        "ua": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    },
    {
        "name": "xxe", "method": "POST", "path": "/api/xml/import", "body": xxe_payload(),
        "content_type": "application/xml", "status": 500, "repeat": 1,
        "ua": "python-requests/2.31.0",
    },
    {
        "name": "ssti", "method": "GET", "path": "/api/render",
        "query": ("name=%7B%7B7*7%7D%7D%7B%7Bconfig.__class__.__init__.__globals__"
                  "%5B'os'%5D.popen('id').read()%7D%7D"),
        "status": 200, "repeat": 1, "ua": "curl/8.4.0",
    },
    {
        "name": "ldap_nosql_injection", "method": "GET", "path": "/api/login",
        "query": "user=*)(uid=*))(|(uid=*&password=x&username[$ne]=x", "status": 500, "repeat": 1,
        "ua": "curl/8.4.0",
    },
    {
        "name": "crlf_injection", "method": "GET", "path": "/redirect",
        "query": "next=%0d%0aSet-Cookie:role=admin", "status": 302, "repeat": 1,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    },
    {
        "name": "scanner_fingerprint", "method": "GET", "path": "/login",
        "query": "continue=Login", "status": 200, "repeat": 1,
        "ua": "Nikto/2.5.0 (Unix)",
    },
    {
        "name": "recon_scan", "method": "GET", "path": "/.env",
        "query": "", "status": 404, "repeat": 1,
        "ua": "curl/8.4.0",
    },
    {
        "name": "deserialization", "method": "POST", "path": "/api/import",
        "body": "data=rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcAAAAAAAAAABAwAAeHB4",
        "content_type": "application/x-www-form-urlencoded", "status": 500, "repeat": 1,
        "ua": "python-requests/2.31.0",
    },
    {
        "name": "api_abuse", "method": "POST", "path": "/api/users/42",
        "body": "role=admin&is_admin=true",
        "content_type": "application/x-www-form-urlencoded", "status": 200, "repeat": 1,
        "ua": "python-requests/2.31.0",
    }
]


class DemoWebSource(WebRequestSource):
    """仿真 Web 请求源：按剧本轮转生成「正常 + 攻击」请求，保证无日志环境下也能演示全链路。"""

    name = "demo"
    description = "业务系统仿真 Web 请求（覆盖知识库全部攻击大类）"

    def __init__(self, interval_sec: float = 2.5, normal_ratio: float = 0.5) -> None:
        super().__init__()
        self.interval_sec = max(0.2, float(interval_sec))
        self.normal_ratio = min(0.9, max(0.0, float(normal_ratio)))
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._index = 0
        self.emitted = 0

    def start(self, on_request: RequestCallback) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, args=(on_request,),
                                        name="web-demo", daemon=True)
        self._thread.start()
        self._running = True
        logger.info("Web 攻击检测仿真源已启动：%d 个剧本，间隔 %.1fs",
                    len(WEB_SCENARIOS), self.interval_sec)

    def _loop(self, on_request: RequestCallback) -> None:
        while not self._stop.is_set():
            try:
                for event in self.next_events():
                    on_request(event)
                self._index += 1
            except Exception:
                logger.exception("仿真 Web 请求生成异常")
            self._stop.wait(self.interval_sec)

    def next_events(self) -> List[WebRequestEvent]:
        """生成一批事件：正常请求按比例穿插，攻击剧本顺序轮转（阈值类剧本一次发多条）。"""
        now = time.time()
        events: List[WebRequestEvent] = []
        if random.random() < self.normal_ratio:
            method, path, query, body = random.choice(NORMAL_PATHS)
            events.append(WebRequestEvent.from_dict({
                "ts": now, "src_ip": random.choice(["10.20.0.11", "10.20.0.12", "10.20.0.21"]),
                "dst_ip": random.choice(SERVERS), "dst_port": random.choice([80, 443, 8080]),
                "method": method, "path": path, "query": query, "body": body,
                "status": 200, "source": "demo",
                "headers": {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                            "referer": "http://192.168.1.30/"},
            }))

        scenario = WEB_SCENARIOS[self._index % len(WEB_SCENARIOS)]
        repeat = int(scenario.get("repeat") or 1)
        for step in range(repeat):
            headers: Dict[str, str] = {"user-agent": str(scenario.get("ua") or "Mozilla/5.0")}
            if scenario["name"] != "csrf":      # CSRF 剧本故意不带 Referer/Origin（模拟跨站伪造）
                headers["referer"] = f"http://{random.choice(SERVERS)}/"
            headers["content-type"] = str(scenario.get("content_type")
                                          or "application/x-www-form-urlencoded")
            events.append(WebRequestEvent.from_dict({
                "ts": now + step * 0.4,
                "src_ip": ATTACKERS[self._index % len(ATTACKERS)],
                "dst_ip": SERVERS[self._index % len(SERVERS)],
                "dst_port": 80, "method": scenario["method"],
                "path": scenario["path"], "query": scenario.get("query") or "",
                "body": scenario.get("body") or "", "status": scenario.get("status") or 0,
                "headers": headers, "source": "demo",
            }))
        self.emitted += len(events)
        return events

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self._running = False


def build_web_source(settings: Optional[Settings] = None) -> Optional[WebRequestSource]:
    """按 ``WEB_DETECT_SOURCE`` 构建 Web 请求源；None 表示仅走 API 投递/整体关闭。"""
    cfg = settings or get_settings()
    if not cfg.web_detect_enabled:
        return None
    mode = (cfg.web_detect_source or "auto").lower()
    if mode == "off":
        return None
    if mode == "api":
        return WebApiSource()
    if mode == "log":
        return AccessLogSource(cfg.web_log_path, cfg.web_log_poll_sec,
                               default_dst_ip=cfg.web_default_dst_ip,
                               default_dst_port=cfg.web_default_dst_port)
    if mode == "demo":
        return DemoWebSource(cfg.web_demo_interval_sec)
    # auto：有访问日志就 tail 日志，否则用仿真源（保证演示环境全链路可跑）
    if cfg.web_log_path and Path(cfg.web_log_path).exists():
        return AccessLogSource(cfg.web_log_path, cfg.web_log_poll_sec,
                               default_dst_ip=cfg.web_default_dst_ip,
                               default_dst_port=cfg.web_default_dst_port)
    logger.info("未配置 WEB_LOG_PATH，Web 攻击检测使用仿真请求源（demo）")
    return DemoWebSource(cfg.web_demo_interval_sec)
