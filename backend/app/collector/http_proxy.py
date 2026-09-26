"""HTTP 高保真接入代理（8080 → 业务站点 8081），把**完整请求（含 POST body）**投递给检测系统。

为什么需要它：Web 服务器访问日志只有请求行，没有 POST body；命令注入、文件上传、
反序列化等攻击载荷都在 body 里，仅靠日志会漏检。代理在转发的同时把请求投递到
``POST /api/v1/web/requests``，检测链路即可拿到完整载荷。

部署拓扑：

    业务客户端 → 本代理 :8080 → 业务站点 :8081
                        └─ 异步投递 → 检测系统 :8000/api/v1/web/requests（source=api）

安全边界：投递只包含检测所需字段（方法/路径/查询/body/UA/Referer/Content-Type/Cookie），
本地回环内传输，不落盘；代理本身不做任何改写，业务响应原样返回。
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

logger = logging.getLogger("secops.http_proxy")

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
}
FORWARD_HEADERS = {"user-agent", "referer", "content-type", "cookie", "origin", "accept"}
MAX_BODY_BYTES = 2 * 1024 * 1024      # 靶场单请求上限，避免超大 body 占用内存

# ---- 响应采集（v6.1）：仅文本类响应保留回显，用于呈现上传路径 / SQLi 拖库 / 命令回显 ----
RESPONSE_TEXT_TYPES = ("text/html", "application/json", "text/plain")
MAX_RESPONSE_BODY_BYTES = 16 * 1024   # 响应体采集截断上限（约 8–16KB 区间取上限）
MAX_RESPONSE_HEAD_BYTES = 8 * 1024    # 响应头采集截断上限

# 响应头中的敏感字段：保留键名，值脱敏（Set-Cookie 里的会话 ID 不落库）
MASKED_RESPONSE_HEADERS = {"set-cookie", "cookie", "authorization",
                           "proxy-authorization", "www-authenticate"}


def mask_header_value(name: str, value: str) -> str:
    """敏感响应头值脱敏：保留可读的结构（首段键名），隐藏会话/凭证内容。"""
    if str(name or "").lower() in MASKED_RESPONSE_HEADERS:
        first = str(value or "").split(";", 1)[0]
        key = first.split("=", 1)[0] if "=" in first else first
        return f"{key}=[已脱敏]" if key else "[已脱敏]"
    return str(value or "")


def build_response_snapshot(status: int, headers, body: bytes) -> Dict[str, str]:
    """把上游响应转成可落库的 (head, body) 文本快照。

    * 仅当 Content-Type 属于文本类（html/json/纯文本）时采集 body，二进制一律丢弃；
    * body 截断至 16KB，head 截断至 8KB（脱敏后）；
    * 任何失败都不影响代理转发（调用方需兜底空串）。
    """
    try:
        head_lines = [f"HTTP/1.1 {int(status or 0)}"]
        content_type = ""
        for name, value in headers or []:
            lowered = str(name or "").lower()
            if lowered in HOP_BY_HOP or lowered == "content-length":
                continue
            if lowered == "content-type":
                content_type = str(value or "")
            head_lines.append(f"{name}: {mask_header_value(name, value)}")
        head = "\n".join(head_lines)
        lowered_ct = content_type.lower()
        if any(kind in lowered_ct for kind in RESPONSE_TEXT_TYPES):
            text = (body or b"").decode("utf-8", errors="ignore")
            if len(text.encode("utf-8", errors="ignore")) > MAX_RESPONSE_BODY_BYTES:
                text = text.encode("utf-8", errors="ignore")[:MAX_RESPONSE_BODY_BYTES] \
                    .decode("utf-8", errors="ignore") + "\n…[已截断]"
        else:
            text = ""
        if len(head.encode("utf-8", errors="ignore")) > MAX_RESPONSE_HEAD_BYTES:
            head = head.encode("utf-8", errors="ignore")[:MAX_RESPONSE_HEAD_BYTES] \
                .decode("utf-8", errors="ignore") + "\n…[已截断]"
        return {"head": head, "body": text}
    except Exception:                     # noqa: BLE001 - 采集失败不影响转发
        return {"head": "", "body": ""}


def build_event_payload(method: str, target: str, headers: Dict[str, str], body: bytes,
                        src_ip: str, dst_ip: str, dst_port: int, status: int,
                        now: Optional[float] = None, src_port: int = 0,
                        response: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """把一次代理请求转成 `POST /web/requests` 的请求体（仅结构化字段）。"""
    parsed = urlsplit(target or "/")
    if parsed.scheme:
        path, query = parsed.path or "/", parsed.query
    else:
        path, _, query = (target or "/").partition("?")
    lowered = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    return {
        "ts": float(now or time.time()),
        "src_ip": src_ip or "",
        "src_port": int(src_port or 0),
        "dst_ip": dst_ip or "",
        "dst_port": int(dst_port or 8080),
        "method": str(method or "GET").upper(),
        "path": path or "/",
        "query": query,
        "body": (body or b"").decode("utf-8", errors="ignore")[:8192],
        "headers": {key: value[:1024] for key, value in lowered.items()
                    if key in FORWARD_HEADERS},
        "status": int(status or 0),
        "source": "api",
        # 响应回显（文本类响应才含 body；供页面呈现上传路径 / SQLi 拖库 / 命令回显）
        "response_head": str((response or {}).get("head") or ""),
        "response_body": str((response or {}).get("body") or ""),
    }


class HttpProxyHandler(BaseHTTPRequestHandler):
    """透明转发 + 异步投递；上游/检测系统失败都不影响代理返回。"""

    protocol_version = "HTTP/1.1"
    upstream_host = "127.0.0.1"
    upstream_port = 8081
    api_base = "http://127.0.0.1:8000/api/v1"
    api_token = ""
    public_dst_ip = "127.0.0.1"
    listen_port = 8080

    # ---- HTTP 方法 ---------------------------------------------------- #
    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def do_PUT(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_HEAD(self):
        self._proxy()

    def do_OPTIONS(self):
        self._proxy()

    # ---- 核心 --------------------------------------------------------- #
    def _client_ip(self) -> str:
        # 只信任 TCP 连接的真实来源，避免攻击者伪造 X-Forwarded-For 绕过检测/封禁
        return self.client_address[0] if self.client_address else ""

    def _proxy(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            self.send_error(413, "request body too large")
            return
        body = self.rfile.read(length) if length > 0 else b""

        status, payload, headers = self._forward(body)
        self._start_report(status, body, headers, payload)
        self.send_response(status)
        for key, value in headers:
            if key.lower() not in HOP_BY_HOP:
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _forward(self, body: bytes):
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in HOP_BY_HOP and key.lower() != "host"}
        # 透传客户端原始 Host（例如 192.168.137.142:8080），不要改写成上游地址。
        # 改写后上游的 SERVER_NAME 变成 127.0.0.1，会导致：
        #   1) 绝对跳转 Location 指回内网（http://127.0.0.1:8081/...）；
        #   2) Set-Cookie 的 domain=127.0.0.1，外部客户端浏览器直接丢弃 → 会话丢失、登录无反应。
        headers["Host"] = (self.headers.get("Host")
                           or f"{self.upstream_host}:{self.upstream_port}")
        headers["X-Forwarded-For"] = self._client_ip()
        connection = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=15)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read()
            return response.status, data, response.getheaders()
        except Exception as exc:
            logger.warning("上游业务站点不可达：%s", exc)
            message = json.dumps({"error": "upstream unavailable", "detail": str(exc)}).encode()
            return 502, message, [("Content-Type", "application/json")]
        finally:
            connection.close()

    def _start_report(self, status: int, body: bytes, headers=(), response_body: bytes = b"") -> None:
        payload = build_event_payload(
            self.command, self.path, dict(self.headers), body,
            src_ip=self._client_ip(), dst_ip=self.public_dst_ip,
            dst_port=self.listen_port, status=status,
            src_port=int(self.client_address[1]) if self.client_address else 0,
            response=build_response_snapshot(status, headers, response_body),
        )
        threading.Thread(target=self._report, args=(payload,), daemon=True).start()

    def _report(self, payload: Dict[str, Any]) -> None:
        data = json.dumps({"requests": [payload]}, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_base.rstrip('/')}/web/requests", data=data, method="POST",
            headers={"Content-Type": "application/json",
                     **({"X-API-Token": self.api_token} if self.api_token else {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                response.read(1024)
        except Exception as exc:      # 检测服务不可用不应影响业务
            logger.warning("请求投递检测系统失败：%s", exc)

    def log_message(self, fmt: str, *args):
        logger.info("%s - %s", self._client_ip(), fmt % args)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="HTTP 高保真接入代理（监听端口 → 业务站点）")
    parser.add_argument("--listen", default="0.0.0.0:8080", help="代理监听地址（默认 0.0.0.0:8080）")
    parser.add_argument("--upstream", default="127.0.0.1:8081", help="上游业务站点地址（默认 127.0.0.1:8081）")
    parser.add_argument("--api", default="http://127.0.0.1:8000/api/v1", help="检测系统 API 前缀")
    parser.add_argument("--token", default=os.environ.get("API_TOKEN", ""),
                        help="API_TOKEN（默认读取环境变量 API_TOKEN）")
    parser.add_argument("--dst-ip", default="127.0.0.1", help="事件中的目的 IP（业务地址）")
    parser.add_argument("--verbose", action="store_true", help="输出访问日志")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s [%(name)s] %(message)s")
    listen_host, _, listen_port = args.listen.partition(":")
    upstream_host, _, upstream_port = args.upstream.partition(":")

    HttpProxyHandler.upstream_host = upstream_host or "127.0.0.1"
    HttpProxyHandler.upstream_port = int(upstream_port or 8081)
    HttpProxyHandler.api_base = args.api
    HttpProxyHandler.api_token = args.token
    HttpProxyHandler.public_dst_ip = args.dst_ip
    HttpProxyHandler.listen_port = int(listen_port or 8080)

    server = ThreadingHTTPServer((listen_host or "0.0.0.0", HttpProxyHandler.listen_port),
                                 HttpProxyHandler)
    logger.warning("HTTP 接入代理已启动：%s → %s:%s（完整请求投递 %s）",
                   args.listen, HttpProxyHandler.upstream_host,
                   HttpProxyHandler.upstream_port, args.api)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0
