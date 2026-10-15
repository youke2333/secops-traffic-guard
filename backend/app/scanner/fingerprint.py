"""资产指纹识别：nmap 版本探测（NSE）为主，原生 banner 抓取为兜底。

为什么两级？

* ``nmap -sV`` 指纹库最全（含 CPE），但需要安装 nmap 且速度较慢；
* 无 nmap 的环境（或只需快速确认）用 socket banner 抓取，对 HTTP/SSH/Redis/MySQL
  等常见服务已足够生成「可交 CVE 知识库匹配」的产品与版本信息。
"""

from __future__ import annotations

import logging
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

from ..config import Settings, get_settings

logger = logging.getLogger(__name__)

# 常见服务端口 → 探测策略
HTTP_PORTS = {80, 81, 88, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 5601}
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 873, 1433, 2049, 2375, 3306,
                3389, 5432, 5601, 5900, 6379, 8080, 8443, 9000, 9090, 9200, 11211, 27017]
DEFAULT_PORTS = ("1-1024,1433,1521,2049,2375,3306,3389,5432,5601,5900,6379,8000,8080,8081,"
                 "8443,9000,9090,9200,11211,27017")


@dataclass
class ServiceInfo:
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""
    cpe: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class HostFingerprint:
    ip: str
    state: str = "up"
    os_guess: str = ""
    mac: str = ""
    services: List[ServiceInfo] = field(default_factory=list)

    @property
    def open_ports(self) -> List[int]:
        return sorted({service.port for service in self.services})


class Fingerprinter:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.nmap_path = shutil.which(self.settings.nmap_path) or ""

    @property
    def nmap_available(self) -> bool:
        return bool(self.nmap_path)

    # ------------------------------------------------------------------ #
    # 对外入口
    # ------------------------------------------------------------------ #
    def scan_host(self, ip: str, ports: str = "", use_nmap: bool = True) -> HostFingerprint:
        """识别单主机；优先 nmap，失败或无 nmap 时降级为 banner 抓取。"""
        result: Optional[HostFingerprint] = None
        if use_nmap and self.nmap_available:
            result = self._scan_with_nmap(ip, ports or DEFAULT_PORTS)
        if result is None or not result.services:
            banner_host = self._scan_with_banner(ip, self._parse_ports(ports))
            result = banner_host if result is None else result
            if not result.services:
                result.services = banner_host.services
        if not result.os_guess:
            result.os_guess = self._guess_os(result.services)
        return result

    # ------------------------------------------------------------------ #
    # nmap 实现
    # ------------------------------------------------------------------ #
    def _scan_with_nmap(self, ip: str, ports: str) -> Optional[HostFingerprint]:
        args = [self.nmap_path, "-Pn", "-n", "--version-light", "-T4", "-sV",
                "-oX", "-", "-p", str(ports), ip]
        try:
            proc = subprocess.run(args, capture_output=True, text=True,
                                  timeout=self.settings.scan_timeout_sec, check=False)
        except Exception as exc:
            logger.warning("nmap 执行失败: %s", exc)
            return None
        if not proc.stdout:
            logger.warning("nmap 无输出（stderr=%s）", (proc.stderr or "")[:200])
            return None
        return self._parse_nmap_xml(proc.stdout, ip)

    @staticmethod
    def _parse_nmap_xml(xml_text: str, ip: str) -> Optional[HostFingerprint]:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning("解析 nmap XML 失败: %s", exc)
            return None

        host = root.find("host")
        if host is None:
            return HostFingerprint(ip=ip, state="down")

        state_node = host.find("status")
        fingerprint = HostFingerprint(
            ip=ip, state=(state_node.get("state", "up") if state_node is not None else "up")
        )
        for address_node in host.findall("address"):
            if address_node.get("addrtype") == "mac":
                fingerprint.mac = address_node.get("addr", "") or ""

        for port_node in host.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") != "open":
                continue
            info = ServiceInfo(port=int(port_node.get("portid", "0")),
                               protocol=port_node.get("protocol", "tcp"))
            service_node = port_node.find("service")
            if service_node is not None:
                info.name = service_node.get("name", "") or ""
                info.product = service_node.get("product", "") or ""
                info.version = service_node.get("version", "") or ""
                info.banner = " ".join(filter(None, [service_node.get("extrainfo", ""),
                                                     service_node.get("ostype", "")])).strip()
                cpe_nodes = service_node.findall("cpe")
                if cpe_nodes:
                    info.cpe = cpe_nodes[0].text or ""
            fingerprint.services.append(info)

        os_match = host.find("./os/osmatch")
        if os_match is not None:
            fingerprint.os_guess = os_match.get("name", "")
        return fingerprint

    # ------------------------------------------------------------------ #
    # banner 抓取实现（无 nmap 环境的兜底路径）
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_ports(ports: str) -> List[int]:
        if not ports:
            return COMMON_PORTS
        wanted: List[int] = []
        for chunk in ports.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                start, _, end = chunk.partition("-")
                try:
                    wanted.extend(range(int(start), min(int(end), 65535) + 1))
                except ValueError:
                    continue
            elif chunk.isdigit():
                wanted.append(int(chunk))
        return wanted[:512] or COMMON_PORTS   # 限制规模，避免扫描耗时不可控

    def _scan_with_banner(self, ip: str, ports: List[int]) -> HostFingerprint:
        """并行 banner 抓取：串行时每个端口最坏要等 1.2s，几十个端口就会让接口超时。

        用线程池把阻塞式 socket 探测并发化（默认 24 并发），整体耗时从 O(端口数 × 超时)
        降到 O(端口数 / 并发数 × 超时)，同时限制并发避免触发目标主机的连接数告警。
        """
        fingerprint = HostFingerprint(ip=ip)
        if not ports:
            return fingerprint
        workers = min(24, max(4, len(ports)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="banner") as pool:
            results = list(pool.map(lambda port: (port, self._grab_banner(ip, port, timeout=0.8)), ports))
        for port, banner in results:
            if not banner:
                continue
            product, version = self._parse_banner(port, banner)
            fingerprint.services.append(ServiceInfo(
                port=port, protocol="tcp", name=self._service_name(port),
                product=product, version=version, banner=banner[:300],
            ))
        fingerprint.services.sort(key=lambda item: item.port)
        return fingerprint

    @staticmethod
    def _grab_banner(ip: str, port: int, timeout: float = 1.2) -> str:
        payload = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n" if port in HTTP_PORTS else ""
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if payload:
                    sock.sendall(payload.encode())
                chunks = b""
                try:
                    while len(chunks) < 2048:
                        data = sock.recv(512)
                        if not data:
                            break
                        chunks += data
                        if b"\r\n\r\n" in chunks:
                            break
                except socket.timeout:
                    pass
                return chunks.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    @staticmethod
    def _service_name(port: int) -> str:
        mapping = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
                   110: "pop3", 143: "imap", 443: "https", 445: "smb", 873: "rsync",
                   1433: "mssql", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp",
                   5432: "postgresql", 5601: "kibana", 5900: "vnc", 6379: "redis",
                   8080: "http", 8443: "https", 9200: "elasticsearch", 11211: "memcached",
                   27017: "mongodb"}
        return mapping.get(port, "unknown")

    @staticmethod
    def _parse_banner(port: int, banner: str) -> Tuple[str, str]:
        """从 banner 中提取（产品, 版本），覆盖常见中间件。"""
        text = banner.strip()
        patterns = [
            (r"(OpenSSH)[_/ ]([\d.p]+)", "OpenSSH"),
            (r"(Apache)/([\d.]+)", "Apache httpd"),
            (r"(nginx)/([\d.]+)", "nginx"),
            (r"(Microsoft-IIS)/([\d.]+)", "Microsoft IIS"),
            (r"(Tomcat)/([\d.]+)", "Apache Tomcat"),
            (r"(Jetty)[ (/]([\d.]+)", "Jetty"),
            (r"(redis_version):([\d.]+)", "Redis"),
            (r"(MySQL)[^\d]{0,20}([\d.]+)", "MySQL"),
            (r"(PostgreSQL)[^\d]{0,20}([\d.]+)", "PostgreSQL"),
            (r"(MariaDB)[^\d]{0,20}([\d.]+)", "MariaDB"),
            (r"(Elasticsearch)[^\d]{0,20}([\d.]+)", "Elasticsearch"),
            (r"(vsFTPd)\s([\d.]+)", "vsftpd"),
        ]
        for pattern, product in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                version = match.group(2) if (match.lastindex or 0) >= 2 else ""
                return product, version or ""
        first_line = text.splitlines()[0][:80] if text else ""
        return first_line, ""

    @staticmethod
    def _guess_os(services: List[ServiceInfo]) -> str:
        products = " ".join(f"{item.product} {item.banner}" for item in services).lower()
        if "microsoft-iis" in products or "windows" in products or "rdp" in products:
            return "Windows（TCP/IP 指纹推断）"
        if "centos" in products or "rhel" in products or "red hat" in products:
            return "Linux/RHEL 系（banner 推断）"
        if "openssh" in products or "ubuntu" in products or "debian" in products:
            return "Linux（SSH banner 推断）"
        return "未知"

