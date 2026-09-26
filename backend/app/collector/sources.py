"""流量采集源实现。

三级降级策略（由 ``build_source`` 自动选择，也可用 CAPTURE_MODE 强制指定）：

1. ``EBPFSource``  —— 生产首选，eBPF 内核态按流聚合，开销 <1% CPU；
2. ``ScapySource`` —— 兜底，libpcap 用户态抓包 + BPF 过滤（容器/无内核头文件环境）；
3. ``DemoSource``  —— 无抓包权限（开发机/Windows/演示环境）时生成仿真流量，保证全链路可跑通。
"""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

FlowCallback = Callable[["FlowEvent"], None]

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

EBPF_PROGRAM_FILE = Path(__file__).with_name("ebpf_program.c")


def is_private_ip(ip: str) -> bool:
    """内网判定，用于大屏的"内网/互联网"来源归类。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in PRIVATE_NETS)


@dataclass(slots=True)
class FlowEvent:
    """标准化流量事件——无论来自 eBPF 还是 libpcap，上层只认这个结构。"""

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str = "TCP"
    nbytes: int = 0
    packets: int = 1
    flags: str = ""
    direction: str = "in"      # in=入站（dst 为本机服务端口），out=出站
    iface: str = ""


class SourceUnavailable(RuntimeError):
    """当前环境无法使用该采集源（无权限 / 缺依赖 / 平台不支持）。"""


class TrafficSource(ABC):
    name = "base"
    description = ""

    def __init__(self, iface: str = "", bpf_filter: str = "ip and (tcp or udp)") -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._running = False

    @abstractmethod
    def start(self, on_flow: FlowCallback) -> None:
        """启动采集，每个流量事件回调一次 ``on_flow``。"""

    @abstractmethod
    def stop(self) -> None:
        """停止采集并释放资源（必须幂等）。"""

    @property
    def running(self) -> bool:
        return self._running


# --------------------------------------------------------------------------- #
# 1. eBPF 采集源（生产首选）
# --------------------------------------------------------------------------- #
class EBPFSource(TrafficSource):
    """基于 BCC 的 eBPF 采集源：内核态按流聚合，用户态每 tick 拉取并清空哈希表。"""

    name = "ebpf"
    description = "eBPF/BCC 内核态流聚合（Linux >= 4.9，需 root 或 CAP_BPF）"

    def __init__(self, iface: str = "", bpf_filter: str = "", poll_interval: float = 0.2) -> None:
        super().__init__(iface=iface, bpf_filter=bpf_filter)
        self.iface = iface
        self.poll_interval = poll_interval
        self._bpf = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._locals: set = set()

    @staticmethod
    def available() -> bool:
        try:
            import bcc  # noqa: F401
        except Exception:
            return False
        return True

    def start(self, on_flow: FlowCallback) -> None:
        if not self.available():
            raise SourceUnavailable("未安装 BCC(bcc)，无法启用 eBPF 采集")
        from bcc import BPF  # 仅 Linux 环境存在

        program = EBPF_PROGRAM_FILE.read_text(encoding="utf-8")
        try:
            self._bpf = BPF(text=program)
        except Exception as exc:
            raise SourceUnavailable(f"eBPF 程序加载失败（需内核头文件与 root 权限）: {exc}") from exc

        self._running = True
        self._stop.clear()
        self._locals = self._local_addrs
        self._thread = threading.Thread(target=self._poll_loop, args=(on_flow,), name="ebpf-poller", daemon=True)
        self._thread.start()
        logger.info("eBPF 采集已启动（iface=%s, 本机地址=%s）", self.iface or "all", sorted(self._locals) or "未知")

    def _poll_loop(self, on_flow: FlowCallback) -> None:  # pragma: no cover - 依赖内核
        import struct

        flows_table = self._bpf["flows"]
        while not self._stop.is_set():
            time.sleep(self.poll_interval)
            now = time.time()
            for key, value in list(flows_table.items()):
                nbytes = int(value.value)
                flows_table.pop(key, None)
                if nbytes <= 0:
                    continue
                saddr, daddr, sport, dport, proto = struct.unpack("IIHHB", bytes(key)[:13])
                src_ip = socket.inet_ntoa(struct.pack("I", saddr))
                dst_ip = socket.inet_ntoa(struct.pack("I", daddr))
                event = FlowEvent(
                    ts=now,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    proto="TCP" if proto == 6 else "UDP",
                    nbytes=nbytes,
                    packets=max(1, nbytes // 1400 + 1),
                    direction="in" if (self._locals and dst_ip in self._locals) else "out",
                    iface=self.iface,
                )
                try:
                    on_flow(event)
                except Exception:
                    logger.exception("处理 eBPF 事件失败")

    @property
    def _local_addrs(self) -> set:
        """本机地址集合，用于判定入/出站方向。"""
        try:
            return {item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None)}
        except Exception:
            return set()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self._bpf = None
        self._running = False


# --------------------------------------------------------------------------- #
# 2. libpcap / scapy 采集源（兜底）
# --------------------------------------------------------------------------- #
class ScapySource(TrafficSource):
    """libpcap 用户态抓包：兼容性好，代价是每包一次用户态拷贝。

    适合单机 < 1Gbps 场景；更高带宽请使用 EBPFSource 或改用 XDP/DPDK。
    """

    name = "scapy"
    description = "scapy/libpcap 用户态抓包（需 root 或 CAP_NET_RAW）"

    def __init__(self, iface: str = "", bpf_filter: str = "ip and (tcp or udp)") -> None:
        super().__init__(iface=iface, bpf_filter=bpf_filter)
        self._sniffer = None
        self._local_addrs: set = set()

    @staticmethod
    def available() -> bool:
        try:
            import scapy.all  # noqa: F401
        except Exception:
            return False
        return True

    @staticmethod
    def default_iface() -> str:
        try:
            from scapy.all import conf

            return str(conf.iface or "")
        except Exception:
            return ""

    @staticmethod
    def _local_addresses() -> set:
        addrs = set()
        try:
            addrs.add(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
        for probe in ("8.8.8.8", "192.168.1.1"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect((probe, 53))
                addrs.add(sock.getsockname()[0])
            except Exception:
                continue
            finally:
                sock.close()
        return addrs

    def start(self, on_flow: FlowCallback) -> None:
        if not self.available():
            raise SourceUnavailable("未安装 scapy，无法启用 libpcap 采集")
        from scapy.all import AsyncSniffer

        iface = self.iface or self.default_iface()
        self._local_addrs = self._local_addresses()
        try:
            self._sniffer = AsyncSniffer(
                iface=iface or None,
                filter=self.bpf_filter or None,
                prn=lambda pkt: self._handle(pkt, on_flow),
                store=False,
                promisc=True,
            )
            self._sniffer.start()
        except Exception as exc:
            message = str(exc)
            if "permission" in message.lower() or "not permitted" in message.lower():
                raise SourceUnavailable(
                    "抓包权限不足：请以 root 运行，或执行 "
                    "`sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))`"
                ) from exc
            raise SourceUnavailable(f"libpcap 启动失败: {exc}") from exc

        self.iface = iface
        self._running = True
        logger.info("libpcap 采集已启动（iface=%s, filter=%s）", iface or "auto", self.bpf_filter)

    def _handle(self, pkt, on_flow: FlowCallback) -> None:
        from scapy.layers.inet import IP, TCP, UDP

        ip_layer = pkt.getlayer(IP)
        if ip_layer is None:
            return
        tcp = pkt.getlayer(TCP)
        udp = pkt.getlayer(UDP)
        if tcp is not None:
            proto, l4, flags = "TCP", tcp, str(tcp.flags)
        elif udp is not None:
            proto, l4, flags = "UDP", udp, ""
        else:
            return

        src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
        direction = "in" if dst_ip in self._local_addrs else "out"
        try:
            on_flow(
                FlowEvent(
                    ts=time.time(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(getattr(l4, "sport", 0) or 0),
                    dst_port=int(getattr(l4, "dport", 0) or 0),
                    proto=proto,
                    nbytes=len(bytes(pkt)),
                    packets=1,
                    flags=flags,
                    direction=direction,
                    iface=self.iface,
                )
            )
        except Exception:
            logger.exception("解析数据包失败")

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                logger.debug("停止 sniffer 时出现异常", exc_info=True)
            self._sniffer = None
        self._running = False


# --------------------------------------------------------------------------- #
# 3. 演示数据源（无抓包权限时保证全链路可跑通）
# --------------------------------------------------------------------------- #
@dataclass
class _Scenario:
    """一次攻击剧本：由仿真器随机触发，检测引擎并不知道"标准答案"。"""

    kind: str
    src_ip: str
    dst_ip: str
    dst_port: int
    until: float
    cursor: int = 0


class DemoSource(TrafficSource):
    """仿真流量源。

    构造「内网正常业务 + 周期性攻击剧本」的流量模型，用于：

    * Windows / macOS 开发机上调试检测与封禁逻辑；
    * 演示环境（答辩/评审）稳定复现异常端口、暴破、端口扫描、突发峰值 4 类告警。

    注意：剧本标签不会传给检测引擎，检测结果完全由流量统计特征推导，保证评测公平。
    """

    name = "demo"
    description = "内置仿真流量（无需任何权限，用于演示与自测）"

    SERVERS = ["192.168.1.10", "192.168.1.15", "192.168.1.18", "192.168.1.20", "192.168.1.30"]
    CLIENTS = ["10.20.0.11", "10.20.0.12", "10.20.0.13", "10.20.0.14", "10.20.0.15"]
    PUBLIC = ["114.114.114.114", "203.0.113.66", "198.51.100.23", "45.33.32.156", "185.199.108.153", "91.121.87.5"]
    NORMAL_PORTS = [443, 80, 53, 3306, 6379, 8080, 22]
    ATTACK_KINDS = ["port_scan", "brute_force", "nonstd_burst", "traffic_spike"]

    def __init__(self, iface: str = "demo0", bpf_filter: str = "", packet_rate: int = 60) -> None:
        super().__init__(iface=iface, bpf_filter=bpf_filter)
        self.packet_rate = packet_rate
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._scenario: Optional[_Scenario] = None
        self._next_scenario_at = 0.0

    def start(self, on_flow: FlowCallback) -> None:
        self._running = True
        self._stop.clear()
        self._next_scenario_at = time.time() + 6.0
        self._thread = threading.Thread(target=self._loop, args=(on_flow,), name="demo-source", daemon=True)
        self._thread.start()
        logger.info("仿真采集源已启动（攻击剧本每 25~40s 触发一次）")

    def _emit_normal(self, on_flow: FlowCallback) -> None:
        now = time.time()
        for _ in range(random.randint(1, 4)):
            if random.random() < 0.7:
                src, dst = random.choice(self.CLIENTS), random.choice(self.SERVERS)
                sport, dport = random.randint(33000, 61000), random.choice(self.NORMAL_PORTS)
                direction = "in"
            else:
                src, dst = random.choice(self.SERVERS), random.choice(self.PUBLIC)
                sport, dport = random.randint(33000, 61000), random.choice([80, 443, 53])
                direction = "out"
            on_flow(
                FlowEvent(
                    ts=now, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                    proto="TCP", nbytes=int(max(64, random.gauss(1200, 600))), packets=1,
                    flags="A", iface=self.iface, direction=direction,
                )
            )

    def _emit_scenario(self, on_flow: FlowCallback, scenario: _Scenario) -> None:
        now = time.time()
        src_port = random.randint(30000, 60000)
        if scenario.kind == "port_scan":
            # 单源在短时间内探测大量目的端口 —— 触发 unique_dst_ports 特征
            for _ in range(12):
                scenario.cursor += random.randint(1, 40)
                on_flow(FlowEvent(ts=now, src_ip=scenario.src_ip, dst_ip=scenario.dst_ip,
                                  src_port=src_port, dst_port=1 + (scenario.cursor % 9000),
                                  proto="TCP", nbytes=60, packets=1, flags="S",
                                  direction="in", iface=self.iface))
        elif scenario.kind == "brute_force":
            # 高包速率的认证型端口访问
            for _ in range(14):
                on_flow(FlowEvent(ts=now, src_ip=scenario.src_ip, dst_ip=scenario.dst_ip,
                                  src_port=src_port, dst_port=scenario.dst_port,
                                  proto="TCP", nbytes=120, packets=1, flags="PA",
                                  direction="in", iface=self.iface))
        elif scenario.kind == "nonstd_burst":
            # 非标准端口（4444/31337 等）高频访问
            for _ in range(18):
                on_flow(FlowEvent(ts=now, src_ip=scenario.src_ip, dst_ip=scenario.dst_ip,
                                  src_port=src_port, dst_port=scenario.dst_port,
                                  proto="TCP", nbytes=random.randint(300, 900), packets=1,
                                  flags="PA", direction="in", iface=self.iface))
        elif scenario.kind == "traffic_spike":
            # 单 tick 内上兆字节，制造带宽利用率尖峰
            for _ in range(10):
                on_flow(FlowEvent(ts=now, src_ip=scenario.src_ip, dst_ip=scenario.dst_ip,
                                  src_port=src_port, dst_port=scenario.dst_port,
                                  proto="TCP", nbytes=random.randint(700_000, 1_500_000),
                                  packets=1, flags="A", direction="in", iface=self.iface))

    def _maybe_start_scenario(self) -> None:
        now = time.time()
        if self._scenario is not None or now < self._next_scenario_at:
            return
        kind = random.choice(self.ATTACK_KINDS)
        dst = random.choice(self.SERVERS)
        if kind == "port_scan":
            src, port, ttl = "203.0.113.66", 0, 18
        elif kind == "brute_force":
            src, port, ttl = "198.51.100.23", random.choice([22, 3389, 3306]), 22
        elif kind == "nonstd_burst":
            src, port, ttl = "45.33.32.156", random.choice([4444, 6666, 31337, 12345]), 20
        else:
            src, port, ttl = "185.199.108.153", random.choice([9090, 5555]), 14
        self._scenario = _Scenario(kind=kind, src_ip=src, dst_ip=dst, dst_port=port, until=now + ttl)
        logger.info("仿真剧本启动: %s %s -> %s:%s", kind, src, dst, port or "-")

    def _loop(self, on_flow: FlowCallback) -> None:
        interval = 1.0 / max(1, self.packet_rate)
        while not self._stop.is_set():
            self._maybe_start_scenario()
            try:
                self._emit_normal(on_flow)
                if self._scenario is not None:
                    self._emit_scenario(on_flow, self._scenario)
                    if time.time() >= self._scenario.until:
                        logger.info("仿真剧本结束: %s", self._scenario.kind)
                        self._scenario = None
                        self._next_scenario_at = time.time() + random.uniform(25, 40)
            except Exception:
                logger.exception("仿真流量生成异常")
            time.sleep(interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        self._running = False


def build_source(mode: str, iface: str = "", bpf_filter: str = "ip and (tcp or udp)") -> TrafficSource:
    """按 CAPTURE_MODE 构建采集源；auto 模式执行三级降级并记录降级原因。"""
    mode = (mode or "auto").lower()
    if mode == "ebpf":
        return EBPFSource(iface=iface, bpf_filter=bpf_filter)
    if mode == "scapy":
        return ScapySource(iface=iface, bpf_filter=bpf_filter)
    if mode == "demo":
        return DemoSource(iface=iface or "demo0")

    if EBPFSource.available():
        return EBPFSource(iface=iface, bpf_filter=bpf_filter)
    if ScapySource.available():
        logger.info("eBPF 不可用，降级使用 libpcap(scapy) 采集")
        return ScapySource(iface=iface, bpf_filter=bpf_filter)
    logger.warning("无可用抓包能力，降级为仿真数据源（仅用于演示）")
    return DemoSource(iface=iface or "demo0")




