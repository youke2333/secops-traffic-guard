"""流量方向判定（不猜测：无法判定时返回 unknown）。"""

from __future__ import annotations

import ipaddress
from typing import Iterable, List, Tuple


def _networks(values: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    result = []
    for item in values or []:
        try:
            result.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    return result


def parse_protected(values: Iterable[str]) -> Tuple[List[ipaddress._BaseNetwork], set]:
    networks = _networks(values)
    return networks, {str(network) for network in networks}


def _inside(address: str, networks: List[ipaddress._BaseNetwork]) -> bool:
    try:
        parsed = ipaddress.ip_address(str(address or ""))
    except ValueError:
        return False
    return any(parsed in network for network in networks)


def detect_direction(src_ip: str, dst_ip: str, protected_cidrs: Iterable[str]) -> str:
    """返回 inbound（外到内）/ internal（内到内）/ outbound（内到外）/ unknown。

    * 必须先配置 ``PROTECTED_CIDRS``；未配置时不猜测，统一返回 unknown；
    * NAT 环境应在 NAT **前**的接口采集，否则源地址会被改写成网关地址。
    """
    networks = _networks(protected_cidrs)
    if not networks:
        return "unknown"
    src_in = _inside(src_ip, networks)
    dst_in = _inside(dst_ip, networks)
    if src_in and dst_in:
        return "internal"
    if dst_in and not src_in:
        return "inbound"
    if src_in and not dst_in:
        return "outbound"
    return "unknown"
