"""资产台账：被动流量发现 + 主动指纹更新。

* 被动：每个 tick 从流量聚合结果学习「内网主机 → 被访问端口」的对应关系，
  无需扫描即可建立资产清单（对应需求 3.5 的「流量特征识别」）；
* 主动：nmap / banner 扫描结果覆盖被动推断，补充产品版本与 CPE；
* 风险评级：危险端口 + 漏洞数 + 告警数综合打分。
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select

from ..collector.sources import FlowEvent, is_private_ip
from ..config import Settings, get_settings
from ..database import session_scope
from ..models import Asset, utcnow
from ..timeutil import iso_local
from .fingerprint import HostFingerprint

logger = logging.getLogger(__name__)

# 端口 → 业务标签
PORT_TAGS: Dict[int, str] = {
    21: "文件传输", 22: "远程管理", 23: "远程管理(明文)", 25: "邮件", 53: "DNS",
    80: "Web", 110: "邮件", 143: "邮件", 443: "Web", 445: "文件共享", 873: "备份",
    1433: "数据库", 2049: "文件共享", 2375: "容器", 3306: "数据库", 3389: "远程管理",
    5432: "数据库", 5601: "日志分析", 5900: "远程桌面", 6379: "缓存", 8080: "Web",
    8443: "Web", 9200: "日志分析", 11211: "缓存", 27017: "数据库",
}

# 高风险端口：出现在资产上会直接抬高风险等级
DANGEROUS_PORTS = {23, 445, 1433, 2375, 3389, 5900, 6379, 11211, 27017, 2049}


class AssetManager:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._lock = threading.Lock()
        # {ip: {"ports": {port: proto}, "pkt_in": .., "bytes_in": .., ...}}
        self._pending: Dict[str, Dict[str, object]] = {}

    # ------------------------------------------------------------------ #
    # 被动学习
    # ------------------------------------------------------------------ #
    def observe_flow(self, flow: FlowEvent) -> None:
        """从流量事件学习资产：目的地址在内网且端口为服务端口 → 记为资产。"""
        if not flow.dst_ip or not flow.dst_port:
            return
        if not is_private_ip(flow.dst_ip):
            return
        if flow.dst_port > 49151:      # 高位端口视为客户端临时端口，不作为服务特征
            return
        with self._lock:
            entry = self._pending.setdefault(
                flow.dst_ip, {"ports": {}, "pkt_in": 0, "bytes_in": 0, "pkt_out": 0, "bytes_out": 0}
            )
            ports: Dict[int, str] = entry["ports"]  # type: ignore[assignment]
            ports.setdefault(flow.dst_port, flow.proto)
            entry["pkt_in"] = int(entry["pkt_in"]) + flow.packets
            entry["bytes_in"] = int(entry["bytes_in"]) + flow.nbytes

            if flow.src_ip and is_private_ip(flow.src_ip):
                source_entry = self._pending.setdefault(
                    flow.src_ip, {"ports": {}, "pkt_in": 0, "bytes_in": 0, "pkt_out": 0, "bytes_out": 0}
                )
                source_entry["pkt_out"] = int(source_entry["pkt_out"]) + flow.packets
                source_entry["bytes_out"] = int(source_entry["bytes_out"]) + flow.nbytes

    def flush(self) -> int:
        """把累积的被动观测写入数据库（由采集 tick 周期调用）。"""
        with self._lock:
            pending, self._pending = self._pending, {}
        if not pending:
            return 0
        count = 0
        try:
            with session_scope() as session:
                for ip, entry in pending.items():
                    ports: Dict[int, str] = entry["ports"]  # type: ignore[assignment]
                    asset = session.scalar(select(Asset).where(Asset.ip == ip))
                    if asset is None:
                        asset = Asset(
                            ip=ip,
                            open_ports=sorted(ports.keys()),
                            services=[{"port": port, "name": _service_name(port), "product": "", "version": ""}
                                      for port in sorted(ports.keys())],
                            first_seen=utcnow(),
                        )
                        session.add(asset)
                    else:
                        asset.open_ports = sorted(set(asset.open_ports or []) | set(ports.keys()))
                    asset.pkt_in = (asset.pkt_in or 0) + int(entry["pkt_in"])
                    asset.pkt_out = (asset.pkt_out or 0) + int(entry["pkt_out"])
                    asset.bytes_in = (asset.bytes_in or 0) + int(entry["bytes_in"])
                    asset.bytes_out = (asset.bytes_out or 0) + int(entry["bytes_out"])
                    asset.last_seen = utcnow()
                    asset.tags = sorted({PORT_TAGS.get(port, "其他") for port in (asset.open_ports or [])})
                    asset.risk_level = self.evaluate_risk(asset)
                    count += 1
        except Exception:
            logger.exception("资产落库失败")
        return count

    # ------------------------------------------------------------------ #
    # 主动扫描结果应用
    # ------------------------------------------------------------------ #
    def apply_fingerprint(self, fingerprint: HostFingerprint) -> Optional[int]:
        if not fingerprint.services:
            return None
        try:
            with session_scope() as session:
                asset = session.scalar(select(Asset).where(Asset.ip == fingerprint.ip))
                if asset is None:
                    asset = Asset(ip=fingerprint.ip, first_seen=utcnow())
                    session.add(asset)
                asset.open_ports = fingerprint.open_ports
                asset.services = [service.to_dict() for service in fingerprint.services]
                asset.os_guess = fingerprint.os_guess
                if fingerprint.mac:
                    asset.mac = fingerprint.mac
                asset.last_seen = utcnow()
                asset.tags = sorted({PORT_TAGS.get(port, "其他") for port in fingerprint.open_ports})
                asset.risk_level = self.evaluate_risk(asset)
                session.flush()
                return asset.id
        except Exception:
            logger.exception("应用指纹失败")
            return None

    def refresh_risk(self, ip: str) -> None:
        try:
            with session_scope() as session:
                asset = session.scalar(select(Asset).where(Asset.ip == ip))
                if asset is not None:
                    asset.risk_level = self.evaluate_risk(asset)
        except Exception:
            logger.debug("刷新风险等级失败", exc_info=True)

    @staticmethod
    def evaluate_risk(asset: Asset) -> str:
        """综合评分：危险端口 + 漏洞 + 告警（分数越高风险越高）。"""
        score = 0
        for port in asset.open_ports or []:
            if port in DANGEROUS_PORTS:
                score += 20
        score += min(60, (asset.vuln_count or 0) * 15)
        score += min(40, (asset.alert_count or 0) * 5)
        if score >= 60:
            return "critical"
        if score >= 30:
            return "high"
        if score >= 10:
            return "medium"
        return "low"

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def list_assets(self, limit: int = 200, keyword: str = "") -> List[Dict[str, object]]:
        with session_scope() as session:
            rows = session.scalars(select(Asset).order_by(Asset.last_seen.desc()).limit(limit)).all()
        items = [self._serialize(row) for row in rows]
        if keyword:
            lowered = keyword.lower()
            items = [item for item in items
                     if lowered in str(item["ip"]).lower()
                     or lowered in str(item["hostname"]).lower()
                     or any(lowered in str(tag).lower() for tag in item["tags"])]
        return items

    def get(self, ip: str) -> Optional[Dict[str, object]]:
        with session_scope() as session:
            asset = session.scalar(select(Asset).where(Asset.ip == ip))
            return self._serialize(asset) if asset else None

    def summary(self) -> Dict[str, object]:
        with session_scope() as session:
            rows = session.scalars(select(Asset)).all()
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        port_counter: Dict[str, int] = {}
        tag_counter: Dict[str, int] = {}
        for asset in rows:
            key = asset.risk_level if asset.risk_level in distribution else "unknown"
            distribution[key] += 1
            for port in asset.open_ports or []:
                port_counter[str(port)] = port_counter.get(str(port), 0) + 1
            for tag in asset.tags or []:
                tag_counter[str(tag)] = tag_counter.get(str(tag), 0) + 1
        top_ports = sorted(port_counter.items(), key=lambda item: item[1], reverse=True)[:10]
        return {
            "total": len(rows),
            "risk_distribution": distribution,
            "top_ports": [{"port": int(port), "count": count} for port, count in top_ports],
            "tags": tag_counter,
            "updated_at": iso_local(utcnow()),
        }

    @staticmethod
    def _serialize(asset: Asset) -> Dict[str, object]:
        return {
            "id": asset.id,
            "ip": asset.ip,
            "mac": asset.mac,
            "hostname": asset.hostname,
            "os_guess": asset.os_guess,
            "open_ports": asset.open_ports or [],
            "services": asset.services or [],
            "risk_level": asset.risk_level,
            "tags": asset.tags or [],
            "bytes_in": asset.bytes_in,
            "bytes_out": asset.bytes_out,
            "alert_count": asset.alert_count,
            "vuln_count": asset.vuln_count,
            "first_seen": _iso(asset.first_seen),
            "last_seen": _iso(asset.last_seen),
        }


def _iso(value: Optional[datetime]) -> Optional[str]:
    """资产时间列（utcnow 写入）统一输出本地时间。"""
    return iso_local(value)


def _service_name(port: int) -> str:
    mapping = {22: "ssh", 80: "http", 443: "https", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
               6379: "redis", 8080: "http", 9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"}
    return mapping.get(port, "unknown")

