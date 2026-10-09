"""白名单管理：封禁前的最后一道闸门，防止误封业务/管理侧地址。

两级来源：
1. 配置文件 ``WHITELIST_CIDRS``（回环、组播等系统必留地址）；
2. 数据库 ``whitelist`` 表（运维通过 API 动态维护）。
热路径查询走内存缓存，避免每包一次 DB 查询。
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from typing import Dict, List, Optional

from ..config import Settings, get_settings
from ..database import session_scope
from ..models import DisposalLog, WhitelistEntry, utcnow

logger = logging.getLogger(__name__)


class WhitelistManager:
    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self._lock = threading.RLock()
        self._nets: List[ipaddress._BaseNetwork] = []       # type: ignore[attr-defined]
        self._entries: Dict[str, Dict[str, object]] = {}
        self._load_config_defaults()

    # ---------------- 加载 ----------------
    def _parse(self, cidr: str) -> Optional[ipaddress._BaseNetwork]:  # type: ignore[attr-defined]
        try:
            return ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("忽略非法白名单项: %s", cidr)
            return None

    def _load_config_defaults(self) -> None:
        with self._lock:
            for cidr in self.settings.whitelist_cidrs:
                net = self._parse(cidr)
                if net is not None and cidr not in self._entries:
                    self._nets.append(net)
                    self._entries[cidr] = {"cidr": cidr, "note": "系统内置", "operator": "system",
                                           "created_at": None, "source": "config"}

    def load_from_db(self) -> int:
        """启动时从数据库加载动态白名单，返回条数。"""
        loaded = 0
        try:
            with session_scope() as session:
                rows = session.query(WhitelistEntry).all()
                with self._lock:
                    for row in rows:
                        net = self._parse(row.cidr)
                        if net is None:
                            continue
                        if row.cidr not in self._entries:
                            self._nets.append(net)
                        self._entries[row.cidr] = {
                            "cidr": row.cidr,
                            "note": row.note,
                            "operator": row.operator,
                            "created_at": row.created_at,
                            "source": "db",
                        }
                        loaded += 1
        except Exception:
            logger.exception("加载白名单失败（数据库尚未初始化？）")
        return loaded

    # ---------------- 查询 ----------------
    def is_whitelisted(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        with self._lock:
            nets = list(self._nets)
        return any(addr in net for net in nets)

    def reason(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ""
        with self._lock:
            for cidr, entry in self._entries.items():
                net = self._parse(cidr)
                if net is not None and addr in net:
                    return str(entry.get("note") or cidr)
        return ""

    def entries(self) -> List[Dict[str, object]]:
        with self._lock:
            return list(self._entries.values())

    # ---------------- 维护 ----------------
    def add(self, cidr: str, note: str = "", operator: str = "admin") -> bool:
        net = self._parse(cidr)
        if net is None:
            return False
        normalized = str(net)
        with self._lock:
            if normalized in self._entries:
                return False
        try:
            with session_scope() as session:
                session.add(WhitelistEntry(cidr=normalized, note=note, operator=operator, created_at=utcnow()))
                session.add(DisposalLog(action="whitelist_add", target=normalized,
                                        detail=f"新增白名单: {note}", operator=operator))
        except Exception:
            logger.exception("写入白名单失败")
            return False
        with self._lock:
            self._entries[normalized] = {"cidr": normalized, "note": note, "operator": operator,
                                         "created_at": utcnow(), "source": "db"}
            self._nets.append(net)
        logger.info("白名单新增: %s（%s）", normalized, note)
        return True

    def remove(self, cidr: str, operator: str = "admin") -> bool:
        normalized = cidr.strip()
        with self._lock:
            entry = self._entries.get(normalized)
            if entry is None or entry.get("source") == "config":
                return False
        try:
            with session_scope() as session:
                session.query(WhitelistEntry).filter(WhitelistEntry.cidr == normalized).delete()
                session.add(DisposalLog(action="whitelist_remove", target=normalized,
                                        detail="移除白名单", operator=operator))
        except Exception:
            logger.exception("删除白名单失败")
            return False
        with self._lock:
            self._entries.pop(normalized, None)
            self._nets = [net for net in self._nets if str(net) != normalized]
        logger.info("白名单移除: %s", normalized)
        return True
