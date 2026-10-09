"""封禁编排：白名单校验 → 防火墙下发 → 落库留痕 → 通知 → TTL 自动解封。

这是"检测 → 响应"闭环的核心，也是风险最高的一环，因此：

* 白名单校验放在最前面，命中即拒绝封禁并记录原因；
* 同一 IP 已封禁则只累加 ``hits``，不重复下发规则；
* 每条封禁都有 TTL（默认 30 分钟），到期由后台线程自动解封，防止"一次误判永久断网"；
* 所有动作写入 ``disposal_logs``，大屏处置时间线与审计报表直接消费该表。
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select

from ..alerting.notifier import Notifier
from ..config import Settings, get_settings
from ..database import session_scope
from ..models import Alert, BlockRule, DisposalLog, utcnow
from ..timeutil import iso_local
from .firewall import FirewallBackend, FirewallError, build_backend
from .whitelist import WhitelistManager

logger = logging.getLogger(__name__)


class Blocker:
    def __init__(self, settings: Optional[Settings] = None,
                 backend: Optional[FirewallBackend] = None,
                 whitelist: Optional[WhitelistManager] = None,
                 notifier: Optional[Notifier] = None) -> None:
        self.settings = settings or get_settings()
        self.backend = backend or build_backend(
            self.settings.firewall_backend, self.settings.dry_run, self.settings.firewall_chain
        )
        self.whitelist = whitelist or WhitelistManager(self.settings)
        self.notifier = notifier
        self._reaper: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start_reaper(self) -> None:
        """启动 TTL 到期自动解封线程（幂等）。"""
        if self._reaper is not None and self._reaper.is_alive():
            return
        self._stop.clear()
        self._reaper = threading.Thread(target=self._reap_loop, name="block-reaper", daemon=True)
        self._reaper.start()

    def stop_reaper(self) -> None:
        self._stop.set()
        if self._reaper is not None:
            self._reaper.join(timeout=2)
            self._reaper = None

    def _reap_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.release_expired()
            except Exception:
                logger.exception("自动解封线程异常")
            time.sleep(10)

    # ------------------------------------------------------------------ #
    # 封禁
    # ------------------------------------------------------------------ #
    def block(self, ip: str, reason: str = "", category: str = "manual", severity: str = "high",
              ttl_sec: Optional[int] = None, source: str = "auto", operator: str = "system",
              force: bool = False) -> Dict[str, object]:
        ip = (ip or "").strip()
        if not ip:
            return {"success": False, "message": "封禁目标为空"}

        # 1) 白名单闸门：命中即拒绝
        if not force and self.whitelist.is_whitelisted(ip):
            detail = f"目标 {ip} 命中白名单（{self.whitelist.reason(ip) or '内置规则'}），已拒绝封禁"
            logger.info(detail)
            self._log_disposal("block", ip, detail, operator, success=False)
            return {"success": False, "message": detail, "whitelisted": True}

        # 2) 重复封禁去重：只累加命中次数
        try:
            with session_scope() as session:
                existing = session.scalar(
                    select(BlockRule).where(BlockRule.ip == ip, BlockRule.active.is_(True))
                )
                if existing is not None:
                    existing.hits += 1
                    existing.reason = reason or existing.reason
                    return {
                        "success": True,
                        "message": f"{ip} 已在封禁中（命中次数 {existing.hits}）",
                        "duplicated": True,
                        "block_id": existing.id,
                    }
        except Exception:
            logger.exception("查询已有封禁记录失败")

        # 3) 下发防火墙规则
        ttl = int(ttl_sec if ttl_sec is not None else self.settings.block_ttl_sec)
        try:
            ok, message, cmd = self.backend.block(ip, ttl_sec=ttl)
        except FirewallError as exc:
            ok, message, cmd = False, str(exc), []

        expires_at = utcnow() + timedelta(seconds=ttl) if ttl > 0 else None
        rule_spec = " ".join(cmd)
        block_id: Optional[int] = None
        try:
            with session_scope() as session:
                rule = BlockRule(
                    ip=ip, reason=reason or "自动封禁", category=category, severity=severity,
                    backend=self.backend.name, rule_spec=rule_spec, source=source,
                    operator=operator, expires_at=expires_at, active=bool(ok),
                    dry_run=self.backend.dry_run,
                )
                session.add(rule)
                session.flush()
                block_id = rule.id
                session.add(DisposalLog(
                    action="block", target=ip,
                    detail=f"[{category}/{severity}] {reason} | 后端={self.backend.name} | {message}",
                    operator=operator, success=bool(ok),
                ))
                session.query(Alert).filter(
                    Alert.source_ip == ip, Alert.status == "open"
                ).update({"status": "blocked" if ok else "open", "blocked": bool(ok),
                          "disposed_by": operator, "disposed_at": utcnow()})
        except Exception:
            logger.exception("封禁记录落库失败")

        result = {
            "success": bool(ok),
            "message": message if ok else f"防火墙下发失败: {message}",
            "block_id": block_id,
            "backend": self.backend.name,
            "dry_run": self.backend.dry_run,
            "expires_at": iso_local(expires_at),
            "command": rule_spec,
        }
        logger.warning("封禁 IP %s：%s（%s）", ip, "成功" if ok else "失败", message)
        return result

    # ------------------------------------------------------------------ #
    # 续期
    # ------------------------------------------------------------------ #
    def extend_ttl(self, ip: str, ttl_sec: int) -> Tuple[bool, str]:
        """续期时同步内核侧的到期时间。

        两个后端对 TTL 的实现不同，续期动作必须有区别：

        * **iptables**：规则是一条无过期时间的 DROP，到期靠 ``release_expired()``
          按数据库的 ``expires_at`` 清理，所以改库就够了，不能重复下发
          （``-I`` 会插出一条重复规则）。
        * **nftables**：集合元素自带 ``timeout``，内核会自行到期删除。只改数据库
          会导致"控制台显示仍封禁、内核其实已放行"，必须 unprefix 后重新下发。

        返回 (是否成功, 说明)；DRY-RUN 下由后端自身短路，不会真正改内核。
        """
        if self.backend.name != "nftables":
            return True, "规则无内核过期时间，仅更新数据库到期时间"
        try:
            self.backend.unblock(ip)
            ok, message, _cmd = self.backend.block(ip, ttl_sec=int(ttl_sec))
        except FirewallError as exc:
            return False, str(exc)
        return ok, message

    # ------------------------------------------------------------------ #
    # 解封
    # ------------------------------------------------------------------ #
    def unblock(self, ip: str, operator: str = "admin", reason: str = "人工解封") -> Dict[str, object]:
        ip = (ip or "").strip()
        if not ip:
            return {"success": False, "message": "解封目标为空"}
        try:
            ok, message, cmd = self.backend.unblock(ip)
        except FirewallError as exc:
            ok, message, cmd = False, str(exc), []

        released = 0
        try:
            with session_scope() as session:
                rows = session.scalars(
                    select(BlockRule).where(BlockRule.ip == ip, BlockRule.active.is_(True))
                ).all()
                for row in rows:
                    row.active = False
                    row.released_at = utcnow()
                    released += 1
                session.add(DisposalLog(action="unblock", target=ip,
                                        detail=f"{reason} | {message}", operator=operator, success=bool(ok)))
        except Exception:
            logger.exception("解封落库失败")

        return {
            "success": bool(ok),
            "message": f"{ip} 解封完成（释放 {released} 条规则）: {message}",
            "released": released,
            "command": " ".join(cmd),
        }

    def release_expired(self) -> int:
        """扫描并解封已到期规则，返回处理条数（由后台线程周期调用）。"""
        count = 0
        try:
            with session_scope() as session:
                now = utcnow()
                rows = session.scalars(
                    select(BlockRule).where(
                        BlockRule.active.is_(True),
                        BlockRule.expires_at.isnot(None),
                        BlockRule.expires_at <= now,
                    )
                ).all()
                for row in rows:
                    try:
                        ok, message, _ = self.backend.unblock(row.ip)
                    except Exception as exc:  # pragma: no cover
                        ok, message = False, str(exc)
                    row.active = False
                    row.released_at = now
                    count += 1
                    session.add(DisposalLog(
                        action="unblock", target=row.ip,
                        detail=f"TTL 到期自动解封 | {message}", operator="system", success=bool(ok),
                    ))
        except Exception:
            logger.exception("扫描到期封禁失败")
        return count

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def active_blocks(self, limit: int = 200) -> List[Dict[str, object]]:
        with session_scope() as session:
            rows = session.scalars(
                select(BlockRule).where(BlockRule.active.is_(True))
                .order_by(BlockRule.created_at.desc()).limit(limit)
            ).all()
            return [self._serialize(row) for row in rows]

    def history(self, limit: int = 100) -> List[Dict[str, object]]:
        with session_scope() as session:
            rows = session.scalars(
                select(BlockRule).order_by(BlockRule.created_at.desc()).limit(limit)
            ).all()
            return [self._serialize(row) for row in rows]

    def disposal_logs(self, limit: int = 50) -> List[Dict[str, object]]:
        with session_scope() as session:
            rows = session.scalars(
                select(DisposalLog).order_by(DisposalLog.ts.desc()).limit(limit)
            ).all()
            return [{
                "id": row.id, "ts": iso_local(row.ts), "action": row.action,
                "target": row.target, "detail": row.detail, "operator": row.operator,
                "success": row.success,
            } for row in rows]

    @staticmethod
    def _serialize(row: BlockRule) -> Dict[str, object]:
        now = utcnow()
        remaining = None
        if row.expires_at and row.active:
            remaining = max(0, int((row.expires_at - now).total_seconds()))
        return {
            "id": row.id, "ip": row.ip, "reason": row.reason, "category": row.category,
            "severity": row.severity, "backend": row.backend, "source": row.source,
            "operator": row.operator, "created_at": iso_local(row.created_at),
            "expires_at": iso_local(row.expires_at),
            "released_at": iso_local(row.released_at),
            "active": row.active, "hits": row.hits, "dry_run": row.dry_run,
            "remaining_sec": remaining,
        }

    # ------------------------------------------------------------------ #
    # 内部
    # ------------------------------------------------------------------ #
    def _log_disposal(self, action: str, target: str, detail: str, operator: str, success: bool) -> None:
        try:
            with session_scope() as session:
                session.add(DisposalLog(action=action, target=target, detail=detail,
                                        operator=operator, success=success))
        except Exception:
            logger.debug("写入处置日志失败", exc_info=True)


