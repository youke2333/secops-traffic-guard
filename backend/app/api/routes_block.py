"""封禁与白名单接口：自动封禁的可视化、人工解封、误报白名单、通道自检。"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select

from ..alerting.notifier import Notifier
from ..auth import audit
from ..database import session_scope
from ..models import BlockRule, DisposalLog, utcnow
from ..timeutil import iso_local
from ..response.blocker import Blocker
from ..schemas import ActionResult, BlockCreate, WhitelistCreate
from .deps import blocker_dep, notifier_dep, require_token

router = APIRouter(tags=["response"])


# ------------------------------------------------------------------ #
# 封禁
# ------------------------------------------------------------------ #
@router.get("/blocks", summary="封禁记录列表（大屏右侧表格数据源）")
def list_blocks(active_only: bool = Query(default=True),
                limit: int = Query(default=50, ge=1, le=500),
                blocker: Blocker = Depends(blocker_dep)) -> Dict[str, Any]:
    items = blocker.active_blocks(limit) if active_only else blocker.history(limit)
    return {"total": len(items), "items": items}


def _result_code(result: Dict[str, Any], success: bool) -> str:
    """把 Blocker 的返回值映射为语义化 code，方便调用方分支处理。"""
    if result.get("whitelisted"):
        return "whitelisted"
    if result.get("duplicated"):
        return "duplicated"
    return "ok" if success else "firewall_failed"


@router.post("/blocks", response_model=ActionResult, summary="手动封禁 IP")
def create_block(payload: BlockCreate, principal: dict = Depends(require_token),
                 blocker: Blocker = Depends(blocker_dep)) -> ActionResult:
    result = blocker.block(ip=payload.ip, reason=payload.reason, category=payload.category,
                           severity=payload.severity, ttl_sec=payload.ttl_sec,
                           source="manual", operator=payload.operator)
    success = bool(result.get("success"))
    audit("block", username=str(principal.get("username") or payload.operator),
          target=payload.ip, detail=f"manual ttl={payload.ttl_sec}s success={success}")
    return ActionResult(success=success, message=str(result.get("message")),
                        code=_result_code(result, success), detail=result)


@router.delete("/blocks/{ip}", response_model=ActionResult, summary="解封 IP（人工纠错入口）")
def delete_block(ip: str, operator: str = Query(default="admin"),
                 principal: dict = Depends(require_token),
                 blocker: Blocker = Depends(blocker_dep)) -> ActionResult:
    result = blocker.unblock(ip=ip, operator=operator, reason="人工解封")
    success = bool(result.get("success"))
    audit("unblock", username=str(principal.get("username") or operator), target=ip,
          detail=f"manual success={success}")
    return ActionResult(success=success, message=str(result.get("message")),
                        code="ok" if success else "firewall_failed", detail=result)


@router.post("/blocks/reap", response_model=ActionResult, summary="立即清理到期封禁")
def reap_blocks(_: None = Depends(require_token),
                blocker: Blocker = Depends(blocker_dep)) -> ActionResult:
    count = blocker.release_expired()
    return ActionResult(success=True, message=f"已释放 {count} 条到期封禁规则")


@router.post("/blocks/{ip}/extend", response_model=ActionResult, summary="延长封禁时长（续期）")
def extend_block(ip: str, ttl_sec: int = Query(default=1800, ge=60, le=86400),
                 operator: str = Query(default="admin"),
                 _: None = Depends(require_token),
                 blocker: Blocker = Depends(blocker_dep)) -> ActionResult:
    """续期是**累加**，不是重置。

    早期实现写成 ``expires_at = now + ttl``，连点几次"续期 30 分"，剩余时长永远
    重新回到 30:00（界面一直显示 29m59s 往下掉），用户会认为续期完全没生效。
    正确语义是在当前到期时间上叠加，次数越多剩余越久。
    """
    with session_scope() as session:
        rows = session.scalars(
            select(BlockRule).where(BlockRule.ip == ip, BlockRule.active.is_(True))
        ).all()
        if not rows:
            raise HTTPException(status_code=404, detail=f"{ip} 当前未被封禁，无法续期")
        if all(row.expires_at is None for row in rows):
            return ActionResult(success=False, message=f"{ip} 为永久封禁，无需续期",
                                code="permanent")

        now = utcnow()
        # 同一 IP 可能有多条生效规则，取最晚的到期时间作为累加基准
        latest = max((row.expires_at for row in rows if row.expires_at is not None), default=now)
        base = max(latest, now)          # 已过期但尚未被清理的记录，从当前时间重新起算
        expires_at = base + timedelta(seconds=ttl_sec)
        remaining_sec = int((expires_at - now).total_seconds())
        for row in rows:
            row.expires_at = expires_at
        session.add(DisposalLog(
            action="extend", target=ip,
            detail=f"封禁续期 +{ttl_sec}s，累计剩余 {remaining_sec}s（原因：{rows[0].reason}）",
            operator=operator, success=True,
        ))

    # nftables 的集合元素带内核 timeout，只改数据库会导致"控制台仍封禁、内核已放行"；
    # iptables 规则无 TTL，由数据库到期清理，无需重复下发（-I 会插出重复规则）。
    fw_ok, fw_message = blocker.extend_ttl(ip, remaining_sec)
    return ActionResult(
        success=bool(fw_ok),
        message=(f"{ip} 已续期 +{ttl_sec} 秒，累计剩余 {remaining_sec} 秒" if fw_ok
                 else f"{ip} 到期时间已更新，但防火墙同步失败：{fw_message}"),
        code="extended" if fw_ok else "firewall_failed",
        detail={"expires_at": iso_local(expires_at), "ttl_sec": ttl_sec,
                "remaining_sec": remaining_sec, "firewall": fw_message},
    )


# ------------------------------------------------------------------ #
# 白名单
# ------------------------------------------------------------------ #
@router.get("/whitelist", summary="白名单列表")
def list_whitelist(blocker: Blocker = Depends(blocker_dep)) -> Dict[str, Any]:
    entries = blocker.whitelist.entries()
    return {"total": len(entries), "items": entries}


@router.post("/whitelist", response_model=ActionResult, summary="新增白名单（支持 CIDR）")
def add_whitelist(payload: WhitelistCreate, _: None = Depends(require_token),
                  blocker: Blocker = Depends(blocker_dep)) -> ActionResult:
    ok = blocker.whitelist.add(payload.cidr, payload.note, payload.operator)
    return ActionResult(success=ok, message=f"白名单 {payload.cidr} " + ("已添加" if ok else "已存在或非法"))


@router.delete("/whitelist/{cidr:path}", response_model=ActionResult, summary="移除白名单")
def remove_whitelist(cidr: str, operator: str = Query(default="admin"),
                     _: None = Depends(require_token),
                     blocker: Blocker = Depends(blocker_dep)) -> ActionResult:
    if blocker.whitelist.remove(cidr, operator):
        return ActionResult(success=True, message=f"白名单 {cidr} 已移除")
    raise HTTPException(status_code=404, detail="白名单不存在，或该项为系统内置不可删除")


# ------------------------------------------------------------------ #
# 告警通道自检
# ------------------------------------------------------------------ #
@router.get("/notify/channels", summary="告警通道状态")
def notify_channels(notifier: Notifier = Depends(notifier_dep)) -> Dict[str, Any]:
    return {"channels": [channel.name for channel in notifier.channels],
            "stats": notifier.stats,
            "history": notifier.history(10)}


@router.post("/notify/test", response_model=ActionResult, summary="发送一条测试告警")
def notify_test(_: None = Depends(require_token),
                notifier: Notifier = Depends(notifier_dep)) -> ActionResult:
    result = notifier.test()
    success = any(bool(item.get("ok")) for item in result["results"].values()) if result["results"] else False
    return ActionResult(success=success, message="通道自检完成，详见 detail", detail=result)
