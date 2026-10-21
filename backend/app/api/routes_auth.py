"""登录、用户管理与审计查询接口（v6 P0）。"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..auth import (
    SESSION_COOKIE,
    audit,
    authenticate,
    create_session,
    hash_password,
    password_is_strong,
    revoke_session,
    revoke_user_sessions,
)
from ..auth.passwords import generate_password, verify_password
from ..config import Settings, get_settings
from ..database import session_scope
from ..models import AuditLog, User, utcnow
from ..timeutil import iso_local
from ..schemas import ActionResult
from .deps import require_auth, require_role, settings_dep

router = APIRouter(tags=["auth"])

_FAILURES: Dict[str, deque] = defaultdict(deque)
_FAIL_WINDOW_SEC = 60
_FAIL_MAX_PER_IP = 5


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordIn(BaseModel):
    current_password: str = Field(default="", max_length=256)
    new_password: str = Field(min_length=8, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")
    display_name: str = Field(default="", max_length=128)


class UserUpdate(BaseModel):
    role: Optional[str] = Field(default=None, pattern="^(admin|analyst|viewer)$")
    active: Optional[bool] = None
    display_name: Optional[str] = Field(default=None, max_length=128)


def _client_ip(request: Request) -> str:
    return str(request.client.host if request.client else "")


def _rate_limited(ip: str) -> bool:
    bucket = _FAILURES[ip]
    cutoff = time.time() - _FAIL_WINDOW_SEC
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    return len(bucket) >= _FAIL_MAX_PER_IP


def _remember_failure(ip: str) -> None:
    _FAILURES[ip].append(time.time())


def _clear_failures(ip: str) -> None:
    _FAILURES.pop(ip, None)


def _set_cookie(response: Response, token: str, cfg: Settings) -> None:
    response.set_cookie(
        key=SESSION_COOKIE, value=token, max_age=int(cfg.session_ttl_sec),
        httponly=True, samesite="lax", secure=bool(cfg.cookie_secure), path="/",
    )


def _guard_last_admin(session, user: User, *, role: Optional[str] = None,
                      active: Optional[bool] = None) -> None:
    """禁止把最后一个启用中的 admin 降级或停用（避免系统失去管理入口）。"""
    if not (user.role == "admin" and bool(user.active)):
        return
    new_role = role if role is not None else user.role
    new_active = bool(active) if active is not None else bool(user.active)
    if new_role == "admin" and new_active:
        return
    remaining = session.scalar(
        select(func.count(User.id)).where(
            User.id != user.id, User.role == "admin", User.active.is_(True),
        )
    )
    if int(remaining or 0) == 0:
        raise HTTPException(status_code=400, detail="至少保留一个启用的 admin 账号")


@router.post("/auth/login", summary="登录（下发会话 Cookie 与 CSRF Token）")
def login(payload: LoginIn, request: Request, response: Response,
          settings: Settings = Depends(settings_dep)) -> Dict[str, Any]:
    ip = _client_ip(request)
    if _rate_limited(ip):
        audit("login", username=payload.username, ip=ip, success=False, detail="IP 登录频率超限")
        raise HTTPException(status_code=429, detail="登录尝试过于频繁，请 1 分钟后再试")
    user, code = authenticate(
        payload.username, payload.password, ip=ip,
        user_agent=request.headers.get("user-agent", ""), settings=settings,
    )
    if user is None:
        _remember_failure(ip)
        message = {
            "locked": "账号已临时锁定，请稍后再试或联系管理员",
            "disabled": "账号已被禁用，请联系管理员",
        }.get(code, "用户名或密码错误")
        raise HTTPException(status_code=401, detail=message)
    _clear_failures(ip)
    session = create_session(
        int(user["id"]), ip=ip, user_agent=request.headers.get("user-agent", ""), settings=settings,
    )
    _set_cookie(response, session["token"], settings)
    return {
        "success": True,
        "user": user,
        "csrf_token": session["csrf_token"],
        "expires_at": session["expires_at"],
        "must_change_password": bool(user.get("must_change_password")),
        "auth_enabled": bool(settings.auth_enabled),
    }


@router.post("/auth/logout", response_model=ActionResult, summary="注销当前会话")
def logout(request: Request, response: Response,
           principal: dict = Depends(require_auth)) -> ActionResult:
    token = request.cookies.get(SESSION_COOKIE, "")
    revoke_session(token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    audit("logout", username=str(principal.get("username") or ""),
          user_id=principal.get("id"), ip=_client_ip(request))
    return ActionResult(success=True, message="已退出登录", code="logged_out")


@router.get("/auth/me", summary="当前登录用户、角色与 CSRF Token")
def me(principal: dict = Depends(require_auth),
       settings: Settings = Depends(settings_dep)) -> Dict[str, Any]:
    return {
        "user": principal,
        "csrf_token": principal.get("csrf_token") or "",
        "auth_enabled": bool(settings.auth_enabled),
        "role": principal.get("role"),
    }


@router.post("/auth/password", response_model=ActionResult, summary="修改自己的密码")
def change_password(payload: PasswordIn, request: Request,
                    principal: dict = Depends(require_auth),
                    settings: Settings = Depends(settings_dep)) -> ActionResult:
    if principal.get("via") != "session":
        raise HTTPException(status_code=403, detail="请使用浏览器登录后修改密码")
    if not password_is_strong(payload.new_password, str(principal.get("username") or ""),
                              settings.password_min_len):
        raise HTTPException(
            status_code=400,
            detail=f"新密码至少 {settings.password_min_len} 位，且必须同时包含字母与数字，不能与用户名相同",
        )
    with session_scope() as session:
        user = session.get(User, int(principal["id"]))
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        if not verify_password(payload.current_password, user.password_hash):
            raise HTTPException(status_code=400, detail="当前密码不正确")
        user.password_hash = hash_password(payload.new_password)
        user.must_change_password = False
        session.add(user)
    revoked = revoke_user_sessions(int(principal["id"]),
                                   except_hash=str(principal.get("session_hash") or ""))
    audit("password_change", username=str(principal.get("username") or ""),
          user_id=principal.get("id"), ip=_client_ip(request),
          detail=f"修改密码，踢出其它会话 {revoked} 个")
    return ActionResult(success=True, message="密码已修改", code="password_changed",
                        detail={"revoked_sessions": revoked})



@router.get("/users", summary="用户列表（admin）")
def list_users(principal: dict = Depends(require_role("admin"))) -> Dict[str, Any]:
    with session_scope() as session:
        rows = session.scalars(select(User).order_by(User.id)).all()
        items = [{
            "id": row.id, "username": row.username, "role": row.role,
            "display_name": row.display_name, "active": bool(row.active),
            "must_change_password": bool(row.must_change_password),
            "failed_count": row.failed_count,
            "locked_until": iso_local(row.locked_until),
            "created_at": iso_local(row.created_at),
            "last_login_at": iso_local(row.last_login_at),
        } for row in rows]
    return {"total": len(items), "items": items}


@router.post("/users", response_model=ActionResult, summary="新建用户（admin）")
def create_user(payload: UserCreate, request: Request,
                principal: dict = Depends(require_role("admin")),
                settings: Settings = Depends(settings_dep)) -> ActionResult:
    username = payload.username.strip()
    if len(username) < 2:
        raise HTTPException(status_code=400, detail="用户名至少 2 个字符，且不能只包含空白")
    if not all(ch.isalnum() or ch in "_.@-" for ch in username):
        raise HTTPException(
            status_code=400,
            detail="用户名仅支持中文、字母、数字、下划线、点、@ 和 -，不能包含空格或控制字符",
        )
    if not password_is_strong(payload.password, username, settings.password_min_len):
        raise HTTPException(
            status_code=400,
            detail=f"密码至少 {settings.password_min_len} 位，且必须同时包含字母与数字，不能与用户名相同",
        )
    with session_scope() as session:
        exists = session.scalar(select(User).where(User.username == username))
        if exists:
            raise HTTPException(status_code=409, detail="用户名已存在")
        row = User(
            username=username, password_hash=hash_password(payload.password),
            role=payload.role, display_name=payload.display_name or username,
            active=True, must_change_password=True, created_at=utcnow(),
        )
        session.add(row)
        session.flush()
        user_id = row.id
    audit("user_create", username=str(principal.get("username") or ""),
          user_id=principal.get("id"), target=username, ip=_client_ip(request),
          detail=f"role={payload.role}")
    return ActionResult(success=True, message=f"用户 {username} 已创建",
                        code="created", detail={"id": user_id})


@router.patch("/users/{user_id}", response_model=ActionResult, summary="修改角色/启用状态（admin）")
def update_user(user_id: int, payload: UserUpdate, request: Request,
                principal: dict = Depends(require_role("admin"))) -> ActionResult:
    if int(principal.get("id") or 0) == user_id and payload.active is False:
        raise HTTPException(status_code=400, detail="不能禁用当前登录账号")
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        _guard_last_admin(session, user, role=payload.role, active=payload.active)
        if payload.role is not None:
            user.role = payload.role
        if payload.active is not None:
            user.active = bool(payload.active)
        if payload.display_name is not None:
            user.display_name = payload.display_name
        session.add(user)
    if payload.active is False or payload.role is not None:
        revoke_user_sessions(user_id)
    audit("user_update", username=str(principal.get("username") or ""),
          user_id=principal.get("id"), target=str(user_id), ip=_client_ip(request),
          detail=payload.model_dump_json())
    return ActionResult(success=True, message="用户已更新", code="updated")



@router.delete("/users/{user_id}", response_model=ActionResult, summary="停用用户（admin，不物理删除）")
def delete_user(user_id: int, request: Request,
                principal: dict = Depends(require_role("admin"))) -> ActionResult:
    if int(principal.get("id") or 0) == user_id:
        raise HTTPException(status_code=400, detail="不能停用当前登录账号")
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        _guard_last_admin(session, user, active=False)
        user.active = False
        session.add(user)
    revoke_user_sessions(user_id)
    audit("user_disable", username=str(principal.get("username") or ""),
          user_id=principal.get("id"), target=str(user_id), ip=_client_ip(request))
    return ActionResult(success=True, message="用户已停用（记录保留以便审计）", code="disabled")


@router.post("/users/{user_id}/reset-password", response_model=ActionResult,
             summary="重置密码（admin，返回一次性新密码）")
def reset_password(user_id: int, request: Request,
                   principal: dict = Depends(require_role("admin")),
                   settings: Settings = Depends(settings_dep)) -> ActionResult:
    temporary = generate_password(16)
    with session_scope() as session:
        user = session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="用户不存在")
        user.password_hash = hash_password(temporary)
        user.must_change_password = True
        user.failed_count = 0
        user.locked_until = None
        username = user.username
        session.add(user)
    revoke_user_sessions(user_id)
    audit("password_reset", username=str(principal.get("username") or ""),
          user_id=principal.get("id"), target=username, ip=_client_ip(request))
    return ActionResult(success=True, message=f"{username} 密码已重置，请安全转交",
                        code="password_reset", detail={"username": username,
                                                       "temporary_password": temporary})


@router.get("/audit-logs", summary="审计日志（admin）")
def list_audit_logs(action: str = Query(default=""),
                    username: str = Query(default=""),
                    limit: int = Query(default=100, ge=1, le=1000),
                    principal: dict = Depends(require_role("admin"))) -> Dict[str, Any]:
    statement = select(AuditLog)
    if action:
        statement = statement.where(AuditLog.action == action)
    if username:
        statement = statement.where(AuditLog.username == username)
    statement = statement.order_by(AuditLog.ts.desc()).limit(limit)
    with session_scope() as session:
        rows = session.scalars(statement).all()
        total = int(session.scalar(select(func.count(AuditLog.id))) or 0)
        items = [{
            "id": row.id, "ts": iso_local(row.ts),
            "username": row.username, "action": row.action, "target": row.target,
            "detail": row.detail, "ip": row.ip, "success": bool(row.success),
        } for row in rows]
    return {"total": total, "items": items}

