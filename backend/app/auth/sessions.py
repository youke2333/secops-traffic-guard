"""用户认证、服务端会话与审计落库。"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import timedelta
from typing import Any, Dict, Optional

from sqlalchemy import delete, func, select

from ..config import Settings, get_settings
from ..database import session_scope
from ..models import AuditLog, User, UserSession, utcnow
from .passwords import generate_password, hash_password, password_is_strong, verify_password

logger = logging.getLogger(__name__)

SESSION_COOKIE = "secops_sid"
ROLES = ("admin", "analyst", "viewer")


def _token_hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _user_dict(user: User) -> Dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "display_name": user.display_name or user.username,
        "active": bool(user.active),
        "must_change_password": bool(user.must_change_password),
    }


def audit(action: str, *, username: str = "", user_id: Optional[int] = None,
          target: str = "", detail: str = "", ip: str = "", success: bool = True) -> None:
    """写审计日志；审计失败不能影响业务动作。"""
    try:
        with session_scope() as session:
            session.add(AuditLog(
                action=action, username=username or "", user_id=user_id,
                target=target or "", detail=(detail or "")[:4000],
                ip=ip or "", success=bool(success),
            ))
    except Exception:      # pragma: no cover - 审计失败只记录日志
        logger.exception("审计日志写入失败：action=%s user=%s", action, username)


def ensure_initial_admin(settings: Optional[Settings] = None) -> Optional[str]:
    """无用户时创建 admin；返回生成的初始密码（仅当未显式配置时）。"""
    cfg = settings or get_settings()
    with session_scope() as session:
        count = int(session.scalar(select(func.count(User.id))) or 0)
        if count:
            return None
        configured = str(cfg.admin_initial_password or "")
        generated: Optional[str] = None
        if password_is_strong(configured, "admin", cfg.password_min_len):
            password = configured
        else:
            password = generate_password(16)
            generated = password
            if configured:
                logger.warning("ADMIN_INITIAL_PASSWORD 不满足强度要求，已改用随机初始密码")
        session.add(User(
            username="admin",
            password_hash=hash_password(password),
            role="admin",
            display_name="系统管理员",
            active=True,
            must_change_password=True,
            created_at=utcnow(),
        ))
    if generated:
        logger.warning("=" * 72)
        logger.warning("首次启动已创建管理员 admin，一次性密码：%s", generated)
        logger.warning("请登录后立即修改密码；本密码只在本次启动日志中出现。")
        logger.warning("=" * 72)
    else:
        logger.info("首次启动已创建管理员 admin（密码来自 ADMIN_INITIAL_PASSWORD）")
    audit("user_init", username="system", target="admin", detail="创建初始管理员")
    return generated


def authenticate(username: str, password: str, *, ip: str = "", user_agent: str = "",
                 settings: Optional[Settings] = None) -> tuple[Optional[Dict[str, Any]], str]:
    """验证账号密码；返回 (用户信息, 错误码)。错误码不泄露账号是否存在。

    注意：审计写入放在本事务提交之后，避免 SQLite 在写事务未结束时出现锁等待。
    """
    cfg = settings or get_settings()
    name = str(username or "").strip()
    result: Optional[Dict[str, Any]] = None
    code = "invalid_credentials"
    detail = ""
    user_id: Optional[int] = None
    with session_scope() as session:
        user = session.scalar(select(User).where(User.username == name))
        now = utcnow()
        if user is None:
            detail = "账号不存在"
        else:
            user_id = user.id
            if not user.active:
                code, detail = "disabled", "账号已禁用"
            elif user.locked_until and user.locked_until > now:
                code = "locked"
                detail = f"账号锁定中，剩余 {int((user.locked_until - now).total_seconds())}s"
            elif not verify_password(password, user.password_hash):
                user.failed_count = int(user.failed_count or 0) + 1
                if user.failed_count >= int(cfg.login_max_fails):
                    user.locked_until = now + timedelta(seconds=int(cfg.login_lock_sec))
                    user.failed_count = 0
                    logger.warning("账号 %s 连续失败达到阈值，已锁定 %ss", name, cfg.login_lock_sec)
                session.add(user)
                detail = "密码错误"
            else:
                user.failed_count = 0
                user.locked_until = None
                user.last_login_at = now
                session.add(user)
                code, detail = "ok", "登录成功"
                result = _user_dict(user)

    audit("login", username=name, user_id=user_id, ip=ip, success=(code == "ok"), detail=detail)
    return result, code


def create_session(user_id: int, *, ip: str = "", user_agent: str = "",
                   settings: Optional[Settings] = None) -> Dict[str, Any]:
    """创建会话；返回仅此一次的明文 token 与 CSRF token。"""
    cfg = settings or get_settings()
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(24)
    now = utcnow()
    expires_at = now + timedelta(seconds=int(cfg.session_ttl_sec))
    with session_scope() as session:
        session.add(UserSession(
            token_hash=_token_hash(token), user_id=int(user_id),
            csrf_token=csrf_token, created_at=now, last_seen_at=now,
            expires_at=expires_at, ip=ip or "", user_agent=(user_agent or "")[:255],
        ))
    return {"token": token, "csrf_token": csrf_token, "expires_at": expires_at.isoformat()}


def resolve_session(token: str, *, settings: Optional[Settings] = None) -> Optional[Dict[str, Any]]:
    """校验会话并刷新活跃时间；无效/过期返回 None。"""
    if not token:
        return None
    cfg = settings or get_settings()
    now = utcnow()
    with session_scope() as session:
        row = session.get(UserSession, _token_hash(token))
        if row is None:
            return None
        if row.expires_at <= now or (now - row.last_seen_at).total_seconds() > int(cfg.session_idle_sec):
            session.delete(row)
            return None
        user = session.get(User, row.user_id)
        if user is None or not user.active:
            session.delete(row)
            return None
        if (now - row.last_seen_at).total_seconds() >= 60:
            row.last_seen_at = now
            session.add(row)
        return {
            **_user_dict(user),
            "csrf_token": row.csrf_token,
            "session_hash": row.token_hash,
            "via": "session",
        }


def revoke_session(token: str) -> None:
    if not token:
        return
    with session_scope() as session:
        session.execute(delete(UserSession).where(UserSession.token_hash == _token_hash(token)))


def revoke_user_sessions(user_id: int, except_hash: str = "") -> int:
    with session_scope() as session:
        statement = delete(UserSession).where(UserSession.user_id == int(user_id))
        if except_hash:
            statement = statement.where(UserSession.token_hash != except_hash)
        result = session.execute(statement)
        return int(result.rowcount or 0)


def purge_expired_sessions(settings: Optional[Settings] = None) -> int:
    cfg = settings or get_settings()
    now = utcnow()
    idle_cutoff = now - timedelta(seconds=int(cfg.session_idle_sec))
    with session_scope() as session:
        result = session.execute(delete(UserSession).where(
            (UserSession.expires_at <= now) | (UserSession.last_seen_at <= idle_cutoff)
        ))
        return int(result.rowcount or 0)

