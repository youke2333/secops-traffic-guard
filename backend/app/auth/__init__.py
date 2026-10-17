"""登录、会话与审计（v6 P0）。

设计取舍：
* 使用**服务端会话**而不是 JWT：需要“立即踢下线/改角色即生效”，服务端会话更直接；
* Cookie 只保存随机 token，数据库保存 sha256(token)，库泄露也不能直接复用会话；
* 密码使用标准库 scrypt，避免引入额外依赖；
* 机器调用继续支持 ``X-API-Token``，浏览器使用会话 + CSRF。
"""

from .passwords import hash_password, verify_password, password_is_strong
from .sessions import (
    SESSION_COOKIE,
    audit,
    authenticate,
    create_session,
    ensure_initial_admin,
    resolve_session,
    revoke_session,
    revoke_user_sessions,
)

__all__ = [
    "SESSION_COOKIE",
    "audit",
    "authenticate",
    "create_session",
    "ensure_initial_admin",
    "hash_password",
    "password_is_strong",
    "resolve_session",
    "revoke_session",
    "revoke_user_sessions",
    "verify_password",
]
