"""全站登录守卫与 CSRF 校验中间件（v6 P0）。

规则：
* ``AUTH_ENABLED=false`` 时完全放行（应急降级，仅建议内网使用）；
* API：除 ``/health``、``/auth/login`` 外必须携带有效会话 Cookie 或 ``X-API-Token``；
* 页面：除登录页与静态资源外，未登录一律 302 到 ``/login.html``；
* 浏览器会话发起写请求时必须带 ``X-CSRF-Token``；机器 Token 调用不受 CSRF 限制。
"""

from __future__ import annotations

import hmac
import logging
from typing import Optional
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from ..config import Settings, get_settings
from .sessions import SESSION_COOKIE, resolve_session

logger = logging.getLogger(__name__)

PUBLIC_API_PATHS = {"/api/v1/health", "/api/v1/auth/login"}
PASSWORD_CHANGE_PATHS = {
    "/api/v1/auth/me", "/api/v1/auth/password", "/api/v1/auth/logout",
    "/api/v1/health", "/api/v1/auth/login",
}
PUBLIC_ASSET_PREFIXES = (
    "/login.html", "/css/", "/js/", "/img/", "/lib/", "/favicon.ico",
)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _is_api(path: str) -> bool:
    return path.startswith("/api/")


def _is_public_asset(path: str) -> bool:
    return any(path == item or path.startswith(item) for item in PUBLIC_ASSET_PREFIXES)


def principal_from_request(request: Request,
                           settings: Optional[Settings] = None) -> Optional[dict]:
    """从 request.state / Cookie / X-API-Token 解析当前身份（依赖与中间件共用）。"""
    cached = getattr(request.state, "principal", None)
    if cached:
        return cached
    cfg = settings or get_settings()
    if not cfg.auth_enabled:
        return {"username": "anonymous", "role": "admin", "display_name": "免认证",
                "must_change_password": False, "csrf_token": "", "via": "disabled"}

    token = (request.headers.get("x-api-token") or "").strip()
    if token and cfg.api_token and hmac.compare_digest(
            token.encode("utf-8"), str(cfg.api_token).encode("utf-8")):
        principal = {"id": None, "username": "api-token", "role": "admin",
                     "display_name": "API Token", "must_change_password": False,
                     "csrf_token": "", "via": "api_token"}
        request.state.principal = principal
        return principal

    sid = request.cookies.get(SESSION_COOKIE, "")
    principal = resolve_session(sid, settings=cfg) if sid else None
    if principal:
        request.state.principal = principal
    return principal


class AuthMiddleware(BaseHTTPMiddleware):
    """登录守卫：未登录 API 返回 401，未登录页面跳转登录页。"""

    def __init__(self, app: ASGIApp, settings: Optional[Settings] = None) -> None:
        super().__init__(app)
        self.settings = settings or get_settings()

    async def dispatch(self, request: Request, call_next):
        cfg = self.settings
        if not cfg.auth_enabled:
            request.state.principal = {
                "username": "anonymous", "role": "admin", "display_name": "免认证",
                "must_change_password": False, "csrf_token": "", "via": "disabled",
            }
            return await call_next(request)

        path = request.url.path or "/"
        method = request.method.upper()

        if method == "OPTIONS" or _is_public_asset(path) or path in PUBLIC_API_PATHS:
            return await call_next(request)

        if _is_api(path):
            principal = principal_from_request(request, cfg)
            if principal is None:
                return JSONResponse(
                    {"detail": "未登录或会话已过期，请先登录", "code": "auth_required"},
                    status_code=401,
                )
            if principal.get("must_change_password") and path not in PASSWORD_CHANGE_PATHS:
                return JSONResponse(
                    {"detail": "首次登录必须修改密码后才能使用系统",
                     "code": "password_change_required"},
                    status_code=403,
                )
            if method not in SAFE_METHODS and principal.get("via") == "session":
                supplied = (request.headers.get("x-csrf-token") or "").strip()
                if not supplied or supplied != principal.get("csrf_token"):
                    return JSONResponse(
                        {"detail": "CSRF 校验失败，请刷新页面后重试", "code": "csrf_failed"},
                        status_code=403,
                    )
            return await call_next(request)

        # 页面与其它静态资源：需要会话；API Token 不适用于浏览器页面
        principal = principal_from_request(request, cfg)
        if principal is None:
            target = request.url.path or "/"
            if request.url.query:
                target += "?" + request.url.query
            return RedirectResponse(
                url=f"/login.html?next={quote(target, safe='')}", status_code=302
            )
        if principal.get("must_change_password") and path not in {"/login.html"}:
            return RedirectResponse(url="/login.html?next=%2F", status_code=302)
        return await call_next(request)
