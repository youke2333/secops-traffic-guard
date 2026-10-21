"""依赖注入与鉴权。

鉴权策略（v6 P0）：
* ``AUTH_ENABLED=true``（默认）：浏览器走服务端会话 + CSRF；机器调用走 ``X-API-Token``；
* ``AUTH_ENABLED=false``：退回 v2 行为，仅当配置了 ``API_TOKEN`` 时校验写接口（应急降级）。
"""

from __future__ import annotations

import hmac
from typing import Callable, Optional

from fastapi import Depends, Header, HTTPException, Request, status

from ..alerting.notifier import Notifier
from ..auth.middleware import principal_from_request
from ..collector.service import CollectorService, get_service
from ..config import Settings, get_settings
from ..response.blocker import Blocker
from ..scanner.assets import AssetManager
from ..scanner.vulnerability import VulnerabilityScanner

_settings: Optional[Settings] = None
_scanner: Optional[VulnerabilityScanner] = None
_assets: Optional[AssetManager] = None

ROLE_ORDER = {"viewer": 1, "analyst": 2, "admin": 3}


def settings_dep() -> Settings:
    return get_settings()


def service_dep() -> CollectorService:
    return get_service()


def blocker_dep(service: CollectorService = Depends(service_dep)) -> Blocker:
    return service.blocker


def notifier_dep(service: CollectorService = Depends(service_dep)) -> Notifier:
    return service.notifier


def assets_dep(service: CollectorService = Depends(service_dep)) -> AssetManager:
    return service.assets


def scanner_dep(service: CollectorService = Depends(service_dep)) -> VulnerabilityScanner:
    """扫描器懒加载：CVE 知识库只在第一次调用时读取。"""
    global _scanner
    if _scanner is None:
        _scanner = VulnerabilityScanner(get_settings(), assets=service.assets)
    return _scanner


def require_scan_enabled(settings: Settings = Depends(settings_dep)) -> None:
    """主动扫描总开关：``SCANNER_ENABLED=false`` 时拒绝一切对外探测。

    关掉它的场景：生产环境不允许本机向业务网段发起连接，只保留被动学习与流量研判。
    """
    if not settings.scanner_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="主动扫描已关闭（SCANNER_ENABLED=false）")


def require_auth(request: Request, settings: Settings = Depends(settings_dep)) -> dict:
    """要求登录（会话或 API Token）；返回当前身份。"""
    principal = principal_from_request(request, settings)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="未登录或会话已过期，请先登录")
    return principal


def require_role(*roles: str) -> Callable[..., dict]:
    """角色依赖工厂：``Depends(require_role("admin"))``。"""
    allowed = set(roles)

    def dependency(request: Request, settings: Settings = Depends(settings_dep)) -> dict:
        principal = principal_from_request(request, settings)
        if principal is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="未登录或会话已过期，请先登录")
        role = str(principal.get("role") or "viewer")
        if role not in allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"权限不足：需要 {'/'.join(sorted(allowed))} 角色")
        return principal

    return dependency


def require_token(request: Request,
                  x_api_token: str = Header(default="", alias="X-API-Token"),
                  settings: Settings = Depends(settings_dep)) -> dict:
    """写操作鉴权（兼容旧接口）。

    * 开启登录后：有效会话（analyst/admin）或有效 API Token 均可；
    * 关闭登录后：沿用“配置了 API_TOKEN 就必须匹配”的旧规则。
    """
    if settings.auth_enabled:
        principal = principal_from_request(request, settings)
        if principal is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="未登录或会话已过期，请先登录")
        if ROLE_ORDER.get(str(principal.get("role")), 0) < ROLE_ORDER["analyst"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="只读角色不能执行该操作")
        return principal

    if settings.api_token and not hmac.compare_digest(
            x_api_token.encode("utf-8"), str(settings.api_token).encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="无效的 API Token，请在请求头携带 X-API-Token")
    return {"username": "anonymous", "role": "admin", "via": "disabled"}

