"""FastAPI 应用入口。

启动流程：
1. 建表（幂等）→ 2. 启动采集/检测/响应编排服务 → 3. 挂载 REST + SSE 路由 → 4. 托管大屏静态文件。

v2 追加的后台任务（均为守护型，随应用生命周期启停）：
* 规则热加载循环（`RULE_RELOAD_INTERVAL_SEC`，0=关闭）；
* 自适应阈值重算循环（`THRESHOLD_RECOMPUTE_INTERVAL_SEC`，可用 `ADAPTIVE_AUTO_RECOMPUTE=false` 关闭）。
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .api import (
    routes_ai,
    routes_alert,
    routes_asset,
    routes_auth,
    routes_block,
    routes_metrics,
    routes_rules,
    routes_reports,
    routes_thresholds,
    routes_threat,
    routes_web,
)
from .auth.middleware import AuthMiddleware
from .auth.sessions import ensure_initial_admin
from .collector.service import get_service
from .config import get_settings
from .database import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
)
logger = logging.getLogger("secops.main")


async def _rule_reload_loop(interval_sec: int) -> None:
    """周期性热加载规则（运维只放文件即可生效，无需重启）。"""
    from .rules import get_registry

    while True:
        await asyncio.sleep(max(30, interval_sec))
        try:
            await asyncio.to_thread(get_registry().reload)
        except Exception:      # pragma: no cover - 后台任务不应中断
            logger.exception("规则热加载失败")


async def _threshold_recompute_loop(interval_sec: int) -> None:
    """周期性重算自适应阈值（从 /alerts 人工反馈里学习误报率）。"""
    service = get_service()
    while True:
        await asyncio.sleep(max(60, interval_sec))
        try:
            await asyncio.to_thread(service.engine.adaptive.recompute)
        except Exception:      # pragma: no cover
            logger.exception("自适应阈值重算失败")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    init_db()
    logger.info("数据库初始化完成：%s", settings.db_url)
    if settings.auth_enabled:
        ensure_initial_admin(settings)
        logger.info("登录鉴权已启用（会话 %ss / 空闲 %ss）",
                    settings.session_ttl_sec, settings.session_idle_sec)
    else:
        logger.warning("AUTH_ENABLED=false：全站免登录，仅建议内网应急使用")
    service = get_service()
    service.start()
    logger.info("采集服务已启动：mode=%s，大屏目录=%s", service.capture_mode, settings.dashboard_path)
    tasks: List[asyncio.Task] = []
    if settings.rule_reload_interval_sec > 0:
        tasks.append(asyncio.create_task(
            _rule_reload_loop(settings.rule_reload_interval_sec), name="rule-reload"))
    if settings.adaptive_threshold_enabled and settings.adaptive_auto_recompute:
        tasks.append(asyncio.create_task(
            _threshold_recompute_loop(settings.threshold_recompute_interval_sec),
            name="threshold-recompute"))
    try:
        yield
    finally:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        service.stop()
        logger.info("服务已停止")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="轻量级本地化部署的智能流量安全检测与分析系统：实时监控、异常检测、自动封禁、漏洞提醒、资产管理。",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # 登录守卫先加入，CORS 后加入 => CORS 位于最外层，401/403 响应同样带 CORS 头。
    app.add_middleware(AuthMiddleware, settings=settings)
    origins = [item.strip() for item in settings.cors_origins.split(",") if item.strip()] or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if origins != ["*"] else ["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    prefix = "/api/v1"
    app.include_router(routes_auth.router, prefix=prefix)
    app.include_router(routes_metrics.router, prefix=prefix)
    app.include_router(routes_alert.router, prefix=prefix)
    app.include_router(routes_block.router, prefix=prefix)
    app.include_router(routes_asset.router, prefix=prefix)
    app.include_router(routes_web.router, prefix=prefix)
    app.include_router(routes_rules.router, prefix=prefix)
    app.include_router(routes_thresholds.router, prefix=prefix)
    app.include_router(routes_threat.router, prefix=prefix)
    app.include_router(routes_reports.router, prefix=prefix)
    app.include_router(routes_ai.router, prefix=prefix)

    @app.get("/api", include_in_schema=False)
    def api_index() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    dashboard = settings.dashboard_path
    if dashboard.exists():
        app.mount("/", StaticFiles(directory=str(dashboard), html=True), name="dashboard")
        logger.info("已挂载大屏静态目录：%s", dashboard)
    else:  # pragma: no cover - 未部署前端时
        @app.get("/", include_in_schema=False)
        def missing_dashboard() -> dict:
            return {"message": "未找到 dashboard 目录，请先部署前端大屏", "api_docs": "/docs"}

    return app


app = create_app()
