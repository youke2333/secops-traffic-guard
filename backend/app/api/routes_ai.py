"""AI 研判接口：流量窗口研判、模型状态。

* ``GET /ai/status``            模型可用性 + 三类研判（告警/流量/漏洞）的降级统计
* ``GET /ai/traffic/review``    对当前流量窗口做 AI 研判（只发聚合摘要；不可用时本地规则兜底）

说明：AI 结论是**建议**，不改变自动封禁判定（封禁仍由直达规则 + 严重度 + 白名单决定）。
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, Query

from ..collector.service import CollectorService
from .deps import service_dep

router = APIRouter(tags=["ai"])


@router.get("/ai/status", summary="AI 能力状态（模型 / 降级链 / 语料来源）")
def ai_status(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    return {
        "enabled": bool(service.settings.llm_enabled),
        "model": service.settings.llm_model if service.settings.llm_enabled else "",
        "client_available": service.traffic_advisor.client.available,
        "alert_analysis": service.enricher.chain.stats,
        "traffic_analysis": service.traffic_advisor.stats,
        "note": ("AI 不可用时自动降级为本地规则/模板/知识库，结果中 source 与 degraded 字段可见；"
                 "AI 结论不会直接触发封禁。"),
    }


@router.get("/ai/traffic/review", summary="AI 流量研判（窗口摘要 → 结论与建议）")
def traffic_review(window_minutes: int = Query(default=10, ge=1, le=1440),
                   service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    return service.ai_traffic_review(window_minutes)
