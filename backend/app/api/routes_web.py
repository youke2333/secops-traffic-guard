"""Web 攻击检测接口：知识库概览、运行统计、规则自测、外部请求投递。

* ``GET  /web/kb``        知识库概览（大类 + 规则清单，供页面展示与运维扩展对照）
* ``GET  /web/kb/{key}``  单个攻击大类的规则明细（含命中示例与修复建议）
* ``GET  /web/stats``     检测器运行统计（已分析请求数 / 各大类命中数 / 数据来源）
* ``POST /web/inspect``   单条请求「只检测不告警」体检（规则自测、WAF 联调）
* ``POST /web/requests``  批量投递请求，进入真实检测 → 告警 → 封禁闭环
"""

from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query

from ..collector.service import CollectorService
from ..schemas import ActionResult, WebRequestIn, WebRequestsIn
from .deps import require_token, service_dep

router = APIRouter(tags=["web-attack"])


@router.get("/web/kb", summary="Web 攻击知识库概览（17 大类 / 全部规则）")
def web_kb(detail: bool = Query(default=True, description="是否返回规则清单"),
           category: str = Query(default="", description="只看某个大类"),
           service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    kb = service.web_detector.kb
    categories = kb.public_categories()
    rules = kb.public_rules()
    if category:
        rules = [item for item in rules if item.get("category") == category]
    return {
        "stats": kb.stats,
        "categories": categories,
        "rules": rules if detail else [],
        "field_help": kb.field_help,
        "source": {"name": getattr(service.web_source, "name", "off") if service.web_source else "off",
                   "description": getattr(service.web_source, "description", "") if service.web_source else ""},
    }


@router.get("/web/kb/{key}", summary="单个攻击大类的规则明细与修复建议")
def web_kb_category(key: str, service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    kb = service.web_detector.kb
    category = kb.category(key)
    if not category:
        raise HTTPException(status_code=404, detail=f"未知攻击大类：{key}")
    rules = [item for item in kb.public_rules() if item.get("category") == key]
    return {
        "category": {**category, "rule_count": len(rules)},
        "rules": rules,
        "detected": service.web_detector.by_category.get(key, 0),
    }


@router.get("/web/stats", summary="Web 攻击检测运行统计")
def web_stats(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    return service.web_stats()


@router.post("/web/inspect", summary="请求体检（只检测不告警，用于规则自测与联调）")
def web_inspect(payload: WebRequestIn,
                service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    result = service.web_detector.inspect_dict(payload.model_dump(exclude_none=True))
    result["stats"] = service.web_detector.stats
    return result


@router.post("/web/requests", summary="批量投递 HTTP 请求（WAF/代理接入，走真实告警闭环）")
def web_requests(payload: WebRequestsIn, _: None = Depends(require_token),
                 service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    items = [item.model_dump(exclude_none=True) for item in payload.requests[:200]]
    alerts: List[Dict[str, Any]] = service.ingest_web_requests(items)
    return {
        "accepted": len(items),
        "alerts": alerts,
        "alert_count": len(alerts),
        "detector": service.web_detector.stats,
        "message": f"已投递 {len(items)} 条请求，产生 {len(alerts)} 条 Web 攻击告警",
    }


@router.post("/web/detect", response_model=ActionResult, summary="对单条请求立即检测并告警（同步）")
def web_detect(payload: WebRequestIn, _: None = Depends(require_token),
               service: CollectorService = Depends(service_dep)) -> ActionResult:
    alerts = service.ingest_web_requests([payload.model_dump(exclude_none=True)])
    return ActionResult(
        success=True,
        message=(f"已检测：产生 {len(alerts)} 条告警"
                 if alerts else "已检测：未命中任何 Web 攻击规则"),
        code="detected" if alerts else "clean",
        detail={"alerts": alerts},
    )
