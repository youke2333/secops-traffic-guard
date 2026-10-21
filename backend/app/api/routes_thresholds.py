"""阈值管理接口（方案第 3 层交付项）。

* ``GET   /thresholds``                     维度化阈值清单（含样本数 / 误报率 / 是否人工覆盖）
* ``GET   /thresholds/static``              静态基准与上下限（前端面板顶部展示）
* ``GET   /thresholds/{dimension}/{key}``   查询单个维度
* ``POST  /thresholds/recompute``           手动触发重算（等价于后台定时任务）
* ``PATCH /thresholds/{id}``                人工覆盖（置 manual_override=True，自动重算将跳过）

注意：**直达机制不参与自适应调整**（`direct_alert` 与 `DIRECT_ALERT_WEIGHT` 均为固定配置），
详见 `detection/adaptive_threshold.py` 的模块注释。
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ..collector.service import CollectorService
from ..detection.adaptive_threshold import AdaptiveThresholdManager
from ..schemas import ActionResult, ThresholdOverride
from .deps import require_token, service_dep

router = APIRouter(tags=["thresholds"])


def manager_dep(service: CollectorService = Depends(service_dep)) -> AdaptiveThresholdManager:
    """阈值管理器与检测引擎共用同一实例（保证 API 改动立刻对检测生效）。"""
    return service.engine.adaptive


@router.get("/thresholds", summary="维度化阈值清单")
def list_thresholds(manager: AdaptiveThresholdManager = Depends(manager_dep)) -> Dict[str, Any]:
    items = manager.entries()
    return {
        "total": len(items),
        "items": items,
        "overview": manager.dimensions_overview(),
        "updated_at": items[0]["last_updated"] if items else None,
    }


@router.get("/thresholds/static", summary="静态基准与调整边界（前端面板用）")
def thresholds_static(manager: AdaptiveThresholdManager = Depends(manager_dep)) -> Dict[str, Any]:
    return manager.dimensions_overview()


@router.get("/thresholds/{detection_type}/{dimension_key}", summary="查询单个维度的生效阈值")
def get_threshold(detection_type: str,
                  dimension_key: str,
                  asset_class: str = Query(default="unknown"),
                  time_bucket: str = Query(default="workhour"),
                  manager: AdaptiveThresholdManager = Depends(manager_dep)) -> Dict[str, Any]:
    if dimension_key != detection_type:
        raise HTTPException(status_code=400, detail="dimension_key 与 detection_type 不一致")
    value = manager.threshold_for(detection_type, source_ip="", now=None)
    return {
        "detection_type": detection_type,
        "asset_class": asset_class,
        "time_bucket": time_bucket,
        "static_value": manager.static_base(detection_type),
        "threshold_value": value,
        "enabled": manager.enabled,
    }


@router.post("/thresholds/recompute", response_model=ActionResult, summary="手动触发阈值重算")
def recompute_thresholds(lookback_days: Optional[int] = Query(default=None, ge=1, le=180),
                         _: None = Depends(require_token),
                         manager: AdaptiveThresholdManager = Depends(manager_dep)) -> ActionResult:
    report = manager.recompute(lookback_days)
    updated: List[Dict[str, Any]] = report.get("updated", [])
    return ActionResult(
        success=True,
        message=(f"阈值重算完成：{report.get('dimensions', 0)} 个维度，"
                 f"更新 {len(updated)} 条，跳过 {len(report.get('skipped', []))} 条（人工覆盖）"),
        code="recomputed",
        detail=report,
    )


@router.post("/thresholds/recompute-async", summary="异步触发阈值重算（API 线程不阻塞）")
async def recompute_thresholds_async(lookback_days: Optional[int] = Query(default=None, ge=1, le=180),
                                     _: None = Depends(require_token),
                                     manager: AdaptiveThresholdManager = Depends(manager_dep)
                                     ) -> Dict[str, Any]:
    await asyncio.to_thread(manager.recompute, lookback_days)
    return {"success": True, "message": "阈值重算已在后台完成", "report": manager.last_recompute}


@router.patch("/thresholds/{entry_id}", response_model=ActionResult, summary="人工覆盖阈值")
def override_threshold(entry_id: int, payload: ThresholdOverride,
                       _: None = Depends(require_token),
                       manager: AdaptiveThresholdManager = Depends(manager_dep)) -> ActionResult:
    result = manager.override(entry_id, payload.threshold_value, payload.reason, payload.operator)
    if result is None:
        raise HTTPException(status_code=404, detail="阈值记录不存在")
    return ActionResult(
        success=True,
        message=(f"已人工覆盖 {result['detection_type']} / {result['asset_class']} / "
                 f"{result['time_bucket']} → {payload.threshold_value}"),
        code="overridden",
        detail=result,
    )
