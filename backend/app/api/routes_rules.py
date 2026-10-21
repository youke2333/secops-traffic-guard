"""规则来源与热加载接口（方案第 1 层交付项）。

* ``GET  /rules/sources``  各来源（native / sigma / et / cve_ext）已加载规则数与直达规则数；
* ``GET  /rules``          统一规则清单（可按来源/类别/直达过滤，供前端「规则库」面板）；
* ``POST /rules/reload``   手动热加载（运维放好新规则文件后无需重启服务）。

启动日志同样会输出 `rules loaded: native=…, sigma=…, et=…, cve_ext=…, direct_alert=…`，
两条路径共用同一份 `RuleRegistry` 报告，避免"日志与接口不一致"。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..auth import audit
from ..collector.service import CollectorService
from ..rules import get_registry
from ..rules.packs import packs_overview
from ..schemas import ActionResult
from .deps import require_role, service_dep

router = APIRouter(tags=["rules"])


def _web_categories(service: CollectorService) -> List[str]:
    return [str(item.get("key")) for item in service.web_detector.kb.categories]


@router.get("/rules/sources", summary="规则来源概览（各来源规则数 / 直达规则数）")
def rule_sources(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    registry = get_registry()
    payload = registry.sources(_web_categories(service))
    payload["web_kb"] = service.web_detector.kb.stats
    payload["direct_alert_categories"] = sorted({
        str(rule.get("category")) for rule in service.web_detector.kb.rules
        if rule.get("direct_alert")
    })
    return payload


@router.get("/rules", summary="统一规则清单（内置 + Sigma + ET + 扩展 CVE）")
def list_rules(source: str = Query(default="", description="native|sigma|et|cve_ext"),
               category: str = Query(default=""),
               direct_only: bool = Query(default=False),
               limit: int = Query(default=200, ge=1, le=2000),
               service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    registry = get_registry()
    rules = registry.get_rules(category=category or None, source=source or None,
                              direct_only=direct_only)
    return {
        "total": len(rules),
        "items": [rule.public() for rule in rules[:limit]],
        "stats": registry.stats(),
    }


@router.post("/rules/reload", response_model=ActionResult, summary="热加载规则（无需重启）")
def reload_rules(principal: dict = Depends(require_role("admin")),
                 service: CollectorService = Depends(service_dep)) -> ActionResult:
    registry = get_registry()
    report = registry.reload()
    # 统一构建入口：内置 + 规则包 + Sigma/ET + 高置信直达规则；构建完成后原子替换。
    kb = service.web_detector.reload_kb(registry=registry)
    audit("rules_reload", username=str(principal.get("username") or ""),
          detail=f"rules={len(kb.rules)} matcher={kb.matcher.name}")
    return ActionResult(
        success=True,
        message=(f"规则已热加载：native={report.get('native')}、sigma={report.get('sigma')}、"
                 f"et={report.get('et')}、cve_ext={report.get('cve_ext')}、"
                 f"Web 规则={len(kb.rules)}、直达={len(kb._direct_ids())}、"
                 f"匹配后端={kb.matcher.name}"),
        code="reloaded",
        detail={**report, "web_kb": kb.stats, "pack": getattr(kb, "pack_report", {})},
    )


@router.get("/rules/packs", summary="规则包列表（条数/档位/启用状态/加载报告）")
def rule_packs(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    kb = service.web_detector.kb
    report = getattr(kb, "pack_report", {}) or {}
    payload = packs_overview(service.settings, report)
    payload["web_kb"] = kb.stats
    return payload


@router.get("/rules/engine", summary="匹配引擎状态（后端/候选/编译/降级规则）")
def rule_engine(service: CollectorService = Depends(service_dep)) -> Dict[str, Any]:
    kb = service.web_detector.kb
    return {
        "backend": kb.matcher.name,
        "configured_backend": service.settings.match_backend,
        "patterns": sum(len(plan.patterns) for plan in kb._plans),
        "plans": len(kb._plans),
        "rules": len(kb.rules),
        "tiers_enabled": list(kb.tiers),
        "compile_ms": kb.build_ms,
        "matcher": kb.matcher.stats(),
        "stats": kb.stats,
        "fallback_rules": [
            kb._plans[index].rule_id for index in sorted(getattr(kb.matcher, "fallback_rules", set()))
            if 0 <= int(index) < len(kb._plans)
        ],
    }


class BackendIn(BaseModel):
    backend: str = "auto"


@router.post("/rules/engine/backend", response_model=ActionResult,
             summary="切换匹配后端（python|re2|auto，admin）")
def switch_backend(payload: BackendIn, principal: dict = Depends(require_role("admin")),
                   service: CollectorService = Depends(service_dep)) -> ActionResult:
    backend = str(payload.backend or "").lower()
    if backend not in {"auto", "python", "re2"}:
        raise HTTPException(status_code=400, detail="backend 必须是 auto|python|re2")
    if backend == "re2":
        try:
            import re2  # noqa: F401
        except Exception:
            raise HTTPException(status_code=400, detail="RE2 未安装：请先 pip install google-re2")
    service.settings.match_backend = backend
    kb = service.web_detector.reload_kb(get_registry())
    audit("rules_engine", username=str(principal.get("username") or ""),
          target=backend, detail=f"实际后端={kb.matcher.name}")
    return ActionResult(success=True, message=f"匹配后端已切换：{kb.matcher.name}",
                        code="backend_switched",
                        detail={"configured": backend, "actual": kb.matcher.name,
                                "stats": kb.matcher.stats()})


class TiersIn(BaseModel):
    tiers: Optional[List[str]] = None
    shadow_mode: Optional[bool] = None


@router.patch("/rules/packs/intrusion", response_model=ActionResult,
              summary="调整入侵规则包档位 / 影子模式（admin）")
def update_intrusion_pack(payload: TiersIn, principal: dict = Depends(require_role("admin")),
                          service: CollectorService = Depends(service_dep)) -> ActionResult:
    if payload.tiers is not None:
        invalid = set(payload.tiers) - {"core", "extended", "lab"}
        if invalid:
            raise HTTPException(status_code=400, detail=f"未知档位：{sorted(invalid)}")
        if not payload.tiers:
            raise HTTPException(status_code=400, detail="至少保留一个档位")
        service.settings.rules_tiers = list(dict.fromkeys(payload.tiers))
    if payload.shadow_mode is not None:
        service.settings.rules_shadow_mode = bool(payload.shadow_mode)
    kb = service.web_detector.reload_kb(get_registry())
    audit("rules_tiers", username=str(principal.get("username") or ""),
          target="intrusion", detail=f"tiers={service.settings.rules_tiers} "
                                     f"shadow={service.settings.rules_shadow_mode}")
    return ActionResult(success=True, message="规则档位已更新（立即生效）", code="tiers_updated",
                        detail={"tiers": service.settings.rules_tiers,
                                "shadow_mode": service.settings.rules_shadow_mode,
                                "web_rules": len(kb.rules), "kb": kb.stats})
