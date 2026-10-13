"""降级链编排（方案第 4 层 / 第五节）：LLM → 本地规则 → 静态模板 → 待人工。

降级顺序与判据：

1. **deepseek_v4_flash**：`LLM_ENABLED=true` 且配置了 API Key，调用成功且输出通过 schema 校验；
2. **local_rules**：API 不可用时，若聚合风险分显著超阈（`risk_score >= 阈值 × 1.5`）或命中直达规则，
   直接由本地规则给出结论（这类告警证据已经很充分，不需要模型背书）；
3. **template**：类别有预设模板时按模板输出判定倾向；
4. **pending**：以上都不适用 —— 明确标记"待人工核查"，绝不编一个结论出来。

**降级必须可见**：每级都会写 `source` 与 `degraded=True`，前端据此显示来源标签与提示条。
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..config import Settings, get_settings
from . import template_responder
from .llm_client import DeepSeekClient, LLMUnavailable
from .prompts import evidence_refs

logger = logging.getLogger(__name__)

SOURCE_LLM = "deepseek_v4_flash"
SOURCE_LOCAL = "local_rules"
SOURCE_TEMPLATE = "template"
SOURCE_PENDING = "pending"


class AnalysisFallbackChain:
    """把一条告警翻译成研判结论（含来源与降级标记）。"""

    def __init__(self, settings: Optional[Settings] = None,
                 client: Optional[DeepSeekClient] = None) -> None:
        self.settings = settings or get_settings()
        self.client = client or DeepSeekClient(self.settings)
        self.counters: Dict[str, int] = {
            "total": 0, SOURCE_LLM: 0, SOURCE_LOCAL: 0, SOURCE_TEMPLATE: 0, SOURCE_PENDING: 0,
            "llm_unavailable": 0,
        }

    # ------------------------------------------------------------------ #
    def analyze(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """执行降级链（同步；调用方负责放到后台线程，避免阻塞 tick）。"""
        self.counters["total"] += 1
        payload = dict(alert)
        payload.setdefault("evidence_refs", evidence_refs(alert))

        if self.client.available:
            try:
                result = self.client.analyze(payload)
                return self._payload(result, SOURCE_LLM, degraded=False,
                                     direct=bool(alert.get("direct_alert")), alert=payload)
            except LLMUnavailable as exc:
                self.counters["llm_unavailable"] += 1
                logger.warning("LLM 不可用，进入降级链：%s", exc)

        local = self._rule_verdict(payload)
        if local is not None:
            return self._payload(local, SOURCE_LOCAL, degraded=True,
                                 direct=bool(alert.get("direct_alert")), alert=payload)

        template = template_responder.render(payload)
        if template is not None:
            return self._payload(template, SOURCE_TEMPLATE, degraded=True,
                                 direct=bool(alert.get("direct_alert")), alert=payload)

        return self._payload({
            "verdict": "unknown",
            "confidence": 0.0,
            "suggestion": "watch",
            "reason": "API 不可用且本地规则评分不足以自动研判，请人工核查该告警的证据与主机日志。",
        }, SOURCE_PENDING, degraded=True, direct=bool(alert.get("direct_alert")), alert=payload)

    # ------------------------------------------------------------------ #
    def _rule_verdict(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """本地规则综合评分：证据已足够充分时直接给结论（不依赖模型）。"""
        threshold = float(getattr(self.settings, "alert_score_threshold", 6.0))
        risk_score = float(alert.get("risk_score") or 0.0)
        severity = str(alert.get("severity") or "medium")
        direct = bool(alert.get("direct_alert"))
        if not direct and risk_score < threshold * 1.5:
            return None
        if severity in ("critical", "high"):
            verdict, suggestion = "confirm", "block"
        else:
            verdict, suggestion = "suspect", "watch"
        reason = ("命中直达规则" if direct else
                  f"聚合风险分 {round(risk_score, 2)} 显著超过阈值 {threshold}")
        return {
            "verdict": verdict,
            "confidence": 0.75,
            "suggestion": suggestion,
            "reason": f"本地规则综合评分判定：{reason}，级别 {severity}，建议{'立即封禁并取证' if suggestion == 'block' else '继续观察并人工确认'}。",
        }

    def _payload(self, result: Dict[str, Any], source: str, degraded: bool,
                 direct: bool, alert: Dict[str, Any]) -> Dict[str, Any]:
        self.counters[source] = self.counters.get(source, 0) + 1
        return {
            "source": source,
            "verdict": result.get("verdict", "unknown"),
            "reason": result.get("reason", ""),
            "confidence": float(result.get("confidence") or 0.0),
            "suggestion": result.get("suggestion", "watch"),
            "evidence_refs": list(alert.get("evidence_refs") or []),
            "direct_alert": direct,
            "degraded": bool(degraded),
            "generated_at": datetime.now(timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        }

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self.settings.llm_enabled),
            "client_available": self.client.available,
            "model": self.settings.llm_model if self.settings.llm_enabled else "",
            "mask_internal_ip": bool(self.settings.llm_mask_internal_ip),
            "timeout_sec": float(self.settings.llm_timeout_sec),
            "sources": {key: value for key, value in self.counters.items()},
        }
