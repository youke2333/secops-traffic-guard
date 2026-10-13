"""LLM 研判与降级链（方案第 4 层）。

    enricher（异步队列 + 工作线程）
        └─ fallback_chain（降级编排）
              ├─ llm_client       DeepSeek V4-Flash（OpenAI 兼容）
              ├─ 本地规则综合评分  （风险分 / 直达标记足够充分时直接给结论）
              ├─ template_responder 静态模板（按攻击大类）
              └─ pending          待人工核查（明确标注，绝不臆测）

对外统一入口：`AlertEnricher`（`get_enricher()` 全局单例）。
"""

from .enricher import AlertEnricher
from .fallback_chain import (
    SOURCE_LLM,
    SOURCE_LOCAL,
    SOURCE_PENDING,
    SOURCE_TEMPLATE,
    AnalysisFallbackChain,
)
from .llm_client import DeepSeekClient, LLMUnavailable
from .prompts import build_alert_digest, build_messages, evidence_refs, mask_ip
from .template_responder import TEMPLATES

__all__ = [
    "AlertEnricher",
    "AnalysisFallbackChain",
    "DeepSeekClient",
    "LLMUnavailable",
    "TEMPLATES",
    "SOURCE_LLM",
    "SOURCE_LOCAL",
    "SOURCE_TEMPLATE",
    "SOURCE_PENDING",
    "build_alert_digest",
    "build_messages",
    "evidence_refs",
    "mask_ip",
]
