"""匹配后端选择。"""

from __future__ import annotations

import logging
from typing import List, Optional

from .base import MatcherBackend, RulePlan, compile_plan
from .python_backend import PythonMatcher

logger = logging.getLogger(__name__)


def build_matcher(plans: List[RulePlan], backend: str = "auto", max_mem_mb: int = 64) -> MatcherBackend:
    name = str(backend or "auto").lower()
    if name in {"auto", "re2"}:
        try:
            from .re2_backend import Re2Matcher

            matcher = Re2Matcher(plans, max_mem_mb=max_mem_mb)
            if matcher._set is not None:
                return matcher
            logger.warning("RE2 索引不可用（%s），本次回落 python 后端", matcher.error)
        except Exception as exc:
            if name == "re2":
                logger.warning("RE2 未安装或加载失败（%s），自动回落 python 后端", exc)
            else:
                logger.info("RE2 未安装，使用 python 后端（安装 google-re2 可提升扩容能力）")
    return PythonMatcher(plans)


__all__ = ["MatcherBackend", "RulePlan", "compile_plan", "build_matcher"]
