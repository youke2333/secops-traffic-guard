"""零依赖 Python 后端：不做候选裁剪（所有规则都进入精匹配）。"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base import MatcherBackend as BaseMatcher, RulePlan


class PythonMatcher(BaseMatcher):
    name = "python"

    def __init__(self, plans: List[RulePlan]) -> None:
        self.plans = plans
        self.patterns = sum(len(plan.patterns) for plan in plans)

    def candidates(self, targets: Dict[str, Dict[str, str]]) -> Optional[bytearray]:
        return None

    def stats(self) -> Dict[str, Any]:
        return {
            "matcher_backend": self.name,
            "matcher_patterns": self.patterns,
            "matcher_fallback_rules": 0,
            "compile_ms": 0.0,
        }
