"""RE2 多模式预筛后端（可选依赖 google-re2）。

构建：把所有规则 pattern 加入 ``re2.Set``，逐字段 ``Set.Match`` 得到“命中了哪些 pattern”，
再映射回规则，只有命中的规则进入 RulePlan 精匹配。

不变量：
* RE2 只负责减少候选，不参与最终判定；
* lookaround / 反向引用等 RE2 不支持的规则进入 fallback，恒为候选，仍走 Python 精匹配；
* 逐字段扫描，绝不把字段拼成一段（否则 ``^``/``$`` 规则会漏报）。
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from .base import MatcherBackend as BaseMatcher, RulePlan

logger = logging.getLogger(__name__)


class Re2Matcher(BaseMatcher):
    name = "re2"

    def __init__(self, plans: List[RulePlan], max_mem_mb: int = 64) -> None:
        import re2            # 由 build_matcher 保证已安装

        self.plans = plans
        self.fallback_rules = set()
        self.pattern_count = 0
        self.compile_ms = 0.0
        self.scan_us_total = 0.0
        self.scan_calls = 0
        self.error = ""
        started = time.perf_counter()
        options = re2.Options()
        options.case_sensitive = False
        options.log_errors = False
        options.max_mem = int(max_mem_mb) << 20
        anchor = re2._re2.RE2.Anchor.UNANCHORED
        pattern_set = re2.Set(anchor, options)
        self._pattern_to_plan: List[int] = []
        for plan in plans:
            for pattern in plan.patterns:
                try:
                    pattern_set.Add(pattern.pattern)
                    self._pattern_to_plan.append(plan.idx)
                    self.pattern_count += 1
                except Exception:
                    self.fallback_rules.add(plan.idx)
        try:
            pattern_set.Compile()
            self._set = pattern_set
        except Exception as exc:
            logger.exception("RE2 Set 编译失败，自动回落 Python 后端")
            self.error = str(exc)
            self._set = None
        self.compile_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.info("RE2 索引构建完成：patterns=%d fallback_rules=%d compile_ms=%.1f",
                    self.pattern_count, len(self.fallback_rules), self.compile_ms)

    def candidates(self, targets: Dict[str, Dict[str, str]]) -> Optional[bytearray]:
        if self._set is None:
            return None
        started = time.perf_counter()
        result = bytearray(len(self.plans))
        for idx in self.fallback_rules:
            result[idx] = 1
        try:
            for entry in targets.values():
                text = entry.get("text") or ""
                raw = entry.get("raw") or ""
                for value in (text, raw):
                    if not value:
                        continue
                    for pattern_index in (self._set.Match(value) or ()):
                        plan_index = self._pattern_to_plan[pattern_index]
                        result[plan_index] = 1
        except Exception:
            logger.exception("RE2 扫描失败，本请求退化为全量精匹配")
            return None
        self.scan_us_total += (time.perf_counter() - started) * 1_000_000
        self.scan_calls += 1
        return result

    def stats(self) -> Dict[str, Any]:
        return {
            "matcher_backend": self.name,
            "matcher_patterns": self.pattern_count,
            "matcher_fallback_rules": len(self.fallback_rules),
            "compile_ms": self.compile_ms,
            "scan_us_avg": round(self.scan_us_total / self.scan_calls, 2) if self.scan_calls else 0.0,
            "error": self.error,
        }
