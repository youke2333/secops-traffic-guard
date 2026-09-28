"""异常检测：统计基线（EWMA / 稳健 Z-score）+ 机器学习（Isolation Forest）双引擎。

v2 追加：
* `scoring`  —— 滑动窗口增量评分 + 直达机制（告警聚合，抑制告警风暴）；
* `adaptive_threshold` —— 维度化自适应阈值（由误报/真阳反馈驱动的阈值收放）。
"""

from .adaptive_threshold import AdaptiveThresholdManager
from .engine import Anomaly, DetectionEngine, TrafficSnapshot
from .iforest import IsolationForestDetector
from .scoring import (
    AggregatedAlert,
    ScoringAggregator,
    compute_weight,
    rule_id_of,
)
from .web_knowledge import WebAttackDetector, WebAttackHit, WebAttackKnowledgeBase, WebRequestEvent
from .zscore import EwmaBaseline, RollingStats, ZScoreDetector, robust_zscore

__all__ = [
    "Anomaly",
    "DetectionEngine",
    "TrafficSnapshot",
    "EwmaBaseline",
    "RollingStats",
    "ZScoreDetector",
    "robust_zscore",
    "IsolationForestDetector",
    "ScoringAggregator",
    "AggregatedAlert",
    "compute_weight",
    "rule_id_of",
    "AdaptiveThresholdManager",
    "WebAttackDetector",
    "WebAttackHit",
    "WebAttackKnowledgeBase",
    "WebRequestEvent",
]
