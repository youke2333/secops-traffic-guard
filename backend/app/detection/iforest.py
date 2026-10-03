"""Isolation Forest 无监督异常检测（可选组件）。

作用：捕捉"统计模型看不出来"的多维行为异常，例如
「连接数不高但目的端口熵很高」「包长分布异常的小包洪泛」。

实现要点：
* 冷启动：先积累 WARMUP 个样本再拟合，模型重训按 RETRAIN_EVERY 次观测节流，避免每 tick 重训；
* sklearn 缺失时自动降级（available=False），整个检测链路照常工作，不影响可用性。
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from typing import Deque, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

try:  # pragma: no cover - 取决于环境是否安装 scikit-learn
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover
    IsolationForest = None  # type: ignore[assignment]
    SKLEARN_AVAILABLE = False


FEATURE_NAMES = [
    "pps",                    # 包速率
    "bps",                    # 字节速率
    "unique_dst_ports",       # 目的端口多样性（扫描特征）
    "unique_dst_ips",         # 目的 IP 多样性
    "avg_packet_size",        # 平均包长
    "conns",                  # 并发连接数
    "syn_ratio",              # SYN 占比（半开连接/扫描特征）
    "bytes_per_conn",         # 单连接字节量
]


class IsolationForestDetector:
    """按源 IP 的行为向量做无监督离群检测。"""

    WARMUP = 200
    RETRAIN_EVERY = 50

    def __init__(self, contamination: float = 0.05, enabled: bool = True, warmup: int = WARMUP) -> None:
        self.enabled = bool(enabled) and SKLEARN_AVAILABLE
        self.contamination = float(contamination)
        self.warmup = int(warmup)
        self._samples: Deque[List[float]] = deque(maxlen=5000)
        self._model = None
        self._observations = 0
        self._lock = threading.Lock()
        self._decision_offset = 0.0

    @property
    def available(self) -> bool:
        return self.enabled

    @property
    def trained(self) -> bool:
        return self._model is not None

    def observe(self, features: List[float]) -> Optional[Dict[str, float]]:
        """返回 None 表示正常或模型未就绪；否则返回异常分数与决策阈值。"""
        if not self.enabled:
            return None
        vector = [float(v) for v in features]
        with self._lock:
            self._samples.append(vector)
            self._observations += 1
            if len(self._samples) < self.warmup:
                return None
            if self._model is None or self._observations % self.RETRAIN_EVERY == 0:
                self._fit()

        score = float(self._model.score_samples(np.asarray([vector]))[0])   # 越小越异常
        if score >= self._decision_offset:
            return None
        span = max(abs(self._decision_offset), 1e-6)
        normalized = min(1.0, max(0.0, (self._decision_offset - score) / span))
        return {
            "if_score": round(score, 4),
            "decision_offset": round(self._decision_offset, 4),
            "score": round(normalized, 4),
            "contamination": self.contamination,
        }

    def _fit(self) -> None:
        data = np.asarray(list(self._samples), dtype=float)
        if data.shape[0] < self.warmup:
            return
        try:
            model = IsolationForest(
                n_estimators=100,
                max_samples=min(256, data.shape[0]),
                contamination=self.contamination,
                random_state=42,
                n_jobs=1,
            )
            model.fit(data)
            self._model = model
            self._decision_offset = float(model.offset_)
        except Exception:  # pragma: no cover
            logger.exception("Isolation Forest 训练失败，继续保持统计检测模式")

    def reset(self) -> None:
        with self._lock:
            self._samples.clear()
            self._model = None
            self._observations = 0
