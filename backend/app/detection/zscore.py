"""统计异常检测：EWMA 基线（O(1) 内存）与基于 MAD 的稳健 Z-score。

为什么用 EWMA + MAD 而不是简单均值方差？
* 攻击流量本身会污染历史窗口，纯均值/方差基线会被"拉高"，导致漏报；
* EWMA 对趋势自适应，MAD 对离群点不敏感，两者结合在无标注数据下鲁棒性最好；
* 全流程 O(1) 内存、O(1) 时间，单核可支撑 10w+ 时序键。
"""

from __future__ import annotations

import math
import statistics
from collections import deque
from typing import Deque, Dict, Hashable, List, Optional, Tuple


class EwmaBaseline:
    """指数加权移动平均基线。

    ``mean`` 与 ``var`` 均以 alpha 平滑更新；提供 z-score 与"基线是否已就绪"判定。
    """

    __slots__ = ("alpha", "warmup", "mean", "var", "samples", "last_value")

    def __init__(self, alpha: float = 0.15, warmup: int = 20) -> None:
        self.alpha = float(alpha)
        self.warmup = int(warmup)
        self.mean = 0.0
        self.var = 0.0
        self.samples = 0
        self.last_value = 0.0

    @property
    def ready(self) -> bool:
        return self.samples >= self.warmup

    @property
    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))

    def update(self, value: float) -> Tuple[float, float]:
        """喂入观测值，返回更新后的 (mean, std)。"""
        return self.update_with_alpha(value, self.alpha)

    def update_with_alpha(self, value: float, alpha: float) -> Tuple[float, float]:
        """以指定权重吸收观测值。

        ``alpha`` 越小吸收越慢 —— 检测到异常时会用 1/10 权重调用本方法，
        避免攻击流量把基线"拉高"导致后续同类攻击漏报（baseline poisoning 防护）。
        """
        value = float(value)
        alpha = max(1e-4, min(1.0, float(alpha)))
        self.samples += 1
        if self.samples == 1:
            self.mean = value
            self.var = 0.0
        else:
            delta = value - self.mean
            self.mean += alpha * delta
            self.var = (1 - alpha) * (self.var + alpha * delta * delta)
        self.last_value = value
        return self.mean, self.std

    def zscore(self, value: float, floor_std: float = 1e-6) -> float:
        """标准化偏离度；std 过小时用 floor 兜底，避免除零导致的误报。"""
        std = max(self.std, floor_std)
        return (float(value) - self.mean) / std

    def snapshot(self) -> Dict[str, float]:
        return {"mean": round(self.mean, 3), "std": round(self.std, 3), "samples": self.samples}


class RollingStats:
    """滑动窗口中位数 / MAD / 分位数（用于非对称分布的稳健判定）。"""

    def __init__(self, maxlen: int = 120) -> None:
        self._data: Deque[float] = deque(maxlen=maxlen)

    def add(self, value: float) -> None:
        self._data.append(float(value))

    def __len__(self) -> int:
        return len(self._data)

    @property
    def ready(self) -> bool:
        return len(self._data) >= 10

    def median(self) -> float:
        return statistics.median(self._data) if self._data else 0.0

    def mad(self) -> float:
        """中位数绝对偏差（Median Absolute Deviation），≈ 0.6745σ。"""
        if len(self._data) < 3:
            return 0.0
        med = self.median()
        return statistics.median([abs(v - med) for v in self._data])

    def percentile(self, ratio: float) -> float:
        if not self._data:
            return 0.0
        ordered = sorted(self._data)
        index = min(len(ordered) - 1, max(0, int(round(ratio * (len(ordered) - 1)))))
        return ordered[index]

    def values(self) -> List[float]:
        return list(self._data)


def robust_zscore(value: float, median: float, mad: float) -> float:
    """稳健 Z-score：0.6745 * (x - median) / MAD，对离群点不敏感。"""
    scale = max(mad * 1.4826, 1e-9)   # 1.4826 使 MAD 与标准差可比
    return (float(value) - median) / scale


class ZScoreDetector:
    """按键（端口 / 源 IP / 全局）维护基线并输出异常分数。

    * ``threshold``：超过即视为异常（默认取全局 ZSCORE_THRESHOLD）；
    * ``floor_std``：标准差下限，避免稳定流量下微小抖动被放大成异常；
    * ``min_absolute``：绝对量下限，抑制低基线上的噪声（例如 0.4 pps 突增）。
    """

    def __init__(self, threshold: float = 3.5, warmup: int = 20, alpha: float = 0.15,
                 floor_std: float = 1e-6, min_absolute: float = 0.0) -> None:
        self.threshold = float(threshold)
        self.warmup = int(warmup)
        self.alpha = float(alpha)
        self.floor_std = float(floor_std)
        self.min_absolute = float(min_absolute)
        self._baselines: Dict[Hashable, EwmaBaseline] = {}

    def baseline(self, key: Hashable) -> EwmaBaseline:
        base = self._baselines.get(key)
        if base is None:
            base = EwmaBaseline(alpha=self.alpha, warmup=self.warmup)
            self._baselines[key] = base
        return base

    def observe(self, key: Hashable, value: float) -> Optional[Dict[str, float]]:
        """返回 None 表示正常；否则返回异常详情（score 已归一化到 0~1）。

        判定顺序至关重要：**先用旧基线打分，再更新基线**。
        若反过来（先 update 再 zscore），突增样本会立刻把均值拉高、方差拉大，
        导致自身 z 值被稀释到阈值以下 —— 这是自研检测器最典型的漏报原因。
        """
        base = self.baseline(key)

        detail: Optional[Dict[str, float]] = None
        if base.ready and value >= self.min_absolute:
            z = base.zscore(value, floor_std=self.floor_std)
            if z >= self.threshold:
                detail = {
                    "zscore": round(z, 3),
                    "score": round(min(1.0, z / (self.threshold * 2)), 4),
                    "baseline_mean": round(base.mean, 3),
                    "baseline_std": round(base.std, 3),
                    "threshold": self.threshold,
                }

        if detail is None:
            base.update(value)
        else:
            # 异常样本仅以 1/10 权重进入基线，防止持续性攻击拖高基线造成漏报
            base.update_with_alpha(value, base.alpha * 0.1)
        return detail

    def keys(self) -> List[Hashable]:
        return list(self._baselines.keys())

    def cleanup(self, keep: int = 4096) -> None:
        """基线表保护：键数量超限时清理样本最少的一半，防止长期运行内存膨胀。"""
        if len(self._baselines) <= keep:
            return
        ordered = sorted(self._baselines.items(), key=lambda item: item[1].samples)
        for key, _ in ordered[: len(ordered) // 2]:
            self._baselines.pop(key, None)
