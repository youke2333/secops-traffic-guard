"""滑动窗口数据结构（线程安全、无第三方依赖，O(1) 摊销）。

设计要点：
* 采集线程只做「累加」，检测/聚合线程按 tick 读取快照，避免每包计算；
* 所有窗口均为时间驱动淘汰，内存上限与 QPS 无关，只与窗口长度有关。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque, Dict, Hashable, Iterable, List, Tuple


class TimeSeries:
    """定长时序环形缓冲，用于大屏趋势图与基线计算。"""

    def __init__(self, maxlen: int = 600) -> None:
        self._data: Deque[Tuple[float, float]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, value: float, ts: float | None = None) -> None:
        with self._lock:
            self._data.append((ts if ts is not None else time.time(), float(value)))

    def values(self, since: float | None = None) -> List[float]:
        with self._lock:
            items = list(self._data)
        return [v for ts, v in items if since is None or ts >= since]

    def points(self, since: float | None = None) -> List[Tuple[float, float]]:
        with self._lock:
            items = list(self._data)
        return [item for item in items if since is None or item[0] >= since]

    def last(self, default: float = 0.0) -> float:
        with self._lock:
            return self._data[-1][1] if self._data else default

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class SlidingWindow:
    """通用滑动窗口计数器：add(key, ts, pkts, bytes) → snapshot() 返回窗口内累计值。"""

    def __init__(self, window_sec: float) -> None:
        self.window = float(window_sec)
        self._data: Dict[Hashable, Deque[Tuple[float, int, int]]] = {}
        self._lock = threading.Lock()

    def add(self, key: Hashable, ts: float, pkts: int = 1, nbytes: int = 0) -> None:
        with self._lock:
            bucket = self._data.get(key)
            if bucket is None:
                bucket = deque()
                self._data[key] = bucket
            # 同一毫秒/秒内合并，避免 deque 被高频小包撑爆
            if bucket and ts - bucket[-1][0] < 0.05:
                last_ts, last_p, last_b = bucket[-1]
                bucket[-1] = (last_ts, last_p + pkts, last_b + nbytes)
            else:
                bucket.append((ts, pkts, nbytes))

    def prune(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        cutoff = now - self.window
        with self._lock:
            for key in list(self._data.keys()):
                bucket = self._data[key]
                while bucket and bucket[0][0] < cutoff:
                    bucket.popleft()
                if not bucket:
                    del self._data[key]

    def snapshot(self, now: float | None = None) -> Dict[Hashable, Tuple[int, int]]:
        """返回 {key: (packets, bytes)}，自动剔除过期数据。"""
        self.prune(now)
        with self._lock:
            return {key: (
                sum(item[1] for item in bucket),
                sum(item[2] for item in bucket),
            ) for key, bucket in self._data.items()}

    def distinct(self, key: Hashable) -> int:
        self.prune()
        with self._lock:
            bucket = self._data.get(key)
            return len(bucket) if bucket else 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)


class WindowCounter:
    """多窗口组合：同一 key 可同时维护 1s / 10s / 60s 等多个粒度。"""

    def __init__(self, windows: Iterable[float] = (1.0, 10.0, 60.0)) -> None:
        self._windows: Dict[float, SlidingWindow] = {float(w): SlidingWindow(float(w)) for w in windows}

    @property
    def granularities(self) -> List[float]:
        return sorted(self._windows)

    def add(self, key: Hashable, ts: float, pkts: int = 1, nbytes: int = 0) -> None:
        for window in self._windows.values():
            window.add(key, ts, pkts, nbytes)

    def snapshot(self, window_sec: float, now: float | None = None) -> Dict[Hashable, Tuple[int, int]]:
        target = min(self._windows, key=lambda w: abs(w - window_sec))
        return self._windows[target].snapshot(now)

    def prune(self, now: float | None = None) -> None:
        for window in self._windows.values():
            window.prune(now)
