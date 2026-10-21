"""进程内事件总线：采集/检测线程 → SSE 异步生成器 的解耦通道。

* 无第三方依赖（不引入 Redis/Janus），单机场景足够；
* 每个订阅者一个定长 deque，写满即丢最旧数据，保证慢客户端不会拖垮采集线程。
"""

from __future__ import annotations

import itertools
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List


class EventBus:
    def __init__(self, maxlen: int = 500) -> None:
        self._subscribers: Dict[int, Deque[dict]] = {}
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._maxlen = maxlen
        self._counters: Dict[str, int] = {}

    def subscribe(self) -> int:
        with self._lock:
            sid = next(self._ids)
            self._subscribers[sid] = deque(maxlen=self._maxlen)
            return sid

    def unsubscribe(self, sid: int) -> None:
        with self._lock:
            self._subscribers.pop(sid, None)

    def publish(self, topic: str, payload: Any) -> None:
        event = {"topic": topic, "ts": time.time(), "data": payload}
        with self._lock:
            self._counters[topic] = self._counters.get(topic, 0) + 1
            for queue in self._subscribers.values():
                queue.append(event)

    def drain(self, sid: int, topic: str | None = None) -> List[dict]:
        with self._lock:
            queue = self._subscribers.get(sid)
            if queue is None:
                return []
            if topic is None:
                events = list(queue)
                queue.clear()
                return events
            kept: Deque[dict] = deque(maxlen=self._maxlen)
            picked: List[dict] = []
            while queue:
                event = queue.popleft()
                if event["topic"] == topic:
                    picked.append(event)
                else:
                    kept.append(event)
            queue.extend(kept)
            return picked

    @property
    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"subscribers": len(self._subscribers), **self._counters}


bus = EventBus()
