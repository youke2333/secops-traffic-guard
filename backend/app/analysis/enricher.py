"""异步研判执行器：把"告警落库"与"LLM 研判"解耦。

为什么需要独立线程而不是 asyncio 任务：采集/检测跑在**后台线程**（`collector-tick`）里，
线程内没有事件循环，`asyncio.create_task` 无法工作；因此这里用一个（可配置多个）守护线程 +
定长队列实现"提交即返回"：

* `submit(alert_id)` 立即返回，队列满时丢弃并保持 `llm_analysis` 为 None（前端显示"待人工"）；
* 工作线程内做同步 HTTP 调用（DeepSeek 3s 超时），写回 `alerts.llm_analysis` 并推送
  `alert_enriched` 事件（前端据此刷新抽屉，无需轮询）；
* 同源同类结果在 `LLM_CACHE_TTL_SEC` 内复用，避免攻击持续期间对同一 IP 反复请求模型。
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Dict, List, Optional

from ..bus import EventBus, bus as default_bus
from ..config import Settings, get_settings
from ..database import session_scope
from ..models import Alert
from .fallback_chain import AnalysisFallbackChain

logger = logging.getLogger(__name__)


class AlertEnricher:
    """研判任务队列 + 工作线程（进程内，无外部依赖）。"""

    def __init__(self, settings: Optional[Settings] = None,
                 chain: Optional[AnalysisFallbackChain] = None,
                 event_bus: Optional[EventBus] = None) -> None:
        self.settings = settings or get_settings()
        self.chain = chain or AnalysisFallbackChain(self.settings)
        self.bus = event_bus or default_bus
        self.queue: "queue.Queue[int]" = queue.Queue(
            maxsize=int(getattr(self.settings, "llm_queue_size", 200)))
        self.workers: List[threading.Thread] = []
        self._stop = threading.Event()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.counters: Dict[str, int] = {"submitted": 0, "done": 0, "dropped": 0, "cached": 0,
                                         "failed": 0}

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self.workers:
            return
        self._stop.clear()
        for index in range(int(getattr(self.settings, "llm_worker_threads", 1))):
            worker = threading.Thread(target=self._loop, name=f"alert-enrich-{index}", daemon=True)
            worker.start()
            self.workers.append(worker)
        logger.info("研判执行器已启动：%d 个线程", len(self.workers))

    def stop(self) -> None:
        self._stop.set()
        for worker in self.workers:
            worker.join(timeout=2)
        self.workers = []

    # ------------------------------------------------------------------ #
    # 提交
    # ------------------------------------------------------------------ #
    def submit(self, alert_id: Optional[int]) -> bool:
        """提交一条告警做研判（立即返回，绝不阻塞调用方）。"""
        if alert_id is None:
            return False
        self.counters["submitted"] += 1
        try:
            self.queue.put_nowait(int(alert_id))
            return True
        except queue.Full:
            self.counters["dropped"] += 1
            logger.warning("研判队列已满，告警 %s 暂不研判（前端显示「待人工」）", alert_id)
            return False

    # ------------------------------------------------------------------ #
    # 工作线程
    # ------------------------------------------------------------------ #
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                alert_id = self.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.enrich(alert_id)
            except Exception:
                self.counters["failed"] += 1
                logger.exception("告警研判失败：alert_id=%s", alert_id)
            finally:
                self.queue.task_done()

    def enrich(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """同步研判一条告警（供工作线程与 POST /alerts/{id}/reanalyze 复用）。"""
        payload = self._load_alert(alert_id)
        if payload is None:
            return None
        cache_key = self._cache_key(payload)
        cached = self._from_cache(cache_key)
        if cached is not None:
            result = {**cached, "cached": True}
        else:
            result = self.chain.analyze(payload)
            self._store_cache(cache_key, result)
        self._save(alert_id, result)
        self.counters["done"] += 1
        return result

    def _load_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with session_scope() as session:
            row = session.get(Alert, alert_id)
            if row is None:
                logger.info("研判跳过：告警不存在（id=%s）", alert_id)
                return None
            return {
                "id": row.id,
                "category": row.category,
                "severity": row.severity,
                "score": row.score,
                "risk_score": row.risk_score,
                "direct_alert": bool(row.direct_alert),
                "contributing_rules": list(row.contributing_rules or []),
                "source_ip": row.source_ip,
                "dest_port": row.dest_port,
                "protocol": row.protocol,
                "detector": (row.evidence or {}).get("detector", ""),
                "evidence": row.evidence or {},
                "message": row.message,
            }

    def _save(self, alert_id: int, result: Dict[str, Any]) -> None:
        with session_scope() as session:
            row = session.get(Alert, alert_id)
            if row is None:
                return
            row.llm_analysis = result
        self.bus.publish("alert_enriched", {"alert_id": alert_id, "analysis": result})

    # ------------------------------------------------------------------ #
    # 缓存
    # ------------------------------------------------------------------ #
    def _cache_key(self, payload: Dict[str, Any]) -> str:
        return f"{payload.get('source_ip')}|{payload.get('category')}|{payload.get('severity')}"

    def _from_cache(self, key: str) -> Optional[Dict[str, Any]]:
        ttl = float(getattr(self.settings, "llm_cache_ttl_sec", 3600))
        if ttl <= 0:
            return None
        entry = self._cache.get(key)
        if entry is None or time.time() - entry["at"] > ttl:
            return None
        self.counters["cached"] += 1
        return dict(entry["value"])

    def _store_cache(self, key: str, value: Dict[str, Any]) -> None:
        if float(getattr(self.settings, "llm_cache_ttl_sec", 3600)) <= 0:
            return
        self._cache[key] = {"at": time.time(), "value": dict(value)}
        if len(self._cache) > 512:      # 简单的容量保护
            oldest = sorted(self._cache, key=lambda item: self._cache[item]["at"])
            for item in oldest[:128]:
                self._cache.pop(item, None)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "queued": self.queue.qsize(),
            "workers": len(self.workers),
            "cache_entries": len(self._cache),
            **self.counters,
            "chain": self.chain.stats,
        }
