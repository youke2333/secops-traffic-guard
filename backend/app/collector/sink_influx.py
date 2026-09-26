"""InfluxDB 时序写入（Line Protocol over HTTP，无需额外客户端依赖）。

为什么同时写 InfluxDB 和关系库？
* 大屏/检测走内存环形缓冲（毫秒级）；
* 关系库存告警与资产（强一致、便于关联查询）；
* InfluxDB 存原始时序指标（长周期趋势、Grafana 二次分析），批量写入、失败不影响主流程。
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional

import httpx

from ..config import Settings, get_settings

logger = logging.getLogger(__name__)


class InfluxSink:
    """异步批量写入 InfluxDB v2；未配置时完全静默（零副作用）。"""

    def __init__(self, settings: Optional[Settings] = None, batch_size: int = 50) -> None:
        self.settings = settings or get_settings()
        self.enabled = bool(self.settings.influx_url and self.settings.influx_token)
        self.batch_size = batch_size
        self._buffer: Deque[str] = deque(maxlen=2000)
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.written = 0
        self.failed = 0
        if not self.enabled:
            logger.info("未配置 InfluxDB，时序数据仅保存在内存缓冲与关系库")

    # ---------------- 生命周期 ----------------
    def start(self) -> None:
        if not self.enabled or (self._thread and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="influx-sink", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    # ---------------- 写入 ----------------
    def write_metrics(self, iface: str, metrics: Dict[str, float]) -> None:
        if not self.enabled:
            return
        fields = ",".join(f"{key}={float(value)}" for key, value in metrics.items())
        self._push(f"traffic,iface={_escape(iface)} {fields}")

    def write_ports(self, samples: List[Dict[str, object]]) -> None:
        if not self.enabled:
            return
        for sample in samples:
            port = int(sample.get("port", 0))
            fields = ",".join([
                f"pps={float(sample.get('pps', 0))}",
                f"bps={float(sample.get('bps', 0))}",
                f"conns={int(sample.get('conns', 0))}",
                f"is_standard={str(bool(sample.get('is_standard', True))).lower()}",
            ])
            self._push(f"port_traffic,port={port},protocol={sample.get('protocol', 'TCP')} {fields}")

    def write_alert(self, anomaly: Dict[str, object]) -> None:
        if not self.enabled:
            return
        fields = ",".join([
            f"score={float(anomaly.get('score', 0) or 0)}",
            f"severity=\"{anomaly.get('severity', 'medium')}\"",
            f"category=\"{anomaly.get('category', 'unknown')}\"",
            f"source_ip=\"{anomaly.get('source_ip', '')}\"",
        ])
        self._push(f"security_alert,detector={anomaly.get('detector', 'unknown')} {fields}")

    def _push(self, line: str) -> None:
        with self._lock:
            self._buffer.append(line)

    def _loop(self) -> None:
        while not self._stop.is_set():
            batch: List[str] = []
            with self._lock:
                while self._buffer and len(batch) < self.batch_size:
                    batch.append(self._buffer.popleft())
            if batch:
                self._flush(batch)
            time_to_sleep = 1.0 if not batch else 0.05
            self._stop.wait(time_to_sleep)

    def _flush(self, batch: List[str]) -> None:
        url = f"{self.settings.influx_url.rstrip('/')}/api/v2/write"
        params = {
            "org": self.settings.influx_org,
            "bucket": self.settings.influx_bucket,
            "precision": "s",
        }
        headers = {
            "Authorization": f"Token {self.settings.influx_token}",
            "Content-Type": "text/plain; charset=utf-8",
        }
        payload = "\n".join(batch)
        try:
            response = httpx.post(url, params=params, headers=headers,
                                  content=payload.encode("utf-8"), timeout=5.0)
            if response.status_code >= 300:
                self.failed += len(batch)
                logger.warning("InfluxDB 写入失败: HTTP %s %s", response.status_code, response.text[:200])
            else:
                self.written += len(batch)
        except Exception as exc:
            self.failed += len(batch)
            logger.warning("InfluxDB 写入异常: %s", exc)

    @property
    def stats(self) -> Dict[str, object]:
        return {"enabled": self.enabled, "written": self.written, "failed": self.failed,
                "buffered": len(self._buffer)}


def _escape(value: str) -> str:
    return (value or "unknown").replace(",", "_").replace(" ", "_")
