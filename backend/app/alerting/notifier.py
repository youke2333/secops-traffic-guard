"""告警通知调度：分级过滤、并发扇出、结果留痕。"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional

from ..config import Settings, get_settings
from ..detection.engine import SEVERITY_ORDER
from .channels import AlertChannel, build_channels

logger = logging.getLogger(__name__)


class Notifier:
    """把一条告警扇出到所有已装配通道，并记录最近发送结果供大屏/接口展示。"""

    HISTORY = 50

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.channels: List[AlertChannel] = build_channels(self.settings)
        self._history: Deque[Dict[str, object]] = deque(maxlen=self.HISTORY)
        self._lock = threading.Lock()
        self.sent_count = 0
        self.failed_count = 0

    # ---------------- 对外 ----------------
    def dispatch(self, anomaly: Dict[str, object], force: bool = False) -> Dict[str, object]:
        """发送告警。返回 {channel: (ok, message)} 结构。"""
        severity = str(anomaly.get("severity", "medium"))
        results: Dict[str, object] = {}
        for channel in self.channels:
            if not force and SEVERITY_ORDER.get(severity, 2) < SEVERITY_ORDER.get(channel.min_severity, 2):
                results[channel.name] = {"ok": False, "message": f"低于通道门槛 {channel.min_severity}"}
                continue
            try:
                ok, message = channel.send(anomaly)
            except Exception as exc:  # pragma: no cover - 防御式
                logger.exception("告警通道异常: %s", channel.name)
                ok, message = False, str(exc)
            results[channel.name] = {"ok": ok, "message": message}
            if ok:
                self.sent_count += 1
            else:
                self.failed_count += 1

        with self._lock:
            self._history.append({
                "ts": time.time(),
                "category": anomaly.get("category"),
                "category_text": anomaly.get("category_text"),
                "severity": severity,
                "source_ip": anomaly.get("source_ip"),
                "message": anomaly.get("message"),
                "channels": results,
            })
        return results

    def history(self, limit: int = 20) -> List[Dict[str, object]]:
        with self._lock:
            items = list(self._history)
        return list(reversed(items))[:limit]

    def test(self) -> Dict[str, object]:
        """通道连通性自检（运维接口用）。"""
        probe = {
            "category": "channel_test",
            "category_text": "通道自检",
            "severity": "high",
            "severity_text": "高危",
            "score": 1.0,
            "source_ip": "127.0.0.1",
            "dest_ip": "-",
            "dest_port": 0,
            "detector": "self-test",
            "message": "这是一条通道连通性测试消息，收到即表示告警链路正常。",
            "evidence": {"hint": "可在 .env 中关闭测试或调整阈值"},
            "ts_text": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        return {"channels": [channel.name for channel in self.channels], "results": self.dispatch(probe, force=True)}

    @property
    def stats(self) -> Dict[str, object]:
        return {
            "channels": [channel.name for channel in self.channels],
            "sent": self.sent_count,
            "failed": self.failed_count,
        }
