"""采集编排服务：流量 → 聚合快照 → 检测 → 封禁 → 告警 → 大屏推送。

数据流（对应总体架构图的中心链路）：

    [eBPF/libpcap 采集] → _on_flow() 累加到滑动窗口
                              ↓ 每个 tick (默认 500ms)
                       构建 TrafficSnapshot（整机 + 端口 + 源）
                              ↓
                        DetectionEngine.evaluate() → 异常列表
                              ↓                       ↘
                     Blocker（白名单→防火墙→落库）      Notifier（钉钉/企微/邮件/Syslog）
                              ↓
                        EventBus → SSE → 大屏实时刷新
"""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter, deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import select

from ..alerting.notifier import Notifier
from ..analysis.enricher import AlertEnricher
from ..analysis.prompts import mask_ip
from ..analysis.traffic_advisor import TrafficAdvisor
from ..analysis.triage import TriageEngine
from ..auth import audit as audit_log
from ..bus import EventBus, bus as default_bus
from ..config import Settings, get_settings
from ..database import session_scope
from ..detection.engine import (
    SEVERITY_TEXT,
    Anomaly,
    ConnRecord,
    DetectionEngine,
    PortSample,
    SourceSample,
    TrafficSnapshot,
    meets_min_severity,
)
from ..detection.scoring import ScoringAggregator, compute_weight, rule_id_of
from ..detection.web_knowledge import WebAttackDetector, WebRequestEvent
from ..models import Alert, PortTrafficSample, Signal, TrafficSample, utcnow
from ..response.blocker import Blocker
from ..scanner.assets import AssetManager
from ..scanner.vulnerability import (
    persist_matches,
    refresh_asset_vuln_counters,
    to_traffic_match,
)
from ..analysis.web_vuln_infer import WebVulnInferrer
from ..threat.store import purge_old_events, save_threat_event
from .http_events import build_web_source
from .ring import SlidingWindow, TimeSeries
from .sink_influx import InfluxSink
from .sources import FlowEvent, TrafficSource, build_source, is_private_ip

logger = logging.getLogger(__name__)

LOCAL_IPS = {"127.0.0.1", "0.0.0.0", "::1"}


class CollectorService:
    """单进程内的采集 + 检测 + 响应编排器（线程安全）。"""

    def __init__(self, settings: Optional[Settings] = None,
                 source: Optional[TrafficSource] = None,
                 engine: Optional[DetectionEngine] = None,
                 blocker: Optional[Blocker] = None,
                 notifier: Optional[Notifier] = None,
                 assets: Optional[AssetManager] = None,
                 event_bus: Optional[EventBus] = None,
                 aggregator: Optional[ScoringAggregator] = None,
                 enricher: Optional[AlertEnricher] = None) -> None:
        self.settings = settings or get_settings()
        self.source = source
        self.engine = engine or DetectionEngine(self.settings)
        self.notifier = notifier or Notifier(self.settings)
        self.blocker = blocker or Blocker(self.settings, notifier=self.notifier)
        self.assets = assets or AssetManager(self.settings)
        self.bus = event_bus or default_bus

        # ---- Web 攻击检测（HTTP 请求侧，知识库驱动）----
        self.web_detector = WebAttackDetector(self.settings)
        self.web_source = None
        self._web_queue: Deque[WebRequestEvent] = deque(maxlen=int(self.settings.web_queue_size))
        self.web_processed = 0
        self.web_dropped = 0

        # ---- 告警聚合评分（滑动窗口 + 直达机制）与异步 AI 研判 ----
        self.aggregator = aggregator or ScoringAggregator(self.settings)
        self.enricher = enricher or AlertEnricher(self.settings, event_bus=self.bus)
        self.traffic_advisor = TrafficAdvisor(self.settings)
        self.triage = TriageEngine(self.settings)
        self._last_purge_at = 0.0
        self._last_threat_purge_at = 0.0

        # ---- 攻击流量 → 漏洞判定（注入类漏洞没有版本特征，只有被打过才知道）----
        self.vuln_inferrer = WebVulnInferrer(self.settings)
        self._vuln_infer_at: Dict[str, float] = {}

        # ---- 滑动窗口 ----
        self.port_window = SlidingWindow(window_sec=10.0)      # (port, proto) -> pkts/bytes
        self.src_window = SlidingWindow(window_sec=10.0)        # src_ip -> pkts/bytes
        self.port_hits = SlidingWindow(window_sec=max(10, self.settings.port_scan_window_sec))
        self.rst_window = SlidingWindow(window_sec=10.0)
        self.syn_window = SlidingWindow(window_sec=10.0)        # src_ip -> SYN 包数
        self._lock = threading.RLock()
        self._conn_table: Dict[Tuple[str, int, str, int, str], ConnRecord] = {}

        # ---- 累计量与趋势 ----
        self._totals = {"in_pkts": 0, "in_bytes": 0, "out_pkts": 0, "out_bytes": 0}
        self._last_totals = dict(self._totals)
        self._last_tick_at = time.time()
        self._last_persist_at = 0.0
        self._started_at = time.time()
        self._ticks = 0
        self.trend_bps_in = TimeSeries(self.settings.trend_points)
        self.trend_bps_out = TimeSeries(self.settings.trend_points)
        self.trend_pps_in = TimeSeries(self.settings.trend_points)
        self.trend_pps_out = TimeSeries(self.settings.trend_points)
        self.trend_conns = TimeSeries(self.settings.trend_points)
        self.snapshots: Deque[Dict[str, Any]] = deque(maxlen=self.settings.trend_points)
        self.latest_snapshot: Dict[str, Any] = {}
        self.influx = InfluxSink(self.settings)

        # ---- 运行状态 ----
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.capture_mode = "unknown"
        self.last_error = ""
        self.alerts_emitted = 0
        self.alerts_suppressed = 0
        self.blocks_triggered = 0

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        self.blocker.whitelist.load_from_db()
        self.blocker.start_reaper()
        self.influx.start()
        self.enricher.start()

        self.source = self.source or build_source(
            self.settings.capture_mode, self.settings.capture_iface, self.settings.bpf_filter
        )
        try:
            self.source.start(self._on_flow)
            self.capture_mode = self.source.name
        except Exception as exc:
            logger.warning("采集源 %s 启动失败（%s），降级为仿真数据源", self.source.name, exc)
            self.last_error = str(exc)
            from .sources import DemoSource

            self.source = DemoSource(iface="demo0")
            self.source.start(self._on_flow)
            self.capture_mode = self.source.name

        self._stop.clear()
        self._started_at = time.time()
        self._start_web_detection()
        self._thread = threading.Thread(target=self._tick_loop, name="collector-tick", daemon=True)
        self._thread.start()
        logger.info("采集服务已启动：mode=%s tick=%sms", self.capture_mode, self.settings.tick_interval_ms)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        if self.web_source is not None:
            try:
                self.web_source.stop()
            except Exception:
                logger.debug("停止 Web 请求源异常", exc_info=True)
            self.web_source = None
        if self.source is not None:
            try:
                self.source.stop()
            except Exception:
                logger.debug("停止采集源异常", exc_info=True)
        self.blocker.stop_reaper()
        self.influx.stop()
        self.enricher.stop()
        logger.info("采集服务已停止")

    # ------------------------------------------------------------------ #
    # Web 攻击检测（HTTP 请求侧）
    # ------------------------------------------------------------------ #
    def _start_web_detection(self) -> None:
        """启动 HTTP 请求源（日志 tail / 仿真 / 仅 API 投递），失败时降级为纯 API 模式。"""
        if not self.settings.web_detect_enabled:
            logger.info("Web 攻击检测已在配置中关闭（WEB_DETECT_ENABLED=false）")
            return
        try:
            self.web_source = build_web_source(self.settings)
            if self.web_source is None:
                return
            self.web_source.start(self._on_http_request)
            logger.info("Web 攻击检测已启动：来源=%s，知识库 %s（%d 条规则 / %d 个大类）",
                        self.web_source.name, self.web_detector.kb.version,
                        len(self.web_detector.kb.rules), len(self.web_detector.kb.categories))
        except Exception as exc:
            logger.warning("Web 请求源启动失败（%s），Web 攻击检测降级为 API 投递模式", exc)
            self.web_source = None

    def _on_http_request(self, event: WebRequestEvent) -> None:
        """HTTP 请求回调（必须极轻量）：只入队，检测在 tick 内批量执行。"""
        if self._web_queue.maxlen and len(self._web_queue) >= self._web_queue.maxlen:
            self.web_dropped += 1
        self._web_queue.append(event)

    def _drain_web_requests(self, now: float) -> int:
        """把队列中的请求送进检测器，命中即复用告警 / 封禁闭环。"""
        if not self.settings.web_detect_enabled or not self._web_queue:
            return 0
        batch = min(len(self._web_queue), int(self.settings.web_detect_batch))
        emitted = 0
        for _ in range(batch):
            try:
                event = self._web_queue.popleft()
            except IndexError:
                break
            self.web_processed += 1
            try:
                for anomaly in self.web_detector.evaluate(event, now):
                    if self._handle_anomaly(anomaly, now) is not None:
                        emitted += 1
            except Exception:
                logger.exception("Web 请求检测失败：%s %s", event.method, event.path)
        return emitted

    def ingest_web_requests(self, payloads: Sequence[Dict[str, Any]],
                            now: Optional[float] = None) -> List[Dict[str, Any]]:
        """外部投递（WAF / 反向代理 / 业务系统）：立即检测并走完整处置闭环。

        返回值只包含**实际产生告警**的事件（未达聚合阈值 / 冷却期内的信号会被记录到
        signals 表并在 /signals 可查，但不算"告警"）—— 这样调用方能准确区分两种结果。
        """
        moment = float(now or time.time())
        results: List[Dict[str, Any]] = []
        for payload in list(payloads)[: int(self.settings.web_detect_batch)]:
            self.web_processed += 1
            for anomaly in self.web_detector.ingest(payload, moment):
                alert = self._handle_anomaly(anomaly, moment)
                if alert is not None:
                    results.append(alert)
        return results

    def web_stats(self) -> Dict[str, object]:
        return {
            **self.web_detector.stats,
            "source_name": getattr(self.web_source, "name", "off") if self.web_source else "off",
            "source_desc": getattr(self.web_source, "description", "") if self.web_source else "",
            "source_running": bool(self.web_source.running) if self.web_source else False,
            "queued": len(self._web_queue),
            "processed": self.web_processed,
            "dropped": self.web_dropped,
            # 日志源可观测性：parsed=成功解析行数，skipped=格式不匹配行数。
            # 两者长期为 0 说明日志路径不可读或 tail 线程已退出，便于现场排障。
            "parsed": int(getattr(self.web_source, "parsed_lines", 0) or 0),
            "skipped": int(getattr(self.web_source, "skipped_lines", 0) or 0),
        }

    # ------------------------------------------------------------------ #
    # 采集回调（每个流量事件调用一次，必须极轻量）
    # ------------------------------------------------------------------ #
    def _on_flow(self, flow: FlowEvent) -> None:
        try:
            ts = flow.ts or time.time()
            self.port_window.add((flow.dst_port, flow.proto), ts, flow.packets, flow.nbytes)
            self.src_window.add(flow.src_ip, ts, flow.packets, flow.nbytes)
            self.port_hits.add((flow.src_ip, flow.dst_port), ts, flow.packets, flow.nbytes)
            if flow.proto == "TCP":
                if "R" in (flow.flags or ""):
                    self.rst_window.add(flow.src_ip, ts, flow.packets, flow.nbytes)
                if "S" in (flow.flags or ""):
                    self.syn_window.add(flow.src_ip, ts, flow.packets, flow.nbytes)

            key_conn = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.proto)
            with self._lock:
                record = self._conn_table.get(key_conn)
                if record is None:
                    self._conn_table[key_conn] = ConnRecord(
                        key=key_conn, src_ip=flow.src_ip, dst_ip=flow.dst_ip,
                        dst_port=flow.dst_port, proto=flow.proto, src_port=flow.src_port,
                        first_seen=ts, last_seen=ts, packets=flow.packets, nbytes=flow.nbytes,
                    )
                else:
                    record.last_seen = ts
                    record.packets += flow.packets
                    record.nbytes += flow.nbytes

                if flow.direction == "out":
                    self._totals["out_pkts"] += flow.packets
                    self._totals["out_bytes"] += flow.nbytes
                else:
                    self._totals["in_pkts"] += flow.packets
                    self._totals["in_bytes"] += flow.nbytes

            self.assets.observe_flow(flow)      # 被动资产发现
        except Exception:
            logger.exception("处理流量事件失败")

    # ------------------------------------------------------------------ #
    # tick 循环
    # ------------------------------------------------------------------ #
    def _tick_loop(self) -> None:
        while not self._stop.is_set():
            started = time.time()
            try:
                self._tick()
            except Exception:
                logger.exception("聚合 tick 异常")
            elapsed = time.time() - started
            time.sleep(max(0.0, self.settings.tick_interval_sec - elapsed))

    def _tick(self) -> None:
        now = time.time()
        interval = max(1e-3, now - self._last_tick_at)
        snapshot = self._build_snapshot(now, interval)
        self._last_tick_at = now
        self._ticks += 1

        metrics = {
            "ts": round(now, 3),
            "interval_ms": int(interval * 1000),
            "iface": self.source.iface if self.source else "",
            "mode": self.capture_mode,
            "bps_in": round(snapshot.bps_in, 2),
            "bps_out": round(snapshot.bps_out, 2),
            "pps_in": round(snapshot.pps_in, 2),
            "pps_out": round(snapshot.pps_out, 2),
            "conns": snapshot.conns,
            "unique_src": snapshot.unique_src,
            "unique_dst_ports": snapshot.unique_dst_ports,
            "packets_total": int(self._totals["in_pkts"] + self._totals["out_pkts"]),
            "bytes_total": int(self._totals["in_bytes"] + self._totals["out_bytes"]),
            "kpi": self.kpi(),
            "ports": [self._port_to_dict(sample) for sample in
                      sorted(snapshot.ports, key=lambda item: item.bps, reverse=True)[:12]],
        }
        self.latest_snapshot = metrics
        self.snapshots.append(metrics)
        self.bus.publish("metrics", metrics)

        self.trend_bps_in.add(snapshot.bps_in, now)
        self.trend_bps_out.add(snapshot.bps_out, now)
        self.trend_pps_in.add(snapshot.pps_in, now)
        self.trend_pps_out.add(snapshot.pps_out, now)
        self.trend_conns.add(snapshot.conns, now)
        self.influx.write_metrics(self.source.iface if self.source else "unknown", {
            "bps_in": snapshot.bps_in, "bps_out": snapshot.bps_out,
            "pps_in": snapshot.pps_in, "pps_out": snapshot.pps_out, "conns": snapshot.conns,
        })

        # 检测 → 处置闭环
        for anomaly in self.engine.evaluate(snapshot):
            self._handle_anomaly(anomaly, now)

        # Web 攻击检测（HTTP 请求侧，知识库驱动）→ 复用同一套告警/封禁/推送闭环
        self._drain_web_requests(now)

        # 评分窗口 / 冷却记录定期清理（避免长期运行内存膨胀）
        if now - self._last_purge_at >= 60.0:
            self.aggregator.purge(now)
            self._last_purge_at = now

        # 威胁事件按留存天数清理（每小时一次，单批 5000，避免长事务）
        if now - self._last_threat_purge_at >= 3600.0:
            try:
                removed = purge_old_events(self.settings)
                if removed:
                    logger.info("已清理过期威胁事件 %d 条", removed)
            except Exception:
                logger.exception("威胁事件清理失败")
            self._last_threat_purge_at = now

        # 周期落库（关系库只存降采样样本，避免写放大）
        if now - self._last_persist_at >= 10.0:
            self._persist_samples(snapshot)
            self.assets.flush()
            self._last_persist_at = now

    # ------------------------------------------------------------------ #
    # 快照构建
    # ------------------------------------------------------------------ #
    def _build_snapshot(self, now: float, interval: float) -> TrafficSnapshot:
        standard_ports = set(self.settings.standard_ports)
        port_snapshot = self.port_window.snapshot(now)
        src_snapshot = self.src_window.snapshot(now)
        hit_snapshot = self.port_hits.snapshot(now)
        syn_snapshot = self.syn_window.snapshot(now)

        with self._lock:
            totals = dict(self._totals)
        in_bytes = max(0, totals["in_bytes"] - self._last_totals["in_bytes"])
        out_bytes = max(0, totals["out_bytes"] - self._last_totals["out_bytes"])
        in_pkts = max(0, totals["in_pkts"] - self._last_totals["in_pkts"])
        out_pkts = max(0, totals["out_pkts"] - self._last_totals["out_pkts"])
        self._last_totals = totals

        # 端口聚合：窗口累计值 → 速率
        port_pkts: Dict[Tuple[int, str], int] = {}
        port_bytes: Dict[Tuple[int, str], int] = {}
        port_sources: Dict[int, Dict[str, int]] = {}
        for (port, proto), (pkts, nbytes) in port_snapshot.items():
            port_pkts[(port, proto)] = pkts
            port_bytes[(port, proto)] = nbytes
        for (src_ip, port), (pkts, _nbytes) in hit_snapshot.items():
            port_sources.setdefault(port, {})[src_ip] = pkts

        window = max(1.0, self.port_window.window)
        ports: List[PortSample] = []
        for (port, proto), nbytes in sorted(port_bytes.items(), key=lambda item: item[1], reverse=True)[:64]:
            sources = port_sources.get(port, {})
            ports.append(PortSample(
                port=port, protocol=proto,
                pps=port_pkts.get((port, proto), 0) / window,
                bps=nbytes * 8 / window,
                conns=len(sources),
                is_standard=port in standard_ports,
                top_source=max(sources, key=sources.get) if sources else "",
            ))

        # 源聚合（含端口多样性、SYN 占比 —— 扫描/暴破判定的核心特征）
        src_hits: Dict[str, Dict[int, int]] = {}
        for (src_ip, port), (pkts, _nbytes) in hit_snapshot.items():
            src_hits.setdefault(src_ip, {})[port] = pkts

        self._prune_connections(now)
        with self._lock:
            conn_table = list(self._conn_table.values())
        src_dst_ips: Dict[str, set] = {}
        for record in conn_table:
            src_dst_ips.setdefault(record.src_ip, set()).add(record.dst_ip)

        sources: List[SourceSample] = []
        for src_ip, (pkts, nbytes) in sorted(src_snapshot.items(), key=lambda item: item[1][1], reverse=True)[:64]:
            syn_pkts = syn_snapshot.get(src_ip, (0, 0))[0]
            sources.append(SourceSample(
                ip=src_ip,
                pps=pkts / window, bps=nbytes * 8 / window,
                packets=pkts, nbytes=nbytes,
                unique_dst_ports=len(src_hits.get(src_ip, {})),
                unique_dst_ips=len(src_dst_ips.get(src_ip, ())),
                conns=len(src_dst_ips.get(src_ip, ())),
                syn_packets=int(syn_pkts),
                dst_port_hits=dict(src_hits.get(src_ip, {})),
            ))

        return TrafficSnapshot(
            ts=now, interval=interval,
            total_bps=(in_bytes + out_bytes) * 8 / interval,
            total_pps=(in_pkts + out_pkts) / interval,
            bps_in=in_bytes * 8 / interval, bps_out=out_bytes * 8 / interval,
            pps_in=in_pkts / interval, pps_out=out_pkts / interval,
            conns=len(conn_table), unique_src=len(src_snapshot),
            unique_dst_ports=len(port_snapshot),
            ports=ports, sources=sources,
        )

    def _prune_connections(self, now: float) -> int:
        """回收空闲连接（连接表只服务于 TOP 会话，不再参与检测判定）。"""
        idle_timeout = self.settings.conn_idle_timeout_sec
        expired: List[Tuple[str, int, str, int, str]] = []
        with self._lock:
            for key, record in self._conn_table.items():
                if now - record.last_seen > idle_timeout:
                    expired.append(key)
            for key in expired:
                self._conn_table.pop(key, None)
            return len(self._conn_table)

    # ------------------------------------------------------------------ #
    # 告警与自动封禁
    # ------------------------------------------------------------------ #
    #: 同一 (目标 IP, 端口) 的漏洞研判最小间隔（秒）：刷屏攻击下避免把研判变成热点
    VULN_INFER_COOLDOWN_SEC = 30.0

    def _save_threat(self, anomaly: Anomaly, *, alert_id: Optional[int],
                     triage: Optional[Dict[str, Any]] = None) -> Optional[int]:
        """落威胁事件 + 顺手更新该服务的漏洞结论（两条路径的公共入口）。"""
        event_id = save_threat_event(anomaly, alert_id=alert_id,
                                     settings=self.settings, triage=triage)
        self._infer_vuln_from_traffic(anomaly)
        return event_id

    def _infer_vuln_from_traffic(self, anomaly: Anomaly) -> None:
        """Web 攻击命中后把「这个服务的这类漏洞」落到漏洞表。

        为什么放在检测链路里：注入/上传/包含这类漏洞没有版本特征，主动漏扫看不见；
        只有"被打过且打穿了"才判得出来。这里只跑规则研判（不调模型，不拖慢 tick），
        AI 复核由资产详情的「按攻击流量研判漏洞」按钮触发。
        """
        if not getattr(self.settings, "web_vuln_infer_enabled", True):
            return
        if str(getattr(anomaly, "detector", "") or "") != "web-kb":
            return
        ip = str(anomaly.dest_ip or "")
        if not ip:
            return
        key = f"{ip}:{int(anomaly.dest_port or 0)}"
        now = time.time()
        if now - self._vuln_infer_at.get(key, 0.0) < self.VULN_INFER_COOLDOWN_SEC:
            return
        self._vuln_infer_at[key] = now
        try:
            findings = self.vuln_inferrer.infer(ip, use_ai=False)
            if not findings:
                return
            matches = [to_traffic_match(item) for item in findings]
            persist_matches(ip, matches)
            refresh_asset_vuln_counters(ip)
            logger.info("[漏洞研判] %s 由攻击流量推出 %d 条漏洞结论", ip, len(matches))
        except Exception:
            logger.exception("攻击流量漏洞研判失败：%s", ip)

    def _handle_anomaly(self, anomaly: Anomaly, now: float) -> Optional[Dict[str, Any]]:
        """告警闭环入口：signal → 聚合评分（直达/聚合）→ 落库 → 封禁 → 通知 → SSE → AI 研判。

        评分聚合是**同步、立即返回**的（不等待窗口到期），因此不会拖慢 tick 节奏；
        未达阈值的信号也会落库（signals 表）并计入统计 —— 禁止静默丢弃（硬约束 6）。

        返回实际发出的告警 payload；被抑制时返回 None（调用方据此区分"检测到"与"已告警"）。
        """
        # 研判在聚合之前执行：只改结论/分值，不直接封禁（封禁仍走五道闸门）。
        triage = self.triage.evaluate(anomaly, now)
        if triage:
            anomaly.evidence = {**(anomaly.evidence or {}), "triage": triage}
            base_weight = float(anomaly.weight or compute_weight(anomaly.severity, anomaly.confidence))
            anomaly.weight = max(0.0, base_weight + float(triage.get("score_delta") or 0.0))
            if triage.get("action") in {"suppress_alert"} or triage.get("verdict") == "benign":
                signal = self._build_signal(anomaly, now)
                signal.suppressed = True
                signal.suppressed_reason = f"triage:{triage.get('rule_id')}"
                self._save_signal(signal)
                self._save_threat(anomaly, alert_id=None, triage=triage)
                self.alerts_suppressed += 1
                self.bus.publish("signal", self._signal_payload(signal))
                logger.info("[研判抑制] %s | %s | %s | %s", anomaly.category, anomaly.source_ip,
                            triage.get("rule_id"), triage.get("reason"))
                return None

        signal = self._build_signal(anomaly, now)

        # 影子模式（v6 P2 误报标定）：全量规则照常运行并落威胁事件，但不告警、不封禁。
        if bool(getattr(self.settings, "rules_shadow_mode", False)):
            signal.suppressed = True
            signal.suppressed_reason = "shadow_mode"
            self._save_signal(signal)
            event_id = self._save_threat(anomaly, alert_id=None, triage=triage)
            signal.alert_id = None
            self.bus.publish("signal", self._signal_payload(signal))
            logger.info("[影子模式] %s | %s | 仅记录事件 #%s", anomaly.category,
                        anomaly.source_ip, event_id)
            return None

        aggregated = self.aggregator.add(signal, now)
        self._save_signal(signal)

        if aggregated is None:
            self.alerts_suppressed += 1
            # 聚合抑制不等于丢弃：威胁事件仍落库，威胁告警页「全部」可见。
            self._save_threat(anomaly, alert_id=None, triage=triage)
            self.bus.publish("signal", self._signal_payload(signal))
            logger.info("[信号] %s | %s | weight=%.1f | 抑制=%s", anomaly.category,
                        anomaly.source_ip, anomaly.weight, signal.suppressed_reason)
            return None

        payload = anomaly.to_dict()
        payload["ts_text"] = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        payload["ts"] = round(now, 3)
        payload.update({
            "risk_score": aggregated.risk_score,
            "direct_alert": aggregated.direct_alert,
            "contributing_rules": aggregated.contributing_rules,
            "signal_window_id": aggregated.signal_window_id,
            "signal_count": aggregated.signal_count,
            "aggregation": aggregated.evidence.get("aggregation", {}),
            "llm_analysis": None,
        })
        payload["message"] = f"{anomaly.message}｜{aggregated.message}"
        # 证据里合并"评分聚合"信息（前端详情抽屉直接读 evidence.aggregation，无需额外请求）
        aggregation = aggregated.evidence.get("aggregation", {})
        payload["evidence"] = {
            **(anomaly.evidence or {}),
            "aggregation": aggregation,
            "signals": list(aggregated.evidence.get("signals", []))[:20],
        }
        self.alerts_emitted += 1

        # 1) 落库（含新增的评分/直达/窗口字段）
        payload["alert_id"] = self._save_alert(anomaly, now, payload)
        self._attach_signal_alert(signal, payload.get("alert_id"))
        payload["threat_event_id"] = self._save_threat(
            anomaly, alert_id=payload.get("alert_id"), triage=triage)

        # 2) 自动封禁（白名单 + 严重度门槛 + TTL 三重保护；门槛不因评分/研判而改变）
        #    Web 告警额外要求「直达规则确认」——签名类规则存在误报可能，宁可多一次人工确认也不误封。
        blocked = False
        web_needs_direct = (anomaly.detector == "web-kb"
                            and bool(getattr(self.settings, "web_auto_block_requires_direct", True))
                            and not anomaly.direct_alert)
        if (self.settings.auto_block_enabled and anomaly.source_ip
                and anomaly.source_ip not in LOCAL_IPS
                and not self.web_detector.is_ignored_source(anomaly.source_ip)
                and not web_needs_direct
                and meets_min_severity(anomaly.severity, self.settings.auto_block_min_severity)):
            block_result = self.blocker.block(
                ip=anomaly.source_ip,
                reason=f"[自动] {anomaly.category_text}：{anomaly.message}",
                category=anomaly.category, severity=anomaly.severity,
                source="auto", operator="system",
            )
            blocked = bool(block_result.get("success"))
            if blocked:
                self.blocks_triggered += 1
                audit_log("block", username="system", target=anomaly.source_ip,
                          detail=f"自动封禁 {anomaly.category} dry_run={self.settings.dry_run}")
            payload["block_command"] = block_result.get("command", "")
            payload["block_message"] = block_result.get("message", "")
        payload["blocked"] = blocked
        payload["dry_run"] = self.settings.dry_run

        # 3) 通知（多通道扇出，单通道失败不影响其它通道）
        try:
            payload["notify"] = self.notifier.dispatch(payload)
        except Exception:
            logger.exception("告警通知失败")
            payload["notify"] = {}

        # 4) 推送大屏 + 时序库
        self.bus.publish("alert", payload)
        self.influx.write_alert(payload)
        logger.warning("[告警] %s | %s | risk=%.2f direct=%s | %s", anomaly.category,
                       anomaly.source_ip, aggregated.risk_score, aggregated.direct_alert,
                       anomaly.message)

        # 5) AI 研判（后台线程，不阻塞 tick；结果通过 alert_enriched 事件回推）
        if payload.get("alert_id") is not None:
            self.enricher.submit(payload["alert_id"])
        return payload

    def _save_alert(self, anomaly: Anomaly, now: float,
                    payload: Optional[Dict[str, Any]] = None) -> Optional[int]:
        """落库：新增字段（risk_score / contributing_rules / direct_alert / signal_window_id）
        全部来自评分聚合结果；老字段语义保持不变（只增不删，满足接口契约要求）。"""
        extra = payload or {}
        try:
            with session_scope() as session:
                row = Alert(
                    ts=datetime.fromtimestamp(now), source_ip=anomaly.source_ip or "",
                    dest_ip=anomaly.dest_ip or "", dest_port=anomaly.dest_port or 0,
                    protocol=anomaly.protocol, category=anomaly.category,
                    severity=anomaly.severity, score=anomaly.score,
                    message=extra.get("message") or anomaly.message,
                    evidence=extra.get("evidence") or anomaly.evidence,
                    status="open", region="内网" if is_private_ip(anomaly.source_ip) else "互联网",
                    risk_score=float(extra.get("risk_score") or anomaly.weight or 0.0),
                    contributing_rules=list(extra.get("contributing_rules") or []),
                    direct_alert=bool(extra.get("direct_alert") or anomaly.direct_alert),
                    signal_window_id=extra.get("signal_window_id"),
                )
                session.add(row)
                session.flush()
                return row.id
        except Exception:
            logger.exception("告警落库失败")
            return None

    # ------------------------------------------------------------------ #
    # 评分链路：signal 构造 / 落库 / 事件
    # ------------------------------------------------------------------ #
    def _build_signal(self, anomaly: Anomaly, now: float) -> Signal:
        """把异常翻译成评分用的 signal（补齐规则 ID / 置信度 / 权重 / 直达标记）。"""
        if not anomaly.rule_id:
            anomaly.rule_id = rule_id_of(anomaly.category)
        if not anomaly.weight:
            anomaly.weight = round(compute_weight(anomaly.severity, anomaly.confidence), 3)
        return Signal(
            ts=datetime.fromtimestamp(now),
            source_ip=anomaly.source_ip or "",
            dst_port=anomaly.dest_port or 0,
            rule_id=anomaly.rule_id,
            category=anomaly.category,
            severity=anomaly.severity,
            confidence=anomaly.confidence,
            weight=float(anomaly.weight),
            direct_alert=bool(anomaly.direct_alert),
            signal_window_id=self.aggregator.new_window_id(),
            evidence={
                "detector": anomaly.detector,
                "score": anomaly.score,
                "rule_source": anomaly.rule_source,
                "message": anomaly.message[:300],
                "evidence": anomaly.evidence,
            },
        )

    def _save_signal(self, signal: Signal) -> Optional[int]:
        """每个 signal 都落库（含被抑制的），用于审计与前端「窗口信号」展示。"""
        try:
            with session_scope() as session:
                session.add(signal)
                session.flush()
                return signal.id
        except Exception:
            logger.exception("信号落库失败")
            return None

    def _attach_signal_alert(self, signal: Signal, alert_id: Optional[int]) -> None:
        if alert_id is None or signal.id is None:
            return
        try:
            with session_scope() as session:
                row = session.get(Signal, signal.id)
                if row is not None:
                    row.alert_id = alert_id
        except Exception:
            logger.exception("信号关联告警失败")

    def _signal_payload(self, signal: Signal) -> Dict[str, Any]:
        """推给大屏的 signal 事件（供页面显示"已抑制的信号"，避免静默丢弃）。"""
        moment = signal.ts or datetime.now()
        return {
            "id": signal.id,
            "ts": moment.timestamp(),
            "ts_text": moment.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": signal.source_ip,
            "category": signal.category,
            "rule_id": signal.rule_id,
            "severity": signal.severity,
            "severity_text": SEVERITY_TEXT.get(signal.severity, signal.severity),
            "weight": round(float(signal.weight or 0.0), 2),
            "suppressed": bool(signal.suppressed),
            "suppressed_reason": signal.suppressed_reason,
            "direct_alert": bool(signal.direct_alert),
            "score_contribution": signal.score_contribution,
            "signal_window_id": signal.signal_window_id,
        }

    def scoring_stats(self) -> Dict[str, object]:
        """评分链路 + AI 研判定级统计（供 /status、/scoring/config 使用）。"""
        return {
            "aggregator": self.aggregator.stats,
            "alert_suppressed": self.alerts_suppressed,
            "alert_emitted": self.alerts_emitted,
            "enricher": self.enricher.stats,
        }

    def _persist_samples(self, snapshot: TrafficSnapshot) -> None:
        """降采样落库：整机样本 + TOP 端口样本（历史回看与大屏长周期查询用）。"""
        moment = datetime.fromtimestamp(snapshot.ts)
        try:
            with session_scope() as session:
                session.add(TrafficSample(
                    ts=moment, iface=self.source.iface if self.source else "",
                    bps_in=snapshot.bps_in, bps_out=snapshot.bps_out,
                    pps_in=snapshot.pps_in, pps_out=snapshot.pps_out,
                    conns=snapshot.conns, unique_src=snapshot.unique_src,
                    unique_dst_ports=snapshot.unique_dst_ports,
                ))
                for sample in snapshot.ports[:16]:
                    session.add(PortTrafficSample(
                        ts=moment, port=sample.port, protocol=sample.protocol,
                        is_standard=sample.is_standard, conns=sample.conns,
                        bps=sample.bps, pps=sample.pps, top_source=sample.top_source,
                    ))
            self.influx.write_ports([self._port_to_dict(sample) for sample in snapshot.ports[:16]])
        except Exception:
            logger.exception("流量样本落库失败")

    # ------------------------------------------------------------------ #
    # 对外查询接口（供 API 层调用）
    # ------------------------------------------------------------------ #
    def kpi(self) -> Dict[str, object]:
        latest = self.latest_snapshot
        capacity = max(1.0, float(self.settings.link_speed_mbps) * 1_000_000)
        if not latest:
            return {"bps": 0.0, "bandwidth_util": 0.0, "pps": 0.0, "conns": 0, "unique_src": 0,
                    "unique_dst_ports": 0, "packets_total": 0, "bytes_total": 0,
                    "mode": self.capture_mode, "iface": "", "uptime_sec": 0.0}
        bps = float(latest.get("bps_in", 0)) + float(latest.get("bps_out", 0))
        pps = float(latest.get("pps_in", 0)) + float(latest.get("pps_out", 0))
        return {
            "bps": round(bps, 2),
            "bandwidth_util": round(min(100.0, bps / capacity * 100), 3),
            "pps": round(pps, 2),
            "conns": int(latest.get("conns", 0)),
            "unique_src": int(latest.get("unique_src", 0)),
            "unique_dst_ports": int(latest.get("unique_dst_ports", 0)),
            "packets_total": int(latest.get("packets_total", 0)),
            "bytes_total": int(latest.get("bytes_total", 0)),
            "mode": self.capture_mode,
            "iface": latest.get("iface", ""),
            "uptime_sec": round(time.time() - self._started_at, 1),
        }

    def portfolio(self) -> Dict[str, object]:
        """大屏首屏一次性拉全量实时数据，减少请求数。"""
        latest = self.latest_snapshot
        return {
            "kpi": self.kpi(),
            "trend": self.trend_data(120),
            "ports": latest.get("ports", []),
            "latest": latest,
            "engine": self.engine.stats,
        }

    def trend_data(self, window_sec: int = 120) -> Dict[str, object]:
        since = time.time() - max(5, window_sec)
        return {
            "window_sec": window_sec,
            "interval_ms": self.settings.tick_interval_ms,
            "bps_in": self.trend_bps_in.points(since),
            "bps_out": self.trend_bps_out.points(since),
            "pps_in": self.trend_pps_in.points(since),
            "pps_out": self.trend_pps_out.points(since),
            "conns": self.trend_conns.points(since),
        }

    def port_stats(self, top: int = 12) -> List[Dict[str, object]]:
        return list(self.latest_snapshot.get("ports", []))[:top]

    def port_baseline(self) -> List[Dict[str, object]]:
        """端口基线视图：当前值 vs EWMA 基线（供「异常端口流量检测」页使用）。

        异常优先排序，其次按流量降序；每条含基线均值/标准差/Z 值/偏离倍数，
        便于运维判断"是真异常还是业务增长"。
        """
        detector = self.engine.port_pps
        rows: List[Dict[str, object]] = []
        for sample in self.latest_snapshot.get("ports", []):
            base = detector.baseline(sample["port"])
            zscore = base.zscore(sample["pps"], floor_std=detector.floor_std) if base.ready else 0.0
            anomaly = bool(sample.get("anomaly")) or (base.ready and zscore >= detector.threshold)
            rows.append({
                **sample,
                "baseline_mean_pps": round(base.mean, 2),
                "baseline_std": round(base.std, 2),
                "zscore": round(zscore, 2),
                "deviation_ratio": round(sample["pps"] / base.mean, 2) if base.mean > 0 else None,
                "baseline_samples": base.samples,
                "baseline_ready": base.ready,
                "anomaly": anomaly,
            })
        rows.sort(key=lambda item: (not item["anomaly"], -float(item.get("bps") or 0)))
        return rows

    # ------------------------------------------------------------------ #
    # AI 流量研判（只发送聚合摘要；结果仅建议，不改变封禁判定）
    # ------------------------------------------------------------------ #
    def ai_traffic_digest(self, window_minutes: int = 10) -> Dict[str, Any]:
        """构造可交给 LLM 的窗口摘要（结构化数值 + 类别计数，不含原始载荷）。"""
        latest = self.latest_snapshot or {}
        # 与 Alert.ts / Signal.ts 的写入口径保持一致：均为本地时间的 naive datetime
        since = datetime.fromtimestamp(time.time() - max(1, int(window_minutes)) * 60)
        try:
            with session_scope() as session:
                alerts = session.scalars(
                    select(Alert).where(Alert.ts >= since)
                    .order_by(Alert.ts.desc()).limit(200)
                ).all()
                signals = session.scalars(
                    select(Signal).where(Signal.ts >= since)
                    .order_by(Signal.ts.desc()).limit(200)
                ).all()
        except Exception:      # pragma: no cover - 防御性：研判不应影响采集
            logger.exception("读取 AI 研判窗口数据失败")
            alerts, signals = [], []

        ports = [{
            "port": item.get("port"), "protocol": item.get("protocol"),
            "pps": item.get("pps"), "is_standard": item.get("is_standard"),
            "top_source": mask_ip(item.get("top_source"), True),
        } for item in (latest.get("ports") or [])[:8]]
        return {
            "window": {
                "minutes": int(window_minutes),
                "bps_in": latest.get("bps_in", 0), "bps_out": latest.get("bps_out", 0),
                "pps_in": latest.get("pps_in", 0), "pps_out": latest.get("pps_out", 0),
                "conns": latest.get("conns", 0), "unique_src": latest.get("unique_src", 0),
                "unique_dst_ports": latest.get("unique_dst_ports", 0),
            },
            "ports": ports,
            "alerts": {
                "total": len(alerts),
                "direct_count": sum(1 for item in alerts if item.direct_alert),
                "high_count": sum(1 for item in alerts
                                  if item.severity in ("critical", "high")),
                "max_risk_score": round(max((item.risk_score or 0.0) for item in alerts), 2)
                if alerts else 0.0,
                "categories": dict(Counter(item.category for item in alerts).most_common(8)),
            },
            "signals": dict(Counter(item.category for item in signals
                                    if not item.suppressed).most_common(8)),
            "threshold": self.aggregator.threshold,
            "thresholds": {key: round(value, 3) for key, value in self.engine.thresholds.items()},
        }

    def ai_traffic_review(self, window_minutes: int = 10) -> Dict[str, Any]:
        digest = self.ai_traffic_digest(window_minutes)
        result = self.traffic_advisor.review(digest)
        result["window"] = digest
        return result

    def top_sessions(self, top: int = 20) -> List[Dict[str, object]]:
        """实时 TOP 会话（供「实时动态流量监控」页的会话明细表）。"""
        now = time.time()
        with self._lock:
            records = list(self._conn_table.values())
        records.sort(key=lambda item: item.nbytes, reverse=True)
        sessions: List[Dict[str, object]] = []
        for record in records[:top]:
            duration = max(0.5, record.duration)
            sessions.append({
                "src_ip": record.src_ip, "src_port": record.src_port,
                "dst_ip": record.dst_ip, "dst_port": record.dst_port,
                "protocol": record.proto,
                "duration_sec": round(duration, 1),
                "idle_sec": round(max(0.0, now - record.last_seen), 1),
                "packets": record.packets, "bytes": record.nbytes,
                "bps": round(record.nbytes * 8 / duration, 2),
                "pps": round(record.packets / duration, 2),
                "is_internal": is_private_ip(record.dst_ip),
            })
        return sessions

    def status(self) -> Dict[str, object]:
        return {
            "running": bool(self._thread is not None and self._thread.is_alive()),
            "capture_mode": self.capture_mode,
            "iface": self.source.iface if self.source else "",
            "source_desc": getattr(self.source, "description", "") if self.source else "",
            "tick_interval_ms": self.settings.tick_interval_ms,
            "ticks": self._ticks,
            "uptime_sec": round(time.time() - self._started_at, 1),
            "conn_table": len(self._conn_table),
            "alerts_emitted": self.alerts_emitted,
            "alerts_suppressed": self.alerts_suppressed,
            "blocks_triggered": self.blocks_triggered,
            "last_error": self.last_error,
            "engine": self.engine.stats,
            "scoring": self.scoring_stats(),
            "web": self.web_stats(),
            "influx": self.influx.stats,
            "notifier": self.notifier.stats,
            "firewall": {"backend": self.blocker.backend.name, "dry_run": self.blocker.backend.dry_run},
        }

    @staticmethod
    def _port_to_dict(sample: PortSample) -> Dict[str, object]:
        return {
            "port": sample.port, "protocol": sample.protocol,
            "pps": round(sample.pps, 2), "bps": round(sample.bps, 2),
            "conns": sample.conns, "is_standard": sample.is_standard,
            "top_source": sample.top_source, "anomaly": not sample.is_standard,
        }


service: Optional[CollectorService] = None


def get_service() -> CollectorService:
    """全局单例（FastAPI 依赖与后台任务共用同一个采集器）。"""
    global service
    if service is None:
        service = CollectorService()
    return service




