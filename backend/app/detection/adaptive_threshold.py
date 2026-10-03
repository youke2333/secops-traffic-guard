"""自适应基线阈值（方案第 3 层）：让检测阈值随「误报/真阳」反馈自动收放。

数据来源：`/alerts/{id}/ack`（确认关闭 = 误报）与自动/人工封禁（= 真阳）两类人工反馈。
维度：`detection_type × asset_class × time_bucket`（例如 端口扫描 × 服务器 × 工作时间）。

设计要点（三个决定，代码里必须保持一致）：

1. **只对统计型检测器生效**：traffic_spike / nonstandard_port / port_scan / brute_force。
   Web 攻击规则自带阈值（知识库 `threshold`）与冷却期，不参与本机制；
2. **直达机制不受本机制影响**：`direct_alert` 是规则固有属性，`DIRECT_ALERT_WEIGHT` 保持配置值。
   这是**有意为之**：避免自适应机制把对致命攻击（RCE / Webshell）的响应能力"调优"掉；
3. **调整幅度受限**：阈值始终被夹在 `[静态基准 × MIN_FACTOR, 静态基准 × MAX_FACTOR]` 内，
   且要求最小样本数，避免样本太少时把阈值推向极端。
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select

from ..config import Settings, get_settings
from ..database import session_scope
from ..models import Alert, Asset, ThresholdConfig
from ..timeutil import iso_local

logger = logging.getLogger(__name__)

# 参与自适应调整的检测类型（Web / 行为类检测器不参与）
ADAPTIVE_TYPES = ("traffic_spike", "nonstandard_port", "port_scan", "brute_force")

# 每个检测类型的资产口径（machine=本机；server=被访问服务；source=按来源 IP 资产属性）
ASSET_SCOPE = {
    "traffic_spike": "machine",
    "nonstandard_port": "server",
    "port_scan": "source",
    "brute_force": "source",
}

MIN_SAMPLES = 5          # 低于该样本数不做调整（避免噪声）
WORKHOUR_START = 9
WORKHOUR_END = 19


class AdaptiveThresholdManager:
    """维度化阈值的读取与重算（线程安全；读取路径带进程内缓存，不影响 tick 节奏）。"""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()
        self.enabled = bool(getattr(self.settings, "adaptive_threshold_enabled", True))
        self.cache_ttl = 30.0
        self._cache: Dict[Tuple[str, str, str], Tuple[float, float]] = {}
        self._lock = threading.Lock()
        self.last_recompute_at: float = 0.0
        self.last_recompute: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # 静态基准
    # ------------------------------------------------------------------ #
    def static_base(self, detection_type: str) -> float:
        cfg = self.settings
        if detection_type == "traffic_spike":
            return float(cfg.zscore_threshold)
        if detection_type == "nonstandard_port":
            return float(cfg.zscore_threshold) + 0.5
        if detection_type == "port_scan":
            return float(max(5, cfg.port_scan_unique_ports))
        if detection_type == "brute_force":
            return float(max(5, cfg.brute_force_attempts))
        return 0.0

    # ------------------------------------------------------------------ #
    # 读取（检测器调用路径：必须极轻量）
    # ------------------------------------------------------------------ #
    def threshold_for(self, detection_type: str, source_ip: str = "",
                      now: Optional[float] = None,
                      default: Optional[float] = None) -> float:
        """返回某检测类型当前生效阈值；无记录 / 功能关闭时回落静态基准。"""
        static = float(default if default is not None else self.static_base(detection_type))
        if not self.enabled:
            return static
        asset_class, bucket = self.dimensions(detection_type, source_ip, now)
        key = (detection_type, asset_class, bucket)
        with self._lock:
            cached = self._cache.get(key)
            if cached and (time.time() - cached[1]) < self.cache_ttl:
                return cached[0]
        value = self._read_db(detection_type, asset_class, bucket)
        resolved = float(value) if value is not None else static
        with self._lock:
            self._cache[key] = (resolved, time.time())
        return resolved

    def _read_db(self, detection_type: str, asset_class: str, bucket: str) -> Optional[float]:
        try:
            with session_scope() as session:
                row = session.scalars(
                    select(ThresholdConfig).where(
                        ThresholdConfig.detection_type == detection_type,
                        ThresholdConfig.asset_class == asset_class,
                        ThresholdConfig.time_bucket == bucket,
                    )
                ).first()
                if row is None:
                    # 退化到"不区分时间段"的记录（减少维度冷启动带来的空档）
                    row = session.scalars(
                        select(ThresholdConfig).where(
                            ThresholdConfig.detection_type == detection_type,
                            ThresholdConfig.asset_class == asset_class,
                            ThresholdConfig.time_bucket == "all",
                        )
                    ).first()
                return float(row.threshold_value) if row is not None else None
        except Exception:      # pragma: no cover - 数据库异常不应影响检测
            logger.exception("读取自适应阈值失败，已回落静态基准")
            return None

    def invalidate_cache(self) -> None:
        with self._lock:
            self._cache.clear()

    # ------------------------------------------------------------------ #
    # 维度计算
    # ------------------------------------------------------------------ #
    def dimensions(self, detection_type: str, source_ip: str = "",
                   now: Optional[float] = None) -> Tuple[str, str]:
        scope = ASSET_SCOPE.get(detection_type, "source")
        if scope == "machine":
            asset_class = "machine"
        elif scope == "server":
            asset_class = "server"
        else:
            asset_class = self.classify_asset(source_ip)
        moment = datetime.fromtimestamp(float(now or time.time()))
        return asset_class, self.bucket(moment)

    def classify_asset(self, source_ip: str) -> str:
        """基于白名单网段与资产台账推断来源类型：office / server / dmz / unknown。"""
        ip = (source_ip or "").strip()
        if not ip:
            return "unknown"
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        for item in self.settings.whitelist_cidrs:
            try:
                if address in ipaddress.ip_network(item, strict=False):
                    return "office"       # 白名单网段即为受信任办公/管理网段
            except ValueError:
                continue
        try:
            with session_scope() as session:
                asset = session.scalars(select(Asset).where(Asset.ip == ip)).first()
                if asset is not None:
                    tags = {str(tag).lower() for tag in (asset.tags or [])}
                    if "dmz" in tags:
                        return "dmz"
                    if {"web", "db", "api", "server"} & tags:
                        return "server"
        except Exception:      # pragma: no cover
            logger.debug("资产查询失败，来源类型回落 unknown", exc_info=True)
        return "unknown"

    @staticmethod
    def bucket(moment: datetime) -> str:
        """时间段分桶：workhour（工作日 09:00-19:00）/ offhour。"""
        if moment.weekday() >= 5:
            return "offhour"
        return "workhour" if WORKHOUR_START <= moment.hour < WORKHOUR_END else "offhour"

    # ------------------------------------------------------------------ #
    # 重算（后台定时任务 / POST /thresholds/recompute 触发）
    # ------------------------------------------------------------------ #
    def recompute(self, lookback_days: Optional[int] = None) -> Dict[str, Any]:
        """按维度统计误报率并调整阈值，写回 ThresholdConfig。

        误报/真阳判定口径（可审计）：
        * 真阳：告警被自动或人工封禁（`alert.blocked=True`）；
        * 误报：告警被人工确认关闭（`status=closed`）且未封禁；
        * 仍处于 open 的告警不计入统计（避免"没人处置"被当成误报）。
        """
        days = int(lookback_days or getattr(self.settings, "threshold_lookback_days", 14))
        stats: Dict[Tuple[str, str, str], Dict[str, int]] = {}
        for alert, asset_class in self._load_alerts(_since(days)):
            detection_type = str(alert.category)
            if detection_type not in ADAPTIVE_TYPES:
                continue
            bucket = self.bucket(alert.ts or _now())
            row = stats.setdefault((detection_type, asset_class, bucket),
                                   {"sample": 0, "fp": 0, "tp": 0})
            row["sample"] += 1
            if bool(alert.blocked):
                row["tp"] += 1
            elif str(alert.status) == "closed":
                row["fp"] += 1

        updated: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        with session_scope() as session:
            for (detection_type, asset_class, bucket), row in stats.items():
                existing = session.scalars(
                    select(ThresholdConfig).where(
                        ThresholdConfig.detection_type == detection_type,
                        ThresholdConfig.asset_class == asset_class,
                        ThresholdConfig.time_bucket == bucket,
                    )
                ).first()
                if existing is not None and existing.manual_override:
                    skipped.append({"detection_type": detection_type, "asset_class": asset_class,
                                    "time_bucket": bucket, "reason": "人工覆盖"})
                    continue
                static = self.static_base(detection_type)
                decided = row["fp"] + row["tp"]
                fp_rate = (row["fp"] / decided) if decided else 0.0
                current = float(existing.threshold_value) if existing is not None else static
                value = self._adjust(current, static, fp_rate, decided)
                record = existing or ThresholdConfig(
                    dimension="detection_type",
                    dimension_key=f"{detection_type}:{asset_class}:{bucket}",
                    detection_type=detection_type, asset_class=asset_class, time_bucket=bucket,
                )
                record.static_value = static
                record.threshold_value = value
                record.sample_count = row["sample"]
                record.false_positive_count = row["fp"]
                record.true_positive_count = row["tp"]
                record.false_positive_rate = round(fp_rate, 4)
                record.last_updated = _now()
                if existing is None:
                    session.add(record)
                updated.append({
                    "detection_type": detection_type, "asset_class": asset_class,
                    "time_bucket": bucket, "fp_rate": round(fp_rate, 4),
                    "sample": row["sample"], "threshold": round(value, 3),
                    "previous": round(current, 3), "static": static,
                    "action": "tighten" if value > current + 1e-9 else
                              ("loosen" if value < current - 1e-9 else "keep"),
                })
        self.invalidate_cache()
        self.last_recompute_at = time.time()
        self.last_recompute = {
            "lookback_days": days, "dimensions": len(stats), "updated": updated,
            "skipped": skipped, "computed_at": iso_local(_now()),
        }
        logger.info("阈值重算完成：维度 %d 个（更新 %d，跳过 %d）",
                    len(stats), len(updated), len(skipped))
        return self.last_recompute

    def _adjust(self, current: float, static: float, fp_rate: float, decided: int) -> float:
        """按误报率调整阈值：FP 高→收紧；FP 低→放松；带上下限与最小样本约束。"""
        cfg = self.settings
        value = current
        if decided >= MIN_SAMPLES:
            if fp_rate > float(cfg.threshold_fp_high):
                value = current * float(cfg.threshold_tighten_factor)
            elif fp_rate < float(cfg.threshold_fp_low):
                value = current * float(cfg.threshold_loosen_factor)
        low = static * float(cfg.threshold_min_factor)
        high = static * float(cfg.threshold_max_factor)
        return round(min(max(value, low), high), 4)

    def _load_alerts(self, since: datetime):
        """拉取回看窗口内的告警，并附上"来源资产类型"（一次性查表，避免 N+1）。"""
        try:
            with session_scope() as session:
                rows = session.scalars(select(Alert).where(Alert.ts >= since)).all()
                assets = session.scalars(select(Asset)).all()
                tags = {asset.ip: {str(tag).lower() for tag in (asset.tags or [])}
                        for asset in assets}
                cidrs = list(self.settings.whitelist_cidrs)
        except Exception:      # pragma: no cover
            logger.exception("阈值重算：读取告警失败")
            return []
        return [(alert, self._asset_class_of(alert.source_ip, tags, cidrs)) for alert in rows]

    @staticmethod
    def _asset_class_of(source_ip: str, tags: Dict[str, set], cidrs) -> str:
        ip = (source_ip or "").strip()
        if not ip:
            return "unknown"
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return "unknown"
        for item in cidrs:
            try:
                if address in ipaddress.ip_network(item, strict=False):
                    return "office"
            except ValueError:
                continue
        asset_tags = tags.get(ip)
        if asset_tags:
            if "dmz" in asset_tags:
                return "dmz"
            if {"web", "db", "api", "server"} & asset_tags:
                return "server"
        return "unknown"

    # ------------------------------------------------------------------ #
    # 对外展示 / 人工覆盖
    # ------------------------------------------------------------------ #
    def entries(self) -> List[Dict[str, Any]]:
        with session_scope() as session:
            rows = session.scalars(
                select(ThresholdConfig).order_by(ThresholdConfig.detection_type,
                                                 ThresholdConfig.asset_class,
                                                 ThresholdConfig.time_bucket)
            ).all()
            return [{
                "id": row.id,
                "dimension": row.dimension,
                "dimension_key": row.dimension_key,
                "detection_type": row.detection_type,
                "asset_class": row.asset_class,
                "time_bucket": row.time_bucket,
                "static_value": row.static_value,
                "threshold_value": row.threshold_value,
                "sample_count": row.sample_count,
                "false_positive_count": row.false_positive_count,
                "true_positive_count": row.true_positive_count,
                "false_positive_rate": row.false_positive_rate,
                "manual_override": bool(row.manual_override),
                "override_reason": row.override_reason,
                "last_updated": iso_local(row.last_updated),
            } for row in rows]

    def override(self, entry_id: int, value: float, reason: str = "",
                 operator: str = "admin") -> Optional[Dict[str, Any]]:
        """人工覆盖：置 `manual_override=True`，后续 recompute 会跳过该维度。"""
        with session_scope() as session:
            row = session.get(ThresholdConfig, entry_id)
            if row is None:
                return None
            row.threshold_value = float(value)
            row.manual_override = True
            row.override_reason = f"{reason}（{operator}）" if reason else f"人工覆盖（{operator}）"
            row.last_updated = _now()
            session.flush()
            payload = {
                "id": row.id, "detection_type": row.detection_type,
                "asset_class": row.asset_class, "time_bucket": row.time_bucket,
                "threshold_value": row.threshold_value,
                "manual_override": True, "override_reason": row.override_reason,
            }
        self.invalidate_cache()
        return payload

    def dimensions_overview(self) -> Dict[str, Any]:
        """静态基准 + 上次重算结果（供前端「阈值管理」面板展示）。"""
        return {
            "enabled": self.enabled,
            "adaptive_types": list(ADAPTIVE_TYPES),
            "static_base": {key: self.static_base(key) for key in ADAPTIVE_TYPES},
            "bounds": {
                "min_factor": float(self.settings.threshold_min_factor),
                "max_factor": float(self.settings.threshold_max_factor),
                "fp_high": float(self.settings.threshold_fp_high),
                "fp_low": float(self.settings.threshold_fp_low),
                "min_samples": MIN_SAMPLES,
            },
            "last_recompute_at": self.last_recompute_at,
            "last_recompute": self.last_recompute,
            "note": "直达机制（direct_alert）不参与自适应调整：规则固有属性，不随误报反馈变化。",
        }


def _now() -> datetime:
    from ..models import utcnow

    return utcnow()


def _since(days: int) -> datetime:
    from datetime import timedelta

    return _now() - timedelta(days=days)
