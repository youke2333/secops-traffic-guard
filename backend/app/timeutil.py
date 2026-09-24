"""时间工具：统一"库里存什么、对外显示什么"的时区语义。

背景（这是历史上造成大屏时间差 8 小时的原因）：
- `Alert` / `Signal` / `TrafficSample` 等由采集链路用 `datetime.fromtimestamp(ts)` 写入，
  落库是**本地时间**（naive）。
- `ThreatEvent` / `DisposalLog` / `BlockRule` / `AuditLog` 等用 `models.utcnow()` 写入，
  落库是**UTC 时间**（naive）。
于是列表页直接把数据库值当本地时间渲染时，威胁事件、处置时间线就比大屏时钟早 8 小时。

约定（本模块负责守住）：
1. 数据库写入语义保持不变（不迁移历史数据）；
2. **对外输出统一成本地时间**，与浏览器时钟一致；
3. 前端传进来的时间筛选条件按本地时间解释，比较前再换算回 UTC。

用法：
    from ..timeutil import iso_local, now_local

    "ts": iso_local(row.ts)                  # 库里是 UTC（默认 stored="utc"）
    "ts": iso_local(row.ts, stored="local")  # 库里已经是本地时间，只做格式化
    since = now_local() - timedelta(hours=24)  # 与本地时间列比较
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional


def local_tz():
    """当前主机时区（取系统本地偏移，容器里是 UTC 时自动退化为恒等换算）。"""
    return datetime.now().astimezone().tzinfo


def now_local() -> datetime:
    """本地当前时间（naive），用于和本地时间列比较。"""
    return datetime.now()


def now_utc() -> datetime:
    """UTC 当前时间（naive），用于和 UTC 列比较。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_to_local(value: Optional[datetime]) -> Optional[datetime]:
    """UTC（naive 或 aware）→ 本地 naive。"""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(local_tz()).replace(tzinfo=None)


def local_to_utc(value: Optional[datetime]) -> Optional[datetime]:
    """本地 naive（或 aware）→ UTC naive。"""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=local_tz())
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def iso_local(value: Optional[datetime], *, stored: str = "utc",
              timespec: str = "seconds") -> Optional[str]:
    """把数据库时间序列化为本地时间的 ISO 字符串。

    stored="utc"   —— 该列存的是 UTC（utcnow 写入），先换算成本地时间；
    stored="local" —— 该列本来就是本地时间，只格式化，不做换算。
    """
    if value is None:
        return None
    if stored != "local":
        value = utc_to_local(value)
    return value.isoformat(timespec=timespec)


def text_local(value: Optional[datetime], *, stored: str = "utc",
               fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """同上，输出 "YYYY-MM-DD HH:MM:SS" 文本（CSV / 日志用）。"""
    if value is None:
        return ""
    if stored != "local":
        value = utc_to_local(value)
    return value.strftime(fmt)


def parse_local_input(value: str) -> Optional[datetime]:
    """解析前端传入的时间筛选（按本地时间理解），返回可与 UTC 列比较的 UTC naive。

    兼容：纯数字（epoch 秒）、"2026-10-21 10:00"、"2026-10-21T10:00:00"、
    带 Z / +08:00 的 ISO 串。
    """
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        return datetime.fromtimestamp(int(text), timezone.utc).replace(tzinfo=None)
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return local_to_utc(parsed)


def hour_bucket(value: Optional[datetime], *, stored: str = "utc") -> str:
    """按本地时间做小时分桶，标签形如 "2026-10-21 18:00"（趋势图 X 轴用）。"""
    if value is None:
        return "unknown"
    if stored != "local":
        value = utc_to_local(value)
    return value.strftime("%Y-%m-%d %H:00")


def shift(value: Optional[datetime], **kwargs) -> Optional[datetime]:
    """便捷的偏移（保留 naive 语义）。"""
    return value + timedelta(**kwargs) if value is not None else None
