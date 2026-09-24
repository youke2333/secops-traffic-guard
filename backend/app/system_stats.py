"""硬件资源占用采集（CPU / 内存 / 磁盘 / 负载 / 运行时长）。

设计约束：
* **不引入新依赖**：优先用 psutil（若环境已安装），否则走 stdlib +
  平台原生接口（Linux /proc、Windows ctypes），再不行就返回 None 由前端显示 "--"；
* **采样无副作用**：CPU 百分比依赖两次采样差值，本模块内部保存上次快照，
  第一次调用返回 0.0，之后（前端 2s 轮询）即为真实值；
* 所有返回值都是纯 JSON 可序列化类型，异常在内部吞掉，绝不因取不到某项指标
  而让 /system/resources 接口 500。
"""

from __future__ import annotations

import os
import platform
import shutil
import time
from typing import Any, Dict, Optional, Tuple

try:  # 可选依赖：装了就用，没装走下面的 fallback
    import psutil  # type: ignore
except Exception:  # pragma: no cover - 环境相关
    psutil = None  # type: ignore

_IS_WINDOWS = os.name == "nt"
_PROCESS_STARTED_AT = time.time()

# CPU 采样状态：(idle, total) 累计值 + 上次采样时间
_prev_cpu: Optional[Tuple[float, float]] = None


# --------------------------------------------------------------------------- CPU
def _cpu_windows() -> Optional[Tuple[float, float]]:
    """GetSystemTimes → (idle, total) 累计 100ns 数。"""
    try:
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD),
                        ("dwHighDateTime", wintypes.DWORD)]

        idle, kernel, user = FILETIME(), FILETIME(), FILETIME()
        if not ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
        ):
            return None

        def _to_int(value: "FILETIME") -> float:
            return float((value.dwHighDateTime << 32) | value.dwLowDateTime)

        idle_ticks = _to_int(idle)
        # kernel 时间包含 idle，故 busy = kernel + user - idle
        total = _to_int(kernel) + _to_int(user)
        return idle_ticks, total
    except Exception:
        return None


def _cpu_linux() -> Optional[Tuple[float, float]]:
    """解析 /proc/stat 第一行 → (idle, total)。"""
    try:
        with open("/proc/stat", "r", encoding="utf-8") as handle:
            parts = handle.readline().split()
        values = [float(item) for item in parts[1:]]
        idle = values[3] + (values[4] if len(values) > 4 else 0.0)
        return idle, sum(values)
    except Exception:
        return None


def _cpu_percent() -> Optional[float]:
    global _prev_cpu
    if psutil is not None:
        try:
            # interval=None：与上次调用做差值，首次返回 0.0 且不阻塞
            value = float(psutil.cpu_percent(interval=None))
            return round(value, 1)
        except Exception:
            pass

    current = _cpu_windows() if _IS_WINDOWS else _cpu_linux()
    if current is None:
        return None
    previous, _prev_cpu = _prev_cpu, current
    if previous is None:
        return 0.0
    idle_delta = current[0] - previous[0]
    total_delta = current[1] - previous[1]
    if total_delta <= 0:
        return 0.0
    return round(max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100.0)), 1)


# ------------------------------------------------------------------------ 内存
def _memory_windows() -> Optional[Tuple[int, int]]:
    try:
        import ctypes
        from ctypes import wintypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return int(status.ullTotalPhys), int(status.ullTotalPhys - status.ullAvailPhys)
    except Exception:
        return None


def _memory_linux() -> Optional[Tuple[int, int]]:
    try:
        info: Dict[str, int] = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                info[key.strip()] = int(rest.split()[0]) * 1024 if rest.split() else 0
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", info.get("MemFree", 0))
        if not total:
            return None
        return total, max(0, total - available)
    except Exception:
        return None


def _memory() -> Dict[str, Any]:
    total = used = None
    if psutil is not None:
        try:
            mem = psutil.virtual_memory()
            total, used = int(mem.total), int(mem.used)
        except Exception:
            total = used = None
    if total is None:
        fallback = _memory_windows() if _IS_WINDOWS else _memory_linux()
        if fallback:
            total, used = fallback
    if not total or used is None:
        return {"total": None, "used": None, "percent": None}
    return {
        "total": total,
        "used": used,
        "percent": round(used / total * 100, 1),
    }


# ------------------------------------------------------------------------ 磁盘
def _disk() -> Dict[str, Any]:
    path = os.environ.get("SystemDrive", "C:\\") if _IS_WINDOWS else "/"
    if not path:
        path = "/"
    try:
        usage = shutil.disk_usage(path)
    except Exception:
        return {"path": path, "total": None, "used": None, "percent": None}
    percent = round(usage.used / usage.total * 100, 1) if usage.total else None
    return {"path": path, "total": int(usage.total), "used": int(usage.used),
            "free": int(usage.free), "percent": percent}


# ------------------------------------------------------------------------ 负载
def _load() -> Dict[str, Any]:
    try:
        one, five, fifteen = os.getloadavg()
        return {"1m": round(one, 2), "5m": round(five, 2), "15m": round(fifteen, 2)}
    except Exception:
        return {"1m": None, "5m": None, "15m": None}


def _cpu_cores() -> Optional[int]:
    try:
        return int(os.cpu_count() or 0) or None
    except Exception:
        return None


def snapshot(network: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """返回一次硬件资源快照（纯 JSON）。network 由调用方（采集服务）注入。"""
    cpu_percent = _cpu_percent()
    memory = _memory()
    disk = _disk()

    # 综合健康度：三个占用率取最大值，供前端按安全色研判
    candidates = [value for value in (cpu_percent, memory.get("percent"),
                                      disk.get("percent")) if value is not None]
    peak = max(candidates) if candidates else None

    return {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.system() or "-",
        "host": platform.node() or "-",
        "uptime_sec": round(time.time() - _PROCESS_STARTED_AT, 1),
        "cpu": {"percent": cpu_percent, "cores": _cpu_cores(), "load": _load()},
        "memory": memory,
        "disk": disk,
        "network": network or {"rx_bps": 0.0, "tx_bps": 0.0, "util": 0.0, "capacity_mbps": None},
        "peak_percent": peak,
        "source": "psutil" if psutil is not None else f"stdlib:{platform.system().lower()}",
    }
