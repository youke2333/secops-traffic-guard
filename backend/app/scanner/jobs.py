"""扫描任务管理：把耗时的指纹/漏洞扫描放后台线程，避免 HTTP 请求超时被取消。

为什么必须异步化？
* nmap 全端口扫描 + 无 nmap 时的 banner 抓取可能耗时数十秒到数分钟；
* 浏览器/网关（nginx 默认 60s、浏览器默认更短）会先超时并断开连接，
  FastAPI 的线程池任务随之收到 CancelledError —— 表现为接口 500，而实际扫描仍在跑；
* 因此改为「提交任务 → 立即返回 job_id → 前端轮询进度」，同时限制并发数，避免把主机扫爆。
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ScanJob:
    """单次扫描任务的状态容器。"""

    def __init__(self, job_id: str, targets: List[str], ports: str, use_nmap: bool) -> None:
        self.id = job_id
        self.targets = targets
        self.ports = ports
        self.use_nmap = use_nmap
        self.status = "pending"          # pending | running | done | error
        self.progress = 0                # 已扫描目标数
        self.total = len(targets)
        self.result: Optional[Dict[str, Any]] = None
        self.error = ""
        self.started_at = time.time()
        self.finished_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "progress": self.progress,
            "total": self.total,
            "percent": round((self.progress / self.total * 100) if self.total else 0, 1),
            "targets": self.targets,
            "ports": self.ports or "默认端口集",
            "use_nmap": self.use_nmap,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_sec": round((self.finished_at or time.time()) - self.started_at, 2),
            "error": self.error,
            "summary": {key: value for key, value in (self.result or {}).items() if key != "details"},
            "details": (self.result or {}).get("details", []),
        }


class ScanJobManager:
    """任务注册表：最多同时运行 MAX_CONCURRENT 个扫描，历史保留 HISTORY 条。"""

    MAX_CONCURRENT = 2
    HISTORY = 20

    def __init__(self) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()
        self._counter = itertools.count(1)
        self._running = 0

    # ------------------------------------------------------------------ #
    def submit(self, targets: List[str], scanner, ports: str = "", use_nmap: bool = True) -> ScanJob:
        job = ScanJob(f"scan-{next(self._counter)}", targets, ports, use_nmap)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            while len(self._order) > self.HISTORY:
                self._jobs.pop(self._order.pop(0), None)
        threading.Thread(target=self._run, args=(job, scanner), name=f"scan-{job.id}", daemon=True).start()
        return job

    def _run(self, job: ScanJob, scanner) -> None:
        with self._lock:
            if self._running >= self.MAX_CONCURRENT:
                job.status = "pending"
                # 简单排队：等待有槽位再执行
                while self._running >= self.MAX_CONCURRENT:
                    time.sleep(0.5)
            self._running += 1
        job.status = "running"
        details: List[Dict[str, Any]] = []
        services_found = 0
        vulns_found = 0
        try:
            for ip in job.targets:
                fingerprint, matches = scanner.scan_host(ip, ports=job.ports, use_nmap=job.use_nmap)
                services_found += len(fingerprint.services)
                vulns_found += len(matches)
                details.append({
                    "ip": ip, "state": fingerprint.state, "os_guess": fingerprint.os_guess,
                    "open_ports": fingerprint.open_ports,
                    "services": [service.to_dict() for service in fingerprint.services],
                    "vulns": [match.to_dict() for match in matches],
                })
                job.progress += 1
            job.result = {
                "targets": len(job.targets), "services_found": services_found,
                "vulns_found": vulns_found, "details": details,
                "engine": "nmap-sV" if (job.use_nmap and scanner.fingerprinter.nmap_available) else "banner-grab",
            }
            job.status = "done"
        except Exception as exc:      # pragma: no cover - 防御式
            job.status = "error"
            job.error = str(exc)
            logger.exception("扫描任务 %s 失败", job.id)
        finally:
            job.finished_at = time.time()
            with self._lock:
                self._running = max(0, self._running - 1)
            logger.info("扫描任务 %s 结束：%s（%s 个目标，%s 个漏洞）",
                        job.id, job.status, job.progress, vulns_found)

    # ------------------------------------------------------------------ #
    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, limit: int = 10) -> List[ScanJob]:
        with self._lock:
            ids = list(reversed(self._order))[:limit]
            return [self._jobs[job_id] for job_id in ids if job_id in self._jobs]

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"jobs": len(self._jobs), "running": self._running,
                    "max_concurrent": self.MAX_CONCURRENT}


scan_jobs = ScanJobManager()
