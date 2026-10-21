"""资产与漏洞接口：台账查询、主动扫描（异步任务）、漏洞状态流转。"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ..scanner.assets import AssetManager
from ..scanner.jobs import scan_jobs
from ..scanner.vulnerability import VulnerabilityScanner
from ..schemas import ActionResult, AssetOut, ScanRequest, VulnOut, WebAppScanRequest
from ..timeutil import iso_local
from .deps import assets_dep, require_scan_enabled, require_token, scanner_dep

router = APIRouter(tags=["assets"])


# ------------------------------------------------------------------ #
# 资产
# ------------------------------------------------------------------ #
@router.get("/assets", response_model=List[AssetOut], summary="资产台账列表")
def list_assets(limit: int = Query(default=200, ge=1, le=1000),
                keyword: str = Query(default=""),
                assets: AssetManager = Depends(assets_dep)) -> List[AssetOut]:
    return [AssetOut.model_validate(item) for item in assets.list_assets(limit, keyword)]


@router.get("/assets/summary", summary="资产统计（风险分布 / 端口分布）")
def assets_summary(assets: AssetManager = Depends(assets_dep)) -> Dict[str, Any]:
    return assets.summary()


@router.get("/assets/{ip}", summary="单资产详情（含历史告警与漏洞关联）")
def get_asset(ip: str, assets: AssetManager = Depends(assets_dep),
              scanner: VulnerabilityScanner = Depends(scanner_dep)) -> Dict[str, Any]:
    asset = assets.get(ip)
    if asset is None:
        raise HTTPException(status_code=404, detail="资产不存在")
    from sqlalchemy import select

    from ..database import session_scope
    from ..models import Alert, Vulnerability

    with session_scope() as session:
        alerts = session.scalars(
            select(Alert).where(Alert.source_ip == ip).order_by(Alert.ts.desc()).limit(20)
        ).all()
        vulns = session.scalars(
            select(Vulnerability).where(Vulnerability.asset_ip == ip).order_by(Vulnerability.cvss.desc())
        ).all()
    asset["alerts"] = [{"id": row.id, "ts": iso_local(row.ts, stored="local"), "category": row.category,
                        "severity": row.severity, "message": row.message} for row in alerts]
    serialized = [scanner._serialize(row) for row in vulns]  # noqa: SLF001
    asset["vulnerabilities"] = serialized
    # 按「服务」归拢：前端要回答的是"这台机器的哪个服务存在什么问题"，
    # 而不是一串脱离服务的漏洞条目。
    asset["service_vulns"] = group_by_service(asset.get("services") or [], serialized)
    return asset


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def group_by_service(services: List[Dict[str, Any]],
                     vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把漏洞挂到「端口 + 服务」上，指纹里没有漏洞的服务也列出来（便于看全貌）。

    同一端口在多处出现时（指纹表与服务清单）按端口合并，服务名优先取指纹里的产品+版本。
    """
    groups: Dict[int, Dict[str, Any]] = {}
    for item in services:
        try:
            port = int(item.get("port") or 0)
        except (TypeError, ValueError):
            continue
        if not port:
            continue
        name = " ".join(part for part in (str(item.get("product") or "").strip(),
                                          str(item.get("version") or "").strip()) if part)
        groups[port] = {
            "port": port,
            "service": name or str(item.get("name") or "").strip() or "未知服务",
            "banner": str(item.get("banner") or "")[:120],
            "vulns": [], "confirmed": 0, "suspected": 0, "severity": "",
        }

    for vuln in vulns:
        port = int(vuln.get("port") or 0)
        group = groups.setdefault(port, {
            "port": port,
            "service": str(vuln.get("service") or "").strip() or "未知服务",
            "banner": "", "vulns": [], "confirmed": 0, "suspected": 0, "severity": "",
        })
        if not group["vulns"] and group["service"] == "未知服务" and vuln.get("service"):
            group["service"] = str(vuln["service"])
        group["vulns"].append(vuln)
        if vuln.get("confidence") == "confirmed":
            group["confirmed"] += 1
        else:
            group["suspected"] += 1

    for group in groups.values():
        group["vulns"].sort(key=lambda item: (-float(item.get("cvss") or 0), item.get("cve") or ""))
        if group["vulns"]:
            top = min(group["vulns"],
                      key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), 9))
            group["severity"] = str(top.get("severity") or "")
        group["label"] = f"{group['port']}/tcp · {group['service']}"

    ordered = [item for item in groups.values() if item["vulns"]]
    empty = [item for item in groups.values() if not item["vulns"]]
    ordered.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["port"]))
    empty.sort(key=lambda item: item["port"])
    return ordered + empty


@router.post("/assets/{ip}/vuln-infer", summary="按攻击流量证据研判该资产的应用层漏洞")
def infer_asset_vulns(ip: str, use_ai: bool = Query(default=True, description="是否调用模型复核"),
                      limit: int = Query(default=0, ge=0, le=2000, description="回看事件条数"),
                      _: None = Depends(require_token),
                      scanner: VulnerabilityScanner = Depends(scanner_dep),
                      assets: AssetManager = Depends(assets_dep)) -> Dict[str, Any]:
    """不发起任何攻击：只读回放本机已捕获的请求/响应，判断目标应用是否存在漏洞。

    这是主动漏扫的补充——注入、上传、包含这类漏洞没有版本特征，只有"被打过且打穿了"
    才能确认。返回 0 条通常意味着：没被打过、或采集等级不够（没有响应体）。
    """
    if assets.get(ip) is None:
        raise HTTPException(status_code=404, detail="资产不存在")
    result = scanner.scan_traffic(ip, use_ai=use_ai, limit=limit)
    assets.refresh_risk(ip)
    return result


# ------------------------------------------------------------------ #
# 漏洞
# ------------------------------------------------------------------ #
@router.post("/assets/{ip}/rescan", summary="对单个资产重新做指纹识别与漏洞匹配")
def rescan_asset(ip: str, ports: str = Query(default="", description="留空使用默认端口集"),
                 use_nmap: bool = Query(default=True),
                 _: None = Depends(require_token),
                 __: None = Depends(require_scan_enabled),
                 scanner: VulnerabilityScanner = Depends(scanner_dep),
                 assets: AssetManager = Depends(assets_dep)) -> Dict[str, Any]:
    fingerprint, matches = scanner.scan_host(ip, ports=ports, use_nmap=use_nmap)
    assets.refresh_risk(ip)
    return {
        "ip": ip,
        "state": fingerprint.state,
        "os_guess": fingerprint.os_guess,
        "open_ports": fingerprint.open_ports,
        "services": [service.to_dict() for service in fingerprint.services],
        "vulns": [match.to_dict() for match in matches],
        "vulns_found": len(matches),
        "engine": "nmap-sV" if (use_nmap and scanner.fingerprinter.nmap_available) else "banner-grab",
    }


@router.get("/vulns", response_model=List[VulnOut], summary="漏洞列表（按 CVSS 降序）")
def list_vulns(limit: int = Query(default=100, ge=1, le=500),
               severity: str = Query(default=""),
               status: str = Query(default=""),
               scanner: VulnerabilityScanner = Depends(scanner_dep)) -> List[VulnOut]:
    return [VulnOut.model_validate(item) for item in scanner.list_vulns(limit, severity, status)]


@router.get("/vulns/summary", summary="漏洞统计（等级分布 + 知识库版本）")
def vulns_summary(scanner: VulnerabilityScanner = Depends(scanner_dep)) -> Dict[str, Any]:
    return scanner.summary()


@router.post("/vulns/scan", summary="提交漏洞扫描任务（默认异步，返回 job_id）")
def run_scan(payload: Optional[ScanRequest] = None, sync: bool = Query(default=False),
             _: None = Depends(require_token),
             __: None = Depends(require_scan_enabled),
             scanner: VulnerabilityScanner = Depends(scanner_dep)) -> Dict[str, Any]:
    """默认异步执行：立即返回任务号，前端轮询 `GET /vulns/scan/{job_id}` 获取进度与结果。

    小规模验证可加 `?sync=true` 同步等待（目标数 ≤ 4 且端口范围有限时才建议）。
    """
    request = payload or ScanRequest()
    targets = scanner.resolve_targets(request.targets)

    if sync or (len(targets) <= 4 and request.sync_hint):
        started = time.time()
        result = scanner.scan_targets(targets=targets, ports=request.ports, use_nmap=request.use_nmap)
        result["duration_sec"] = round(time.time() - started, 2)
        result["mode"] = "sync"
        return result

    job = scan_jobs.submit(targets, scanner, ports=request.ports, use_nmap=request.use_nmap)
    return {"mode": "async", "job_id": job.id, "status": job.status,
            "total": job.total, "message": f"扫描任务已提交（{job.total} 个目标），请轮询任务状态"}


@router.get("/vulns/scan/jobs", summary="扫描任务列表")
def list_scan_jobs(limit: int = Query(default=10, ge=1, le=50)) -> Dict[str, Any]:
    items = [job.to_dict() for job in scan_jobs.list(limit)]
    return {"total": len(items), "items": items, "stats": scan_jobs.stats}


@router.get("/vulns/scan/{job_id}", summary="扫描任务状态与结果")
def get_scan_job(job_id: str) -> Dict[str, Any]:
    job = scan_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="扫描任务不存在或已被清理")
    return job.to_dict()


@router.patch("/vulns/{vuln_id}", response_model=ActionResult, summary="更新漏洞状态（修复/忽略）")
def update_vuln(vuln_id: int, status: str = Query(..., pattern="^(open|fixing|fixed|ignored)$"),
                _: None = Depends(require_token),
                scanner: VulnerabilityScanner = Depends(scanner_dep)) -> ActionResult:
    if not scanner.update_status(vuln_id, status):
        raise HTTPException(status_code=404, detail="漏洞记录不存在")
    return ActionResult(success=True, message=f"漏洞 {vuln_id} 状态已更新为 {status}")


@router.get("/cve/kb", summary="CVE 知识库概览")
def cve_kb(scanner: VulnerabilityScanner = Depends(scanner_dep)) -> Dict[str, Any]:
    return {
        "stats": scanner.kb.stats,
        "rules": [{"cve": rule.get("cve"), "title": rule.get("title"),
                   "severity": rule.get("severity"), "cvss": rule.get("cvss"),
                   "fixed_version": rule.get("fixed_version")} for rule in scanner.kb.rules],
    }


@router.post("/scanner/webapp", summary="Web 应用漏扫（通用只读体检：指纹 + 配置缺陷 + 暴露面）")
def scan_webapp(payload: WebAppScanRequest, _: None = Depends(require_token),
                __: None = Depends(require_scan_enabled),
                scanner: VulnerabilityScanner = Depends(scanner_dep)) -> Dict[str, Any]:
    """对 URL 做只读探测：指纹 → 安全响应头/Cookie/暴露面/演示页面检查 → 落库为漏洞记录。

    所有结论都带 HTTP 状态码与命中的页面标记，未取得证据不会生成记录（避免误报）。
    """
    return scanner.scan_webapp_url(payload.url, port=payload.port)


@router.post("/vulns/{vuln_id}/ai-advice", summary="生成 AI 修复建议（API 不可用时自动降级）")
def vuln_ai_advice(vuln_id: int, force: bool = Query(default=False),
                   _: None = Depends(require_token),
                   scanner: VulnerabilityScanner = Depends(scanner_dep)) -> Dict[str, Any]:
    """生成/重新生成 AI 修复建议。

    ``force=true`` 对应页面的「重新生成」：一定会再打一次模型请求，并提高采样温度，
    保证内容与上次不同。不带该参数时按 ``temperature=0`` 求稳定输出。
    """
    from ..analysis.vuln_advisor import VulnAdvisor
    from ..database import session_scope
    from ..models import Vulnerability

    with session_scope() as session:
        row = session.get(Vulnerability, vuln_id)
        if row is None:
            raise HTTPException(status_code=404, detail="漏洞记录不存在")
        payload = scanner._serialize(row)      # noqa: SLF001 - 复用统一序列化
    result = VulnAdvisor(scanner.settings).advise(payload, force=force)
    with session_scope() as session:
        row = session.get(Vulnerability, vuln_id)
        if row is not None:
            row.ai_advice = result
            row.ai_source = str(result.get("source") or "")
    return {"vuln_id": vuln_id, **result}
