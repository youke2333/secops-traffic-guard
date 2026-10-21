"""封禁证据报告接口（v6 P1）。"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import select

from ..auth import audit
from ..config import Settings, get_settings
from ..database import session_scope
from ..models import BlockReport
from ..timeutil import iso_local
from ..reports.generator import generate_block_report
from ..schemas import ActionResult
from .deps import require_token, require_role

router = APIRouter(tags=["reports"])


def _row(row: BlockReport) -> Dict[str, Any]:
    return {
        "id": row.id, "block_id": row.block_id, "ip": row.ip,
        "format": row.format, "sha256": row.evidence_sha256,
        "operator": row.operator,
        "created_at": iso_local(row.created_at),
        "view_url": f"/api/v1/reports/{row.id}",
        "download_url": f"/api/v1/reports/{row.id}/download",
    }


def _load(report_id: int, settings: Settings) -> tuple[BlockReport, Path]:
    with session_scope() as session:
        row = session.get(BlockReport, report_id)
        if row is None:
            raise HTTPException(status_code=404, detail="报告不存在")
        path = Path(row.path).resolve()
        root = Path(settings.report_path).resolve()
        if root not in path.parents:
            raise HTTPException(status_code=403, detail="报告路径越界，已拒绝访问")
        if not path.exists():
            raise HTTPException(status_code=410, detail="报告文件已被清理，请重新生成")
        return row, path


@router.post("/blocks/{ip}/report", summary="为已封禁 IP 生成安全事件报告")
def create_report(ip: str, principal: dict = Depends(require_token),
                  settings: Settings = Depends(get_settings)) -> Dict[str, Any]:
    try:
        result = generate_block_report(ip, operator=str(principal.get("username") or "system"),
                                       settings=settings)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    audit("report_generate", username=str(principal.get("username") or ""), target=ip,
          detail=f"report_id={result['report_id']} sha256={result['sha256']}")
    return {"success": True, **result}


@router.get("/reports", summary="安全事件报告列表")
def list_reports(limit: int = Query(default=50, ge=1, le=500),
                 principal: dict = Depends(require_role("analyst", "admin"))) -> Dict[str, Any]:
    with session_scope() as session:
        rows = session.scalars(
            select(BlockReport).order_by(BlockReport.created_at.desc()).limit(limit)
        ).all()
        return {"total": len(rows), "items": [_row(row) for row in rows]}


@router.get("/reports/{report_id}", response_class=HTMLResponse,
            summary="在线查看报告（HTML）")
def view_report(report_id: int, principal: dict = Depends(require_role("analyst", "admin")),
                settings: Settings = Depends(get_settings)) -> HTMLResponse:
    _, path = _load(report_id, settings)
    return HTMLResponse(path.read_text(encoding="utf-8"))


@router.get("/reports/{report_id}/download", summary="下载报告（HTML，可打印为 PDF）")
def download_report(report_id: int, principal: dict = Depends(require_role("analyst", "admin")),
                    settings: Settings = Depends(get_settings)) -> FileResponse:
    row, path = _load(report_id, settings)
    audit("report_download", target=row.ip, detail=f"report_id={report_id}")
    return FileResponse(path, media_type="text/html; charset=utf-8", filename=path.name)
