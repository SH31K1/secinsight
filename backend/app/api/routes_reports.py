from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from secinsight_core.models import ScanResult
from secinsight_core.reports import render_html, render_markdown, write_pdf_report

from app.config import get_settings
from app.db import get_db
from app.models_db import ReportRecord, ScanRecord

router = APIRouter(prefix="/api/reports", tags=["reports"])
settings = get_settings()

_MEDIA_TYPES = {"pdf": "application/pdf", "html": "text/html", "markdown": "text/markdown"}
_EXTENSIONS = {"pdf": "pdf", "html": "html", "markdown": "md"}


@router.post("/{scan_id}/generate")
def generate_report(
    scan_id: str,
    format: str = Query(..., pattern="^(pdf|html|markdown)$"),
    mode: str = Query("pro", pattern="^(pro|student)$"),
    ai_summary: bool = False,
    db: Session = Depends(get_db),
):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = ScanResult.from_dict(record.scan_json)

    ai_text = None
    if ai_summary:
        from secinsight_core import ai as ai_module
        ai_text = ai_module.ai_summary(scan, student=(mode == "student"))

    os.makedirs(settings.reports_dir, exist_ok=True)
    ext = _EXTENSIONS[format]
    out_path = os.path.join(settings.reports_dir, f"{scan_id}_{mode}.{ext}")

    if format == "pdf":
        write_pdf_report(scan, out_path, mode=mode, ai_summary_text=ai_text)
    elif format == "html":
        with open(out_path, "w") as f:
            f.write(render_html(scan, mode=mode, ai_summary_text=ai_text))
    else:
        with open(out_path, "w") as f:
            f.write(render_markdown(scan, mode=mode, ai_summary_text=ai_text))

    report = ReportRecord(scan_id=scan_id, format=format, mode=mode, file_path=out_path)
    db.add(report)
    db.commit()
    db.refresh(report)

    return {"report_id": report.id, "download_url": f"/api/reports/{report.id}/download"}


@router.get("", tags=["reports"])
def list_reports(scan_id: str | None = None, db: Session = Depends(get_db)):
    from sqlalchemy import select
    stmt = select(ReportRecord).order_by(ReportRecord.created_at.desc())
    if scan_id:
        stmt = stmt.where(ReportRecord.scan_id == scan_id)
    rows = db.execute(stmt).scalars().all()
    return [
        {"id": r.id, "scan_id": r.scan_id, "format": r.format, "mode": r.mode, "created_at": r.created_at}
        for r in rows
    ]


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    record = db.get(ReportRecord, report_id)
    if not record or not os.path.isfile(record.file_path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        record.file_path,
        media_type=_MEDIA_TYPES[record.format],
        filename=os.path.basename(record.file_path),
    )
