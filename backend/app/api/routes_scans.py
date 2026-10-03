from __future__ import annotations

import os
import shutil
import uuid
from collections import Counter
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secinsight_core import ai
from secinsight_core.filters import filter_findings
from secinsight_core.models import ScanResult
from secinsight_core.parsers.base import ParseError, autodetect, available_tools, get_parser
from secinsight_core.scoring import risk_analysis, score_scan

from app.config import get_settings
from app.db import get_db
from app.models_db import ScanRecord
from app.schemas import DashboardOut, ScanOut, ScanSummaryOut, ScoreOut

router = APIRouter(prefix="/api/scans", tags=["scans"])
settings = get_settings()


@router.get("/tools")
def list_tools():
    return {"tools": available_tools()}


@router.post("", response_model=ScanOut)
async def upload_and_analyze(
    file: UploadFile = File(...),
    tool: Optional[str] = None,
    db: Session = Depends(get_db),
):
    os.makedirs(settings.upload_dir, exist_ok=True)
    ext = os.path.splitext(file.filename or "")[1] or ".dat"
    tmp_path = os.path.join(settings.upload_dir, f"{uuid.uuid4().hex}{ext}")
    with open(tmp_path, "wb") as out:
        shutil.copyfileobj(file.file, out)

    try:
        parser = get_parser(tool) if tool else autodetect(tmp_path)
        scan = parser.parse(tmp_path)
    except ParseError as e:
        raise HTTPException(status_code=422, detail=str(e))
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    result = score_scan(scan)
    record = ScanRecord(
        tool=scan.meta.tool,
        target=scan.meta.target,
        source_filename=file.filename,
        score=result.score,
        grade=result.grade,
        counts=result.counts,
        scan_json=scan.to_dict(),
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return _scan_to_out(record)


def _scan_to_out(record: ScanRecord) -> ScanOut:
    findings = record.scan_json.get("findings", [])
    return ScanOut(
        id=record.id,
        tool=record.tool,
        target=record.target,
        source_filename=record.source_filename,
        score=record.score,
        grade=record.grade,
        counts=record.counts,
        created_at=record.created_at,
        findings=findings,
    )


@router.get("", response_model=list[ScanSummaryOut])
def list_scans(
    tool: Optional[str] = None,
    limit: int = Query(50, le=500),
    db: Session = Depends(get_db),
):
    stmt = select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)
    if tool:
        stmt = stmt.where(ScanRecord.tool == tool)
    rows = db.execute(stmt).scalars().all()
    return [
        ScanSummaryOut(
            id=r.id, tool=r.tool, target=r.target, score=r.score, grade=r.grade,
            counts=r.counts, created_at=r.created_at,
        )
        for r in rows
    ]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, filter: Optional[str] = None, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    if filter:
        scan = ScanResult.from_dict(record.scan_json)
        try:
            findings = [f.to_dict() for f in filter_findings(scan, filter)]
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        out = _scan_to_out(record)
        out.findings = findings
        return out
    return _scan_to_out(record)


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(record)
    db.commit()
    return {"deleted": scan_id}


@router.get("/{scan_id}/score", response_model=ScoreOut)
def get_score(scan_id: str, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = ScanResult.from_dict(record.scan_json)
    result = score_scan(scan)
    return ScoreOut(
        score=result.score, grade=result.grade, total_findings=result.total_findings,
        counts=result.counts, summary=result.summary, top_risks=result.top_risks,
    )


@router.get("/{scan_id}/risk")
def get_risk(scan_id: str, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = ScanResult.from_dict(record.scan_json)
    return risk_analysis(scan)


@router.get("/{scan_id}/explain")
def explain_scan(scan_id: str, student: bool = True, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = ScanResult.from_dict(record.scan_json)
    return {"explanations": [ai.explain_finding(f, student=student) for f in scan.sorted_findings()]}


@router.get("/{scan_id}/ai-summary")
def ai_summary_scan(scan_id: str, student: bool = False, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = ScanResult.from_dict(record.scan_json)
    text = ai.generate_with_claude(
        f"Summarize this security scan for a {'student' if student else 'professional'} audience:\n{scan.to_dict()}"
    ) or ai.ai_summary(scan, student=student)
    return {"text": text}


@router.get("/{scan_id}/ai-fix")
def ai_fix_scan(scan_id: str, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = ScanResult.from_dict(record.scan_json)
    text = ai.generate_with_claude(
        f"Produce a prioritized remediation plan for this security scan:\n{scan.to_dict()}"
    ) or ai.ai_fix(scan)
    return {"text": text}


@router.get("/{scan_id}/story")
def story_scan(scan_id: str, db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = ScanResult.from_dict(record.scan_json)
    return {"text": ai.attack_story(scan)}


@router.get("/dashboard/overview", response_model=DashboardOut)
def dashboard_overview(db: Session = Depends(get_db)):
    rows = db.execute(select(ScanRecord).order_by(ScanRecord.created_at.asc())).scalars().all()
    total = len(rows)
    avg_score = round(sum(r.score for r in rows) / total, 1) if total else 100.0
    tools_used = dict(Counter(r.tool for r in rows))

    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in rows:
        for sev, count in (r.counts or {}).items():
            if sev in severity_totals:
                severity_totals[sev] += count

    recent = sorted(rows, key=lambda r: r.created_at, reverse=True)[:10]
    trend = [{"timestamp": r.created_at.isoformat(), "score": r.score, "tool": r.tool} for r in rows[-50:]]

    return DashboardOut(
        total_scans=total,
        average_score=avg_score,
        tools_used=tools_used,
        severity_totals=severity_totals,
        recent_scans=[
            ScanSummaryOut(id=r.id, tool=r.tool, target=r.target, score=r.score, grade=r.grade,
                            counts=r.counts, created_at=r.created_at)
            for r in recent
        ],
        score_trend=trend,
    )
