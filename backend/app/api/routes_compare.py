from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secinsight_core.compare import compare_scans
from secinsight_core.models import ScanResult

from app.db import get_db
from app.models_db import ScanRecord
from app.schemas import CompareOut

router = APIRouter(prefix="/api/compare", tags=["compare"])


@router.get("/{old_scan_id}/{new_scan_id}", response_model=CompareOut)
def compare_two_scans(old_scan_id: str, new_scan_id: str, db: Session = Depends(get_db)):
    old_record = db.get(ScanRecord, old_scan_id)
    new_record = db.get(ScanRecord, new_scan_id)
    if not old_record or not new_record:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    old_scan = ScanResult.from_dict(old_record.scan_json)
    new_scan = ScanResult.from_dict(new_record.scan_json)
    result = compare_scans(old_scan, new_scan)

    return CompareOut(
        old_score=result.old_score,
        new_score=result.new_score,
        score_delta=result.score_delta,
        new_findings=[f.to_dict() for f in result.new_findings],
        resolved_findings=[f.to_dict() for f in result.resolved_findings],
        unchanged_findings=[f.to_dict() for f in result.unchanged_findings],
        summary=result.summary(),
    )
