from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class ScanRecord(Base):
    """A single imported scan, normalized into ScanResult JSON, plus its
    computed score. This is what powers the dashboard, timeline, and
    compare-from-history features in the GUI."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    tool: Mapped[str] = mapped_column(String(50), index=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    score: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(2))
    counts: Mapped[dict] = mapped_column(JSON)
    scan_json: Mapped[dict] = mapped_column(JSON)  # full normalized ScanResult.to_dict()
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class ReportRecord(Base):
    """Metadata about a generated report file (PDF/HTML/Markdown) tied back
    to a scan, so the GUI's Reports tab can list/download past exports."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), index=True)
    format: Mapped[str] = mapped_column(String(10))  # pdf | html | markdown
    mode: Mapped[str] = mapped_column(String(10))  # student | pro
    file_path: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
