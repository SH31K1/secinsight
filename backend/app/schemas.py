from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class FindingOut(BaseModel):
    finding_id: str
    title: str
    severity: str
    tool: str
    description: str = ""
    host: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service: Optional[str] = None
    path: Optional[str] = None
    cve: Optional[str] = None
    cvss: Optional[float] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None


class ScoreOut(BaseModel):
    score: int
    grade: str
    total_findings: int
    counts: dict[str, int]
    summary: str
    top_risks: list[dict[str, Any]]


class ScanOut(BaseModel):
    id: str
    tool: str
    target: Optional[str] = None
    source_filename: Optional[str] = None
    score: int
    grade: str
    counts: dict[str, int]
    created_at: datetime
    findings: list[FindingOut] = []


class ScanSummaryOut(BaseModel):
    id: str
    tool: str
    target: Optional[str] = None
    score: int
    grade: str
    counts: dict[str, int]
    created_at: datetime


class CompareOut(BaseModel):
    old_score: int
    new_score: int
    score_delta: int
    new_findings: list[FindingOut]
    resolved_findings: list[FindingOut]
    unchanged_findings: list[FindingOut]
    summary: str


class AITextOut(BaseModel):
    text: str


class DashboardOut(BaseModel):
    total_scans: int
    average_score: float
    tools_used: dict[str, int]
    severity_totals: dict[str, int]
    recent_scans: list[ScanSummaryOut]
    score_trend: list[dict[str, Any]]
