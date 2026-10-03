"""Security scoring & risk analysis.

The score is a 0-100 "health" score (100 = no findings), computed by
penalizing for each finding based on severity, with diminishing marginal
penalty per additional finding of the same severity so that one host with
50 low-severity findings doesn't look worse than one host with 3 criticals.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from secinsight_core.models import ScanResult, Severity

_BASE_PENALTY = {
    Severity.CRITICAL: 18,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0.2,
}

_GRADE_BOUNDARIES = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
]


@dataclass
class RiskBreakdown:
    severity: str
    count: int
    penalty: float


@dataclass
class ScoreResult:
    score: int
    grade: str
    total_findings: int
    counts: dict[str, int]
    breakdown: list[RiskBreakdown]
    top_risks: list[dict]
    summary: str


def _diminishing_penalty(base: float, count: int) -> float:
    """Penalty grows with count but with diminishing returns, using a log curve
    so scores don't bottom out at 0 the instant there are >10 findings."""
    if count <= 0:
        return 0.0
    return base * (1 + math.log(count, 2)) if count > 1 else base


def score_scan(scan: ScanResult) -> ScoreResult:
    counts = scan.counts_by_severity()
    breakdown: list[RiskBreakdown] = []
    total_penalty = 0.0

    for severity, count in counts.items():
        base = _BASE_PENALTY[Severity(severity)]
        penalty = _diminishing_penalty(base, count)
        total_penalty += penalty
        breakdown.append(RiskBreakdown(severity=severity, count=count, penalty=round(penalty, 2)))

    score = max(0, min(100, round(100 - total_penalty)))
    grade = "F"
    for threshold, letter in _GRADE_BOUNDARIES:
        if score >= threshold:
            grade = letter
            break

    top_risks = [
        f.to_dict()
        for f in scan.sorted_findings()
        if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ][:10]

    total = sum(counts.values())
    summary = (
        f"{total} findings across {scan.meta.tool}: "
        f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
        f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low, "
        f"{counts.get('info', 0)} informational. Overall score {score}/100 (grade {grade})."
    )

    return ScoreResult(
        score=score,
        grade=grade,
        total_findings=total,
        counts=counts,
        breakdown=breakdown,
        top_risks=top_risks,
        summary=summary,
    )


def risk_analysis(scan: ScanResult) -> dict:
    """A slightly richer view than the raw score: groups risk by host and by
    category, and flags any internet-facing services that are commonly
    dangerous (used by --risk)."""
    score_result = score_scan(scan)

    by_host: dict[str, dict[str, int]] = {}
    for f in scan.findings:
        host = f.host or "unknown"
        by_host.setdefault(host, {s.value: 0 for s in Severity})
        by_host[host][f.severity.value] += 1

    dangerous_services = []
    for f in scan.findings:
        if f.tool == "nmap" and f.severity in (Severity.HIGH, Severity.CRITICAL):
            dangerous_services.append(
                {"host": f.host, "port": f.port, "service": f.service, "title": f.title}
            )

    return {
        "score": score_result.score,
        "grade": score_result.grade,
        "summary": score_result.summary,
        "by_host": by_host,
        "dangerous_services": dangerous_services,
        "top_risks": score_result.top_risks,
    }
