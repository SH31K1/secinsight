"""
Core data models for SecInsight AI.

These models are the common currency between parsers, the scoring engine,
report generators, the CLI, and the FastAPI backend. Every tool-specific
parser normalizes its input into a `ScanResult` made of `Finding` objects,
so everything downstream (scoring, reports, comparisons, AI summaries)
only ever has to deal with one shape of data.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    @property
    def rank(self) -> int:
        # Lower rank = more severe. Useful for sorting.
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self)


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


@dataclass
class Finding:
    """A single normalized security finding (a vulnerability, open port,
    misconfiguration, or discovered path/endpoint)."""

    title: str
    severity: Severity
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
    raw: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default="")

    def __post_init__(self):
        if not self.finding_id:
            basis = f"{self.tool}|{self.title}|{self.host}|{self.port}|{self.path}|{self.cve}"
            self.finding_id = hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "tool": self.tool,
            "description": self.description,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "path": self.path,
            "cve": self.cve,
            "cvss": self.cvss,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Finding":
        return Finding(
            title=d["title"],
            severity=Severity(d["severity"]),
            tool=d.get("tool", "unknown"),
            description=d.get("description", ""),
            host=d.get("host"),
            port=d.get("port"),
            protocol=d.get("protocol"),
            service=d.get("service"),
            path=d.get("path"),
            cve=d.get("cve"),
            cvss=d.get("cvss"),
            evidence=d.get("evidence"),
            recommendation=d.get("recommendation"),
            finding_id=d.get("finding_id", ""),
        )


@dataclass
class ScanMeta:
    tool: str
    source_file: str
    scanned_at: Optional[str] = None
    target: Optional[str] = None
    imported_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ScanResult:
    """The normalized output of running a parser over a raw scan file."""

    meta: ScanMeta
    findings: list[Finding] = field(default_factory=list)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.title))

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": {
                "tool": self.meta.tool,
                "source_file": self.meta.source_file,
                "scanned_at": self.meta.scanned_at,
                "target": self.meta.target,
                "imported_at": self.meta.imported_at,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "ScanResult":
        m = d["meta"]
        meta = ScanMeta(
            tool=m.get("tool", "unknown"),
            source_file=m.get("source_file", ""),
            scanned_at=m.get("scanned_at"),
            target=m.get("target"),
            imported_at=m.get("imported_at", datetime.now(timezone.utc).isoformat()),
        )
        findings = [Finding.from_dict(fd) for fd in d.get("findings", [])]
        return ScanResult(meta=meta, findings=findings)
