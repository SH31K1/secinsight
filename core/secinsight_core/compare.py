"""Compare two scans (e.g. old.json vs new.json exported by `secinsight analyze --json`)
to show what's new, fixed, or unchanged. Powers `secinsight compare` and --timeline."""
from __future__ import annotations

from dataclasses import dataclass, field

from secinsight_core.models import Finding, ScanResult
from secinsight_core.scoring import score_scan


@dataclass
class CompareResult:
    old_score: int
    new_score: int
    score_delta: int
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    unchanged_findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "old_score": self.old_score,
            "new_score": self.new_score,
            "score_delta": self.score_delta,
            "new_findings": [f.to_dict() for f in self.new_findings],
            "resolved_findings": [f.to_dict() for f in self.resolved_findings],
            "unchanged_findings": [f.to_dict() for f in self.unchanged_findings],
            "summary": self.summary(),
        }

    def summary(self) -> str:
        direction = "improved" if self.score_delta > 0 else ("regressed" if self.score_delta < 0 else "stayed the same")
        return (
            f"Security posture {direction} by {abs(self.score_delta)} points "
            f"({self.old_score} -> {self.new_score}). "
            f"{len(self.new_findings)} new finding(s), {len(self.resolved_findings)} resolved, "
            f"{len(self.unchanged_findings)} unchanged."
        )


def _finding_key(f: Finding) -> str:
    # Compare on semantic identity rather than the random hash, since a
    # re-run of the same scan can generate a different finding_id if raw
    # metadata differs slightly.
    return "|".join(str(x) for x in [f.tool, f.title, f.host, f.port, f.path, f.cve])


def compare_scans(old: ScanResult, new: ScanResult) -> CompareResult:
    old_map = {_finding_key(f): f for f in old.findings}
    new_map = {_finding_key(f): f for f in new.findings}

    new_keys = set(new_map) - set(old_map)
    resolved_keys = set(old_map) - set(new_map)
    unchanged_keys = set(old_map) & set(new_map)

    old_score = score_scan(old).score
    new_score = score_scan(new).score

    return CompareResult(
        old_score=old_score,
        new_score=new_score,
        score_delta=new_score - old_score,
        new_findings=[new_map[k] for k in new_keys],
        resolved_findings=[old_map[k] for k in resolved_keys],
        unchanged_findings=[new_map[k] for k in unchanged_keys],
    )
