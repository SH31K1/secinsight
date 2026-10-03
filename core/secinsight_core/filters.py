"""Implements the `--filter` CLI flag: a small query language for narrowing
down findings, e.g. --filter "severity>=high" or --filter "host=10.0.0.5"
or --filter "tool=nmap,severity=critical" (comma = AND)."""
from __future__ import annotations

from secinsight_core.models import Finding, SEVERITY_ORDER, ScanResult, Severity

_FIELDS = {"severity", "host", "port", "tool", "path", "service", "cve"}
_OPERATORS = [">=", "<=", "!=", "=", ">", "<"]


def _parse_clause(clause: str) -> tuple[str, str, str]:
    clause = clause.strip()
    for op in _OPERATORS:
        if op in clause:
            field, value = clause.split(op, 1)
            field = field.strip().lower()
            value = value.strip().strip("'\"")
            if field not in _FIELDS:
                raise ValueError(f"Unknown filter field '{field}'. Valid fields: {', '.join(sorted(_FIELDS))}")
            return field, op, value
    raise ValueError(f"Could not parse filter clause: '{clause}'. Use e.g. severity>=high or host=10.0.0.1")


def _match(finding: Finding, field: str, op: str, value: str) -> bool:
    if field == "severity":
        target_rank = Severity(value.lower()).rank
        actual_rank = finding.severity.rank
        # Note: lower rank = more severe, so >= "high" means "at least as severe as high"
        if op in (">=",):
            return actual_rank <= target_rank
        if op in ("<=",):
            return actual_rank >= target_rank
        if op == ">":
            return actual_rank < target_rank
        if op == "<":
            return actual_rank > target_rank
        if op == "=":
            return actual_rank == target_rank
        if op == "!=":
            return actual_rank != target_rank
    elif field == "port":
        fval = finding.port
        if fval is None:
            return False
        ival = int(value)
        return {"=": fval == ival, "!=": fval != ival, ">": fval > ival,
                "<": fval < ival, ">=": fval >= ival, "<=": fval <= ival}[op]
    else:
        fval = (getattr(finding, field) or "").lower()
        value_l = value.lower()
        if op == "=":
            return value_l in fval
        if op == "!=":
            return value_l not in fval
        return False
    return False


def filter_findings(scan: ScanResult, expression: str) -> list[Finding]:
    """`expression` is comma-separated clauses ANDed together."""
    clauses = [_parse_clause(c) for c in expression.split(",") if c.strip()]
    return [f for f in scan.findings if all(_match(f, field, op, value) for field, op, value in clauses)]
