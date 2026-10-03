"""Parser for Gobuster (dir/dns/vhost modes). Handles the default text output
and the -o json output.
"""
from __future__ import annotations

import json
import re

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, register

_INTERESTING = {
    "/.git": Severity.HIGH,
    "/.env": Severity.CRITICAL,
    "/.svn": Severity.HIGH,
    "/backup": Severity.MEDIUM,
    "/admin": Severity.MEDIUM,
    "/config": Severity.MEDIUM,
    "/.aws": Severity.CRITICAL,
    "/wp-admin": Severity.LOW,
    "/phpmyadmin": Severity.MEDIUM,
    "/server-status": Severity.MEDIUM,
}


def _severity_for_path(path: str, status: int) -> Severity:
    path = path.lower()

    for key, sev in _INTERESTING.items():
        if path.startswith(key):
            return sev

    if status == 200:
        return Severity.LOW
    elif status in (301, 302, 307):
        return Severity.INFO
    elif status in (401, 403):
        return Severity.INFO

    return Severity.INFO


class GobusterParser(BaseParser):
    tool_name = "gobuster"

    def can_parse(self, path: str, sample: str) -> bool:
        low = sample.lower()

        if "gobuster" in low:
            return True

        # Supports:
        # /admin (Status: 200)
        # admin (Status: 200)
        return re.search(
            r"^/?\S+\s+\(Status:\s*\d+\)",
            sample,
            re.MULTILINE,
        ) is not None

    def parse(self, path: str) -> ScanResult:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        target = None

        m = re.search(r"\[\+\]\s*Url:\s*(\S+)", content)
        if m:
            target = m.group(1)

        findings = []

        # JSON output
        if content.strip().startswith("[") or content.strip().startswith("{"):
            try:
                data = json.loads(content)

                if isinstance(data, list):
                    entries = data
                else:
                    entries = data.get("results", [])

                for entry in entries:
                    p = entry.get("path", "")
                    status = int(entry.get("status", 0))
                    size = entry.get("length")

                    if p and not p.startswith("/"):
                        p = "/" + p

                    findings.append(
                        Finding(
                            title=f"Discovered path {p}",
                            severity=_severity_for_path(p, status),
                            tool=self.tool_name,
                            description=f"Gobuster discovered '{p}' returning HTTP {status}",
                            path=p,
                            host=target,
                            evidence=f"HTTP {status}",
                            raw=entry,
                        )
                    )

                return ScanResult(
                    meta=ScanMeta(
                        tool=self.tool_name,
                        source_file=path,
                        target=target,
                    ),
                    findings=findings,
                )

            except json.JSONDecodeError:
                pass

        # Text output
        pattern = re.compile(
            r"^(?P<path>/?\S+)\s+\(Status:\s*(?P<status>\d+)\)"
            r"(?:\s+\[Size:\s*(?P<size>\d+)\])?",
            re.MULTILINE,
        )

        for match in pattern.finditer(content):
            p = match.group("path")

            if not p.startswith("/"):
                p = "/" + p

            status = int(match.group("status"))
            size = match.group("size")

            findings.append(
                Finding(
                    title=f"Discovered path {p} ({status})",
                    severity=_severity_for_path(p, status),
                    tool=self.tool_name,
                    description=f"Gobuster discovered '{p}' returning HTTP {status}"
                    + (f" ({size} bytes)" if size else ""),
                    path=p,
                    host=target,
                    evidence=f"HTTP {status}",
                    raw={"line": match.group(0)},
                )
            )

        return ScanResult(
            meta=ScanMeta(
                tool=self.tool_name,
                source_file=path,
                target=target,
            ),
            findings=findings,
        )


register(GobusterParser())
