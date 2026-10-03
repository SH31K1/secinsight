"""Parser for Dirsearch output (plain text report or -o report.json)."""
from __future__ import annotations

import json
import re

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, ParseError, register
from secinsight_core.parsers.gobuster import _severity_for_path


class DirsearchParser(BaseParser):
    tool_name = "dirsearch"

    def can_parse(self, path: str, sample: str) -> bool:
        low = sample.lower()
        if "dirsearch" in low:
            return True
        if re.search(r"^\[\d{2}:\d{2}:\d{2}\]\s+\d{3}\s+-\s+", sample, re.M):
            return True
        return False

    def parse(self, path: str) -> ScanResult:
        with open(path, "r", errors="ignore") as f:
            content = f.read()

        target = None
        m = re.search(r"Target:\s*(\S+)", content)
        if m:
            target = m.group(1)

        findings: list[Finding] = []

        stripped = content.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                data = json.loads(content)
                results = data.get("results") if isinstance(data, dict) else data
                if isinstance(results, dict):
                    # dirsearch json shape: {"target_url": [ {..}, ... ]}
                    for tgt, entries in results.items():
                        target = target or tgt
                        for entry in entries:
                            findings.append(self._finding_from_entry(entry, target))
                elif isinstance(results, list):
                    for entry in results:
                        findings.append(self._finding_from_entry(entry, target))
                meta = ScanMeta(tool=self.tool_name, source_file=path, target=target)
                return ScanResult(meta=meta, findings=findings)
            except json.JSONDecodeError:
                pass

        # Text format: [10:23:45] 200 -  1234B  - /admin/
        for line in content.splitlines():
            match = re.match(r"^\[\d{2}:\d{2}:\d{2}\]\s+(\d{3})\s+-\s+(\d+B|\d+(?:\.\d+)?[KM]B)?\s*-\s*(\S+)", line.strip())
            if not match:
                continue
            status, size, p = int(match.group(1)), match.group(2), match.group(3)
            findings.append(
                Finding(
                    title=f"Discovered path {p} ({status})",
                    severity=_severity_for_path(p, status),
                    tool=self.tool_name,
                    description=f"Dirsearch discovered '{p}' returning HTTP {status}"
                    + (f", size {size}" if size else "") + ".",
                    path=p,
                    host=target,
                    evidence=f"HTTP {status}",
                    raw={"line": line.strip()},
                )
            )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=target)
        return ScanResult(meta=meta, findings=findings)

    def _finding_from_entry(self, entry: dict, target: str | None) -> Finding:
        p = entry.get("path") or entry.get("url", "")
        status = int(entry.get("status", 0))
        size = entry.get("content-length") or entry.get("length")
        return Finding(
            title=f"Discovered path {p} ({status})",
            severity=_severity_for_path(p, status),
            tool=self.tool_name,
            description=f"Dirsearch discovered '{p}' returning HTTP {status}"
            + (f", size {size}" if size else "") + ".",
            path=p,
            host=target,
            evidence=f"HTTP {status}",
            raw=entry,
        )


register(DirsearchParser())
