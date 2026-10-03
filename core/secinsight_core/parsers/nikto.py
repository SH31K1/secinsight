"""Parser for Nikto output. Nikto can emit plain text, CSV, or JSON (-Format json).
This parser handles the classic text report and JSON export."""
from __future__ import annotations

import json
import re

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, ParseError, register

# Keyword -> severity heuristics for Nikto's free-text findings, since Nikto
# itself doesn't assign severities.
_HIGH_KEYWORDS = ["remote code execution", "sql injection", "shell", "backdoor", "rce", "authentication bypass"]
_MEDIUM_KEYWORDS = ["xss", "cross-site scripting", "directory traversal", "outdated", "vulnerable", "csrf",
                    "injection", "exposed", "disclosure"]
_LOW_KEYWORDS = ["default file", "interesting file", "banner", "cookie", "header"]


def _guess_severity(text: str) -> Severity:
    t = text.lower()
    if any(k in t for k in _HIGH_KEYWORDS):
        return Severity.HIGH
    if any(k in t for k in _MEDIUM_KEYWORDS):
        return Severity.MEDIUM
    if any(k in t for k in _LOW_KEYWORDS):
        return Severity.LOW
    return Severity.INFO


class NiktoParser(BaseParser):
    tool_name = "nikto"

    def can_parse(self, path: str, sample: str) -> bool:
        low = sample.lower()
        if "nikto" in low:
            return True
        if path.lower().endswith(".json") and '"nikto' in low:
            return True
        return False

    def parse(self, path: str) -> ScanResult:
        with open(path, "r", errors="ignore") as f:
            content = f.read()

        if path.lower().endswith(".json") or content.strip().startswith("{"):
            return self._parse_json(path, content)
        return self._parse_text(path, content)

    def _parse_json(self, path: str, content: str) -> ScanResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid Nikto JSON: {e}") from e

        target = None
        findings: list[Finding] = []
        host_block = data.get("host") or {}
        target = host_block.get("ip") or host_block.get("hostname")

        for v in data.get("vulnerabilities", []):
            msg = v.get("msg", "")
            findings.append(
                Finding(
                    title=msg[:120] if msg else v.get("id", "Nikto finding"),
                    severity=_guess_severity(msg),
                    tool=self.tool_name,
                    description=msg,
                    host=target,
                    path=v.get("url"),
                    evidence=v.get("method"),
                    raw=v,
                )
            )
        meta = ScanMeta(tool=self.tool_name, source_file=path, target=target)
        return ScanResult(meta=meta, findings=findings)

    def _parse_text(self, path: str, content: str) -> ScanResult:
        lines = content.splitlines()
        target = None
        m = re.search(r"Target(?: IP)?:\s*([^\s]+)", content)
        if m:
            target = m.group(1)
        else:
            m2 = re.search(r"\+\s*Target Host:\s*([^\s]+)", content)
            if m2:
                target = m2.group(1)

        findings: list[Finding] = []
        for line in lines:
            line = line.strip()
            if not line.startswith("+"):
                continue
            if line.startswith("+ Target") or line.startswith("+ Server:") or line.startswith("+ Start") or \
               line.startswith("+ End") or line.startswith("+ 1 host"):
                continue
            body = line.lstrip("+").strip()
            if not body:
                continue
            path_match = re.match(r"(/\S*)\s*:?\s*(.*)", body)
            found_path = path_match.group(1) if path_match and path_match.group(1).startswith("/") else None
            findings.append(
                Finding(
                    title=body[:120],
                    severity=_guess_severity(body),
                    tool=self.tool_name,
                    description=body,
                    host=target,
                    path=found_path,
                    raw={"line": body},
                )
            )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=target)
        return ScanResult(meta=meta, findings=findings)


register(NiktoParser())
