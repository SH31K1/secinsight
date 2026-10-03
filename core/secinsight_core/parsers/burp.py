"""Parser for Burp Suite's XML export (Report > Save as XML, or the
'issues' export from Burp Scanner), and for Burp Community Edition's
HTTP History export ('Save selected items' from the Proxy/Target tabs,
root element <items>)."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, ParseError, register

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "information": Severity.INFO,
    "informational": Severity.INFO,
}

# Burp Community's HTTP history export has no scanner behind it, so there is
# no real severity to assign to a captured request. These path substrings are
# heuristically elevated above INFO so obviously sensitive requests stand
# out; everything else defaults to INFO.
_INTERESTING_PATHS = {
    "/.env": Severity.CRITICAL,
    "/.aws": Severity.CRITICAL,
    "/.git": Severity.HIGH,
    "/.svn": Severity.HIGH,
    "/backup": Severity.MEDIUM,
    "/config": Severity.MEDIUM,
    "/phpmyadmin": Severity.MEDIUM,
    "/server-status": Severity.MEDIUM,
    "/admin": Severity.LOW,
    "/wp-admin": Severity.LOW,
}


def _strip_html(text: str | None) -> str:
    if not text:
        return ""
    import re
    return re.sub(r"<[^>]+>", " ", text).strip()


def _text(el, tag) -> str | None:
    child = el.find(tag)
    return child.text if child is not None else None


def _severity_for_history_item(path_val: str | None, status: str | None) -> Severity:
    """Burp Community assigns no severity to HTTP history entries, so this is
    just a lightweight heuristic to surface obviously sensitive requests."""
    if path_val:
        low = path_val.lower()
        for marker, sev in _INTERESTING_PATHS.items():
            if marker in low:
                return sev
    if status and status.isdigit() and int(status) >= 500:
        return Severity.LOW
    return Severity.INFO


class BurpParser(BaseParser):
    tool_name = "burp"

    def can_parse(self, path: str, sample: str) -> bool:
        return (
            "<issues" in sample
            or "<issue>" in sample
            or "<items" in sample
            or "<item>" in sample
            or "burpVersion" in sample
        )

    def parse(self, path: str) -> ScanResult:
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise ParseError(f"Invalid Burp XML: {e}") from e
        root = tree.getroot()

        if root.tag == "issues":
            return self._parse_issues(path, root)
        if root.tag == "items":
            return self._parse_history(path, root)

        raise ParseError(
            "Not a recognized Burp XML file (expected <issues> for a Burp "
            "Professional scan report, or <items> for a Burp Community HTTP "
            "history export)."
        )

    def _parse_issues(self, path: str, root: ET.Element) -> ScanResult:
        """Burp Professional / Scanner issues export: <issues><issue>...</issue></issues>."""
        findings: list[Finding] = []
        targets: set[str] = set()

        for issue in root.findall("issue"):
            name = _text(issue, "name") or "Burp finding"
            severity_raw = (_text(issue, "severity") or "information").lower()
            severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)
            host_el = issue.find("host")
            host = host_el.text if host_el is not None else None
            if host:
                targets.add(host)
            path_val = _text(issue, "path")
            confidence = _text(issue, "confidence")
            issue_bg = _strip_html(_text(issue, "issueBackground"))
            remediation = _strip_html(_text(issue, "remediationBackground"))
            detail = _strip_html(_text(issue, "issueDetail"))

            description = detail or issue_bg
            findings.append(
                Finding(
                    title=name,
                    severity=severity,
                    tool=self.tool_name,
                    description=description,
                    host=host,
                    path=path_val,
                    evidence=f"Confidence: {confidence}" if confidence else None,
                    recommendation=remediation or None,
                    raw={"confidence": confidence},
                )
            )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=", ".join(sorted(targets)) or None)
        return ScanResult(meta=meta, findings=findings)

    def _parse_history(self, path: str, root: ET.Element) -> ScanResult:
        """Burp Community HTTP history export: <items><item>...</item></items>."""
        findings: list[Finding] = []
        targets: set[str] = set()

        for item in root.findall("item"):
            host = item.findtext("host")
            url = item.findtext("url")
            method = item.findtext("method") or "GET"
            status = item.findtext("status")
            path_val = item.findtext("path")
            mime = item.findtext("mimetype")
            length = item.findtext("responselength")

            if host:
                targets.add(host)

            description = f"{method} request to {url} returned HTTP {status}."
            if mime:
                description += f" MIME type: {mime}."
            if length:
                description += f" Response length: {length} bytes."

            findings.append(
                Finding(
                    title=f"{method} {path_val or url} ({status or '?'})",
                    severity=_severity_for_history_item(path_val, status),
                    tool=self.tool_name,
                    description=description,
                    host=host,
                    path=path_val,
                    evidence=f"HTTP {status}" if status else None,
                    raw={"url": url, "mimetype": mime, "responselength": length},
                )
            )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=", ".join(sorted(targets)) or None)
        return ScanResult(meta=meta, findings=findings)


register(BurpParser())
