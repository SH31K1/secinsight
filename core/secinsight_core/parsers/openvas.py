"""Parser for OpenVAS / Greenbone XML reports (report format XML v2)."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, ParseError, register


def _severity_from_score(score: float | None, threat: str | None) -> Severity:
    if threat:
        t = threat.lower()
        if t == "critical":
            return Severity.CRITICAL
        if t == "high":
            return Severity.HIGH
        if t == "medium":
            return Severity.MEDIUM
        if t == "low":
            return Severity.LOW
        if t in ("log", "none", "info"):
            return Severity.INFO
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
    return Severity.INFO


class OpenVASParser(BaseParser):
    tool_name = "openvas"

    def can_parse(self, path: str, sample: str) -> bool:
        low = sample.lower()
        return "openvas" in low or "greenbone" in low or "<report " in low and "<results>" in low

    def parse(self, path: str) -> ScanResult:
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise ParseError(f"Invalid OpenVAS XML: {e}") from e
        root = tree.getroot()

        findings: list[Finding] = []
        targets: set[str] = set()

        results_el = root.find(".//results")
        result_nodes = results_el.findall("result") if results_el is not None else root.findall(".//result")

        for result in result_nodes:
            name = _t(result, "name") or "OpenVAS finding"
            host_el = result.find("host")
            host = host_el.text.strip() if host_el is not None and host_el.text else None
            if host:
                targets.add(host)
            port = _t(result, "port")
            description = _t(result, "description") or ""
            nvt = result.find("nvt")
            cve = None
            cvss = None
            solution = None
            if nvt is not None:
                cve_el = nvt.find("cve")
                if cve_el is not None and cve_el.text and cve_el.text != "NOCVE":
                    cve = cve_el.text
                cvss_el = nvt.find("cvss_base")
                if cvss_el is not None and cvss_el.text:
                    try:
                        cvss = float(cvss_el.text)
                    except ValueError:
                        cvss = None
                solution_el = nvt.find("solution")
                if solution_el is not None:
                    solution = solution_el.text

            threat = _t(result, "threat")
            severity = _severity_from_score(cvss, threat)

            proto = None
            port_num = None
            if port and "/" in port:
                port_part, proto = port.split("/", 1)
                port_num = int(port_part) if port_part.isdigit() else None

            findings.append(
                Finding(
                    title=name,
                    severity=severity,
                    tool=self.tool_name,
                    description=description.strip(),
                    host=host,
                    port=port_num,
                    protocol=proto,
                    cve=cve,
                    cvss=cvss,
                    recommendation=solution.strip() if solution else None,
                    raw={"threat": threat},
                )
            )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=", ".join(sorted(targets)) or None)
        return ScanResult(meta=meta, findings=findings)


def _t(el, tag) -> str | None:
    child = el.find(tag)
    return child.text if child is not None else None


register(OpenVASParser())
