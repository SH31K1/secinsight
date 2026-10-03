"""Parser for Nessus (.nessus) XML export."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, ParseError, register

# Nessus severity: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical
_SEVERITY_MAP = {
    "4": Severity.CRITICAL,
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}


class NessusParser(BaseParser):
    tool_name = "nessus"

    def can_parse(self, path: str, sample: str) -> bool:
        return "NessusClientData" in sample or path.lower().endswith(".nessus")

    def parse(self, path: str) -> ScanResult:
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise ParseError(f"Invalid Nessus XML: {e}") from e
        root = tree.getroot()

        findings: list[Finding] = []
        targets: set[str] = set()

        for block in root.findall(".//ReportHost"):
            host_name = block.attrib.get("name")
            if host_name:
                targets.add(host_name)
            for item in block.findall("ReportItem"):
                severity_raw = item.attrib.get("severity", "0")
                severity = _SEVERITY_MAP.get(severity_raw, Severity.INFO)
                plugin_name = item.attrib.get("pluginName", "Nessus finding")
                port = item.attrib.get("port")
                protocol = item.attrib.get("protocol")
                svc_name = item.attrib.get("svc_name")
                description = _t(item, "description") or _t(item, "synopsis") or ""
                solution = _t(item, "solution")
                cve = _t(item, "cve")
                cvss = _t(item, "cvss3_base_score") or _t(item, "cvss_base_score")

                findings.append(
                    Finding(
                        title=plugin_name,
                        severity=severity,
                        tool=self.tool_name,
                        description=description.strip(),
                        host=host_name,
                        port=int(port) if port and port.isdigit() else None,
                        protocol=protocol,
                        service=svc_name,
                        cve=cve,
                        cvss=float(cvss) if cvss else None,
                        recommendation=solution.strip() if solution else None,
                        raw={"plugin_id": item.attrib.get("pluginID")},
                    )
                )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=", ".join(sorted(targets)) or None)
        return ScanResult(meta=meta, findings=findings)


def _t(el, tag) -> str | None:
    child = el.find(tag)
    return child.text if child is not None else None


register(NessusParser())
