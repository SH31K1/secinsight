"""Parser for OWASP ZAP reports. Supports the XML report (Report > Generate
Report > XML) and the JSON report."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, ParseError, register

# ZAP risk codes: 0=Informational, 1=Low, 2=Medium, 3=High 4=critical
_RISK_CODE_MAP = {
    "4": Severity.CRITICAL,
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


class ZapParser(BaseParser):
    tool_name = "zap"

    def can_parse(self, path: str, sample: str) -> bool:
        low = sample.lower()
        return "@version" in low and "zap" in low or "<owaspzapreport" in low or '"@programname"' in low and "zap" in low or "zap" in low and ("alertitem" in low or "site" in low)

    def parse(self, path: str) -> ScanResult:
        with open(path, "r", errors="ignore") as f:
            content = f.read()
        stripped = content.strip()
        if stripped.startswith("{"):
            return self._parse_json(path, content)
        return self._parse_xml(path, content)

    def _parse_xml(self, path: str, content: str) -> ScanResult:
        try:
            root = ET.fromstring(content)
        except ET.ParseError as e:
            raise ParseError(f"Invalid ZAP XML: {e}") from e

        findings: list[Finding] = []
        targets: set[str] = set()

        for site in root.findall(".//site"):
            site_name = site.attrib.get("name")
            if site_name:
                targets.add(site_name)
            alerts_el = site.find("alerts")
            if alerts_el is None:
                continue
            for alert in alerts_el.findall("alertitem"):
                name = _t(alert, "alert") or _t(alert, "name") or "ZAP finding"
                riskcode = _t(alert, "riskcode") or "0"
                severity = _RISK_CODE_MAP.get(riskcode, Severity.INFO)
                desc = _t(alert, "desc") or ""
                solution = _t(alert, "solution")
                cweid = _t(alert, "cweid")
                confidence = _t(alert, "riskdesc")

                instances_el = alert.find("instances")
                if instances_el is not None and len(instances_el):
                    for instance in instances_el.findall("instance"):
                        uri = _t(instance, "uri")
                        findings.append(
                            Finding(
                                title=name,
                                severity=severity,
                                tool=self.tool_name,
                                description=_strip(desc),
                                host=site_name,
                                path=uri,
                                recommendation=_strip(solution) if solution else None,
                                evidence=f"CWE-{cweid}" if cweid else confidence,
                                raw={"cweid": cweid},
                            )
                        )
                else:
                    findings.append(
                        Finding(
                            title=name,
                            severity=severity,
                            tool=self.tool_name,
                            description=_strip(desc),
                            host=site_name,
                            recommendation=_strip(solution) if solution else None,
                            evidence=f"CWE-{cweid}" if cweid else confidence,
                            raw={"cweid": cweid},
                        )
                    )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=", ".join(sorted(targets)) or None)
        return ScanResult(meta=meta, findings=findings)

    def _parse_json(self, path: str, content: str) -> ScanResult:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ParseError(f"Invalid ZAP JSON: {e}") from e

        findings: list[Finding] = []
        targets: set[str] = set()
        sites = data.get("site", [])
        if isinstance(sites, dict):
            sites = [sites]
        for site in sites:
            site_name = site.get("@name")
            if site_name:
                targets.add(site_name)
            alerts = site.get("alerts", [])
            for alert in alerts:
                riskcode = str(alert.get("riskcode", "0"))
                severity = _RISK_CODE_MAP.get(riskcode, Severity.INFO)
                instances = alert.get("instances", [])
                if instances:
                    for inst in instances:
                        findings.append(
                            Finding(
                                title=alert.get("alert", alert.get("name", "ZAP finding")),
                                severity=severity,
                                tool=self.tool_name,
                                description=_strip(alert.get("desc", "")),
                                host=site_name,
                                path=inst.get("uri"),
                                recommendation=_strip(alert.get("solution")) if alert.get("solution") else None,
                                evidence=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None,
                                raw=alert,
                            )
                        )
                else:
                    findings.append(
                        Finding(
                            title=alert.get("alert", alert.get("name", "ZAP finding")),
                            severity=severity,
                            tool=self.tool_name,
                            description=_strip(alert.get("desc", "")),
                            host=site_name,
                            recommendation=_strip(alert.get("solution")) if alert.get("solution") else None,
                            evidence=f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None,
                            raw=alert,
                        )
                    )

        meta = ScanMeta(tool=self.tool_name, source_file=path, target=", ".join(sorted(targets)) or None)
        return ScanResult(meta=meta, findings=findings)


def _t(el, tag) -> str | None:
    child = el.find(tag)
    return child.text if child is not None else None


def _strip(text: str | None) -> str:
    if not text:
        return ""
    import re
    return re.sub(r"<[^>]+>", " ", text).strip()


register(ZapParser())
