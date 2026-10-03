"""Parser for Nmap XML output (`nmap -oX`)."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import BaseParser, ParseError, register

# Nmap doesn't score severity itself, so we infer a reasonable severity from
# well-known risky ports/services. Anything else defaults to INFO (it's just
# host/port inventory) unless a script reports a vulnerability.
RISKY_PORTS = {
    21: Severity.MEDIUM,    # ftp
    23: Severity.HIGH,      # telnet
    25: Severity.LOW,       # smtp
    135: Severity.MEDIUM,   # msrpc
    139: Severity.MEDIUM,   # netbios
    445: Severity.HIGH,     # smb
    1433: Severity.HIGH,    # mssql
    1521: Severity.HIGH,    # oracle
    3306: Severity.HIGH,    # mysql
    3389: Severity.HIGH,    # rdp
    5432: Severity.HIGH,    # postgres
    5900: Severity.HIGH,    # vnc
    6379: Severity.HIGH,    # redis
    9200: Severity.HIGH,    # elasticsearch
    27017: Severity.HIGH,   # mongodb
}


class NmapParser(BaseParser):
    tool_name = "nmap"

    def can_parse(self, path: str, sample: str) -> bool:
        if not path.lower().endswith(".xml"):
            if "<nmaprun" not in sample:
                return False
        return "<nmaprun" in sample or path.lower().endswith(".xml") and self._sniff(path)

    def _sniff(self, path: str) -> bool:
        try:
            with open(path, "r", errors="ignore") as f:
                head = f.read(2048)
            return "<nmaprun" in head
        except OSError:
            return False

    def parse(self, path: str) -> ScanResult:
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            raise ParseError(f"Invalid Nmap XML: {e}") from e
        root = tree.getroot()
        if root.tag != "nmaprun":
            raise ParseError("Not an Nmap XML file (missing <nmaprun> root).")

        scanned_at = root.attrib.get("startstr")
        findings: list[Finding] = []
        targets: list[str] = []

        for host in root.findall("host"):
            address_el = host.find("address")
            host_ip = address_el.attrib.get("addr") if address_el is not None else None
            hostname_el = host.find("hostnames/hostname")
            hostname = hostname_el.attrib.get("name") if hostname_el is not None else None
            display_host = hostname or host_ip
            if display_host:
                targets.append(display_host)

            ports_el = host.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue
                portid = int(port_el.attrib.get("portid", 0))
                protocol = port_el.attrib.get("protocol", "tcp")
                service_el = port_el.find("service")
                service_name = service_el.attrib.get("name") if service_el is not None else None
                product = service_el.attrib.get("product", "") if service_el is not None else ""
                version = service_el.attrib.get("version", "") if service_el is not None else ""
                banner = " ".join(x for x in [product, version] if x)

                severity = RISKY_PORTS.get(portid, Severity.INFO)

                findings.append(
                    Finding(
                        title=f"Open port {portid}/{protocol} ({service_name or 'unknown'})",
                        severity=severity,
                        tool=self.tool_name,
                        description=f"Port {portid}/{protocol} is open running {service_name or 'an unknown service'}"
                        + (f" ({banner})" if banner else "") + ".",
                        host=display_host,
                        port=portid,
                        protocol=protocol,
                        service=service_name,
                        evidence=banner or None,
                        recommendation=_recommend_for_port(portid, service_name),
                        raw={"state": "open"},
                    )
                )

                # Nmap NSE vulnerability scripts (e.g. vulners, vuln category)
                for script in port_el.findall("script"):
                    script_id = script.attrib.get("id", "")
                    output = script.attrib.get("output", "")
                    if "VULNERABLE" in output or "CVE-" in output or script_id.endswith("-vuln"):
                        findings.append(
                            Finding(
                                title=f"NSE script finding: {script_id}",
                                severity=Severity.CRITICAL if "CRITICAL" in output.upper() else Severity.HIGH if "VULNERABLE" in output else Severity.MEDIUM,
                                tool=self.tool_name,
                                description=output.strip()[:500],
                                host=display_host,
                                port=portid,
                                protocol=protocol,
                                service=service_name,
                                cve=_extract_cve(output),
                                evidence=output.strip()[:500],
                                raw={"script_id": script_id},
                            )
                        )

        meta = ScanMeta(
            tool=self.tool_name,
            source_file=path,
            scanned_at=scanned_at,
            target=", ".join(sorted(set(targets))) if targets else None,
        )
        return ScanResult(meta=meta, findings=findings)


def _recommend_for_port(port: int, service: str | None) -> str | None:
    recs = {
        23: "Disable Telnet and use SSH instead; Telnet transmits credentials in plaintext.",
        445: "Restrict SMB to trusted networks, disable SMBv1, and ensure it's patched (EternalBlue).",
        3389: "Restrict RDP to a VPN or bastion host, enforce NLA and MFA, and rate-limit auth attempts.",
        3306: "Do not expose MySQL to the internet; bind to localhost or a private network and use strong auth.",
        5432: "Do not expose PostgreSQL publicly; restrict via firewall/security group and enforce SSL + strong auth.",
        6379: "Redis has no auth by default in many setups — bind to localhost, require a password, and firewall it.",
        27017: "MongoDB should not be internet-facing; enable authentication and bind to a private network.",
        5900: "VNC often has weak or no authentication; tunnel over SSH/VPN and use a strong password.",
        1433: "Restrict MSSQL access to application servers only; disable SA account or set a strong password.",
        1521: "Restrict Oracle listener access; disable default accounts and enable listener security.",
    }
    return recs.get(port)


def _extract_cve(text: str) -> str | None:
    import re
    m = re.search(r"CVE-\d{4}-\d{4,7}", text)
    return m.group(0) if m else None


register(NmapParser())
