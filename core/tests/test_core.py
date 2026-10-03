import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from secinsight_core.compare import compare_scans
from secinsight_core.filters import filter_findings
from secinsight_core.models import Finding, ScanMeta, ScanResult, Severity
from secinsight_core.parsers.base import autodetect, get_parser, load_all_parsers
from secinsight_core.scoring import risk_analysis, score_scan

load_all_parsers()

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)


def test_nmap_parser_open_ports():
    parser = get_parser("nmap")
    result = parser.parse(fixture_path("nmap_sample.xml"))
    assert result.meta.tool == "nmap"
    assert len(result.findings) >= 4
    ports = {f.port for f in result.findings if f.port}
    assert 22 in ports and 3306 in ports


def test_nmap_autodetect():
    parser = autodetect(fixture_path("nmap_sample.xml"))
    assert parser.tool_name == "nmap"


def test_nikto_text_parser():
    parser = get_parser("nikto")
    result = parser.parse(fixture_path("nikto_sample.txt"))
    assert result.meta.tool == "nikto"
    assert len(result.findings) > 0


def test_gobuster_text_parser():
    parser = get_parser("gobuster")
    result = parser.parse(fixture_path("gobuster_sample.txt"))
    assert any(f.path == "/admin" for f in result.findings)


def test_dirsearch_text_parser():
    parser = get_parser("dirsearch")
    result = parser.parse(fixture_path("dirsearch_sample.txt"))
    assert len(result.findings) > 0


def test_burp_xml_parser():
    parser = get_parser("burp")
    result = parser.parse(fixture_path("burp_sample.xml"))
    assert len(result.findings) == 2
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_zap_xml_parser():
    parser = get_parser("zap")
    result = parser.parse(fixture_path("zap_sample.xml"))
    assert len(result.findings) >= 1


def test_nessus_parser():
    parser = get_parser("nessus")
    result = parser.parse(fixture_path("nessus_sample.xml"))
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_openvas_parser():
    parser = get_parser("openvas")
    result = parser.parse(fixture_path("openvas_sample.xml"))
    assert len(result.findings) >= 1


def test_scoring_perfect_score_no_findings():
    scan = ScanResult(meta=ScanMeta(tool="nmap", source_file="x"), findings=[])
    result = score_scan(scan)
    assert result.score == 100
    assert result.grade == "A"


def test_scoring_penalizes_critical_more_than_low():
    crit_scan = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="x"),
        findings=[Finding(title="c", severity=Severity.CRITICAL, tool="nmap")],
    )
    low_scan = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="x"),
        findings=[Finding(title="l", severity=Severity.LOW, tool="nmap")],
    )
    assert score_scan(crit_scan).score < score_scan(low_scan).score


def test_risk_analysis_flags_dangerous_nmap_services():
    scan = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="x", target="host1"),
        findings=[
            Finding(title="Open port 3389/tcp (rdp)", severity=Severity.HIGH, tool="nmap", host="host1", port=3389, service="rdp"),
        ],
    )
    r = risk_analysis(scan)
    assert len(r["dangerous_services"]) == 1


def test_compare_scans_detects_new_and_resolved():
    old = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="old"),
        findings=[
            Finding(title="A", severity=Severity.HIGH, tool="nmap", host="h1"),
            Finding(title="B", severity=Severity.LOW, tool="nmap", host="h1"),
        ],
    )
    new = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="new"),
        findings=[
            Finding(title="A", severity=Severity.HIGH, tool="nmap", host="h1"),
            Finding(title="C", severity=Severity.CRITICAL, tool="nmap", host="h1"),
        ],
    )
    result = compare_scans(old, new)
    assert len(result.new_findings) == 1
    assert result.new_findings[0].title == "C"
    assert len(result.resolved_findings) == 1
    assert result.resolved_findings[0].title == "B"
    assert len(result.unchanged_findings) == 1


def test_filter_findings_by_severity():
    scan = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="x"),
        findings=[
            Finding(title="A", severity=Severity.CRITICAL, tool="nmap"),
            Finding(title="B", severity=Severity.LOW, tool="nmap"),
        ],
    )
    result = filter_findings(scan, "severity>=high")
    assert len(result) == 1
    assert result[0].title == "A"


def test_filter_findings_by_host():
    scan = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="x"),
        findings=[
            Finding(title="A", severity=Severity.HIGH, tool="nmap", host="10.0.0.1"),
            Finding(title="B", severity=Severity.HIGH, tool="nmap", host="10.0.0.2"),
        ],
    )
    result = filter_findings(scan, "host=10.0.0.1")
    assert len(result) == 1


def test_roundtrip_to_dict_from_dict():
    scan = ScanResult(
        meta=ScanMeta(tool="nmap", source_file="x", target="t1"),
        findings=[Finding(title="A", severity=Severity.HIGH, tool="nmap", host="h1", port=80)],
    )
    d = scan.to_dict()
    restored = ScanResult.from_dict(d)
    assert restored.meta.tool == "nmap"
    assert restored.findings[0].title == "A"
    assert restored.findings[0].port == 80
