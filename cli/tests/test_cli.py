import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "core"))

from typer.testing import CliRunner

from secinsight_cli.main import app

runner = CliRunner()

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "..", "core", "tests", "fixtures")


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)


def test_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output
    assert "compare" in result.output


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0


def test_tools_command():
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0
    assert "nmap" in result.output


def test_analyze_basic(tmp_path):
    result = runner.invoke(app, ["analyze", fixture("nmap_sample.xml"), "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "Security Score" in result.output or "score" in result.output.lower()


def test_analyze_pretty_full(tmp_path):
    result = runner.invoke(
        app, ["analyze", fixture("nmap_sample.xml"), "--pretty", "--full", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 0


def test_analyze_score_only(tmp_path):
    result = runner.invoke(app, ["analyze", fixture("nmap_sample.xml"), "--score", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert result.output.strip().isdigit()


def test_analyze_student_mode(tmp_path):
    result = runner.invoke(
        app, ["analyze", fixture("nikto_sample.txt"), "--student", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 0


def test_analyze_json_export(tmp_path):
    result = runner.invoke(
        app, ["analyze", fixture("nmap_sample.xml"), "--json", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    out_file = tmp_path / "nmap_scan.json"
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["meta"]["tool"] == "nmap"


def test_analyze_html_export(tmp_path):
    result = runner.invoke(
        app, ["analyze", fixture("nmap_sample.xml"), "--html", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert (tmp_path / "nmap_report.html").exists()


def test_analyze_markdown_export(tmp_path):
    result = runner.invoke(
        app, ["analyze", fixture("nmap_sample.xml"), "--markdown", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert (tmp_path / "nmap_report.md").exists()


def test_analyze_pdf_export(tmp_path):
    result = runner.invoke(
        app, ["analyze", fixture("nmap_sample.xml"), "--pdf", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert (tmp_path / "nmap_report.pdf").exists()


def test_analyze_filter(tmp_path):
    result = runner.invoke(
        app,
        ["analyze", fixture("nmap_sample.xml"), "--filter", "severity>=high", "--full", "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == 0


def test_analyze_risk_story_ai(tmp_path):
    result = runner.invoke(
        app,
        ["analyze", fixture("nmap_sample.xml"), "--risk", "--story", "--ai-summary", "--ai-fix", "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == 0


def test_analyze_missing_file():
    result = runner.invoke(app, ["analyze", "/nonexistent/file.xml"])
    assert result.exit_code != 0


def test_analyze_bad_filter(tmp_path):
    result = runner.invoke(
        app, ["analyze", fixture("nmap_sample.xml"), "--filter", "nonsense_field=1", "--output-dir", str(tmp_path)]
    )
    assert result.exit_code != 0


def test_compare_command(tmp_path):
    # First export two JSON scans to compare
    runner.invoke(app, ["analyze", fixture("nmap_sample.xml"), "--json", "--output-dir", str(tmp_path)])
    old_path = tmp_path / "nmap_scan.json"
    new_path = tmp_path / "nmap_scan_new.json"
    data = json.loads(old_path.read_text())
    data["findings"].append(
        {
            "finding_id": "extra1", "title": "New finding", "severity": "high", "tool": "nmap",
            "description": "", "host": "h1", "port": 9999, "protocol": "tcp", "service": None,
            "path": None, "cve": None, "cvss": None, "evidence": None, "recommendation": None,
        }
    )
    new_path.write_text(json.dumps(data))

    result = runner.invoke(app, ["compare", str(old_path), str(new_path), "--pretty"])
    assert result.exit_code == 0
    assert "New finding" in result.output


def test_compare_json_output(tmp_path):
    runner.invoke(app, ["analyze", fixture("nmap_sample.xml"), "--json", "--output-dir", str(tmp_path)])
    old_path = tmp_path / "nmap_scan.json"
    result = runner.invoke(app, ["compare", str(old_path), str(old_path), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["score_delta"] == 0
