from __future__ import annotations

from datetime import datetime, timezone

from secinsight_core.models import ScanResult
from secinsight_core.scoring import score_scan


def render_markdown(scan: ScanResult, mode: str = "pro", ai_summary_text: str | None = None) -> str:
    score = score_scan(scan)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        f"# SecInsight AI Report — {scan.meta.tool.upper()}",
        "",
        f"- **Target:** {scan.meta.target or 'N/A'}",
        f"- **Generated:** {generated_at}",
        f"- **Mode:** {mode.capitalize()}",
        "",
        f"## Security Score: {score.score}/100 (Grade {score.grade})",
        "",
        score.summary,
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {sev.capitalize()} | {score.counts.get(sev, 0)} |")

    lines += ["", f"## Findings ({len(scan.findings)})", ""]
    lines += ["| Severity | Title | Host | CVE |", "|---|---|---|---|"]
    for f in scan.sorted_findings():
        host = (f.host or "-") + (f":{f.port}" if f.port else "")
        lines.append(f"| {f.severity.value.upper()} | {f.title} | {host} | {f.cve or '-'} |")

    lines += ["", "## Details", ""]
    for f in scan.sorted_findings():
        lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        if f.host:
            lines.append(f"- **Host:** {f.host}" + (f":{f.port}" if f.port else ""))
        if f.path:
            lines.append(f"- **Path:** {f.path}")
        if f.cve:
            lines.append(f"- **CVE:** {f.cve}" + (f" (CVSS {f.cvss})" if f.cvss else ""))
        if f.description:
            lines.append(f"- **Description:** {f.description}")
        if f.recommendation:
            lines.append(f"- **Recommendation:** {f.recommendation}")
        lines.append("")

    if ai_summary_text:
        lines += ["## AI Summary", "", ai_summary_text, ""]

    return "\n".join(lines)


def write_markdown_report(scan: ScanResult, out_path: str, mode: str = "pro", ai_summary_text: str | None = None) -> str:
    md = render_markdown(scan, mode=mode, ai_summary_text=ai_summary_text)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)
    return out_path
