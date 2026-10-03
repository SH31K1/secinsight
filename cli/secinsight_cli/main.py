"""SecInsight AI — command-line interface.

Examples
--------
    secinsight analyze nmap.xml --pretty
    secinsight analyze nikto.txt --student --pdf
    secinsight compare old.json new.json
    secinsight tools
"""
from __future__ import annotations

import json as json_lib
import os
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from secinsight_core import ai
from secinsight_core.compare import compare_scans
from secinsight_core.filters import filter_findings
from secinsight_core.models import ScanResult, Severity
from secinsight_core.parsers.base import (
    ParseError,
    autodetect,
    available_tools,
    get_parser,
    load_all_parsers,
)
from secinsight_core.reports import render_html, render_markdown, write_pdf_report
from secinsight_core.scoring import risk_analysis, score_scan

from secinsight_cli import __version__
from secinsight_cli.history import load_history, record_scan

load_all_parsers()

app = typer.Typer(
    name="secinsight",
    help="SecInsight AI — parse, score, explain, and report on security scan output.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red3",
    Severity.HIGH: "bold white on dark_orange3",
    Severity.MEDIUM: "black on gold3",
    Severity.LOW: "white on blue3",
    Severity.INFO: "white on grey37",
}


def _version_callback(value: bool):
    if value:
        console.print(f"secinsight {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    )
):
    """SecInsight AI CLI."""


@app.command()
def tools():
    """List all supported scanner tools/formats."""
    console.print(Panel("\n".join(f"- {t}" for t in available_tools()), title="Supported tools"))


def _load_scan(file: str, tool: Optional[str]) -> ScanResult:
    if not os.path.isfile(file):
        console.print(f"[bold red]Error:[/bold red] file not found: {file}")
        raise typer.Exit(code=1)
    try:
        parser = get_parser(tool) if tool else autodetect(file)
        return parser.parse(file)
    except ParseError as e:
        console.print(f"[bold red]Parse error:[/bold red] {e}")
        raise typer.Exit(code=1)


def _severity_badge(sev: Severity) -> Text:
    return Text(f" {sev.value.upper()} ", style=_SEVERITY_STYLE[sev])


def _print_pretty(scan: ScanResult, findings, score_result, summary_mode: bool, full_mode: bool):
    header = Text()
    header.append("SecInsight AI", style="bold cyan")
    header.append(f"  {scan.meta.tool.upper()} scan", style="bold")
    if scan.meta.target:
        header.append(f"  \u2192 {scan.meta.target}", style="dim")
    console.print(header)

    grade_color = {"A": "green", "B": "green", "C": "yellow", "D": "dark_orange", "F": "red"}.get(
        score_result.grade, "white"
    )
    console.print(
        Panel(
            f"[bold {grade_color}]{score_result.score}/100  (grade {score_result.grade})[/bold {grade_color}]\n"
            f"{score_result.summary}",
            title="Security Score",
            border_style=grade_color,
        )
    )

    if summary_mode:
        return

    table = Table(show_lines=False, expand=True)
    table.add_column("Severity", width=10)
    table.add_column("Title")
    table.add_column("Host")
    if full_mode:
        table.add_column("Detail", overflow="fold")

    rows = findings if full_mode else findings[:25]
    for f in rows:
        host = (f.host or "-") + (f":{f.port}" if f.port else "")
        row = [_severity_badge(f.severity), f.title, host]
        if full_mode:
            row.append(f.description or "-")
        table.add_row(*row)
    console.print(table)
    if not full_mode and len(findings) > 25:
        console.print(f"[dim]... and {len(findings) - 25} more (use --full to see all)[/dim]")


def _print_plain(scan: ScanResult, findings, score_result, summary_mode: bool, full_mode: bool):
    print(f"SecInsight AI - {scan.meta.tool.upper()} scan" + (f" -> {scan.meta.target}" if scan.meta.target else ""))
    print(f"Security Score: {score_result.score}/100 (grade {score_result.grade})")
    print(score_result.summary)
    if summary_mode:
        return
    print()
    rows = findings if full_mode else findings[:25]
    for f in rows:
        host = (f.host or "-") + (f":{f.port}" if f.port else "")
        print(f"[{f.severity.value.upper()}] {f.title} | host={host}" + (f" | cve={f.cve}" if f.cve else ""))
        if full_mode and f.description:
            print(f"    {f.description}")
    if not full_mode and len(findings) > 25:
        print(f"... and {len(findings) - 25} more (use --full to see all)")


@app.command()
def analyze(
    file: str = typer.Argument(..., help="Path to the scan output file (xml/txt/json)."),
    tool: Optional[str] = typer.Option(
        None, "--tool", help="Force a specific tool parser instead of auto-detecting "
        "(nmap, nikto, burp, zap, nessus, openvas, gobuster, dirsearch)."
    ),
    pretty: bool = typer.Option(False, "--pretty", help="Colorized, formatted terminal output."),
    summary: bool = typer.Option(False, "--summary", help="Only show the summary/score, not individual findings."),
    full: bool = typer.Option(False, "--full", help="Show the full report (all findings + details)."),
    student: bool = typer.Option(False, "--student", help="Beginner-friendly explanations."),
    pro: bool = typer.Option(False, "--pro", help="Concise, professional-oriented output (default)."),
    pdf: bool = typer.Option(False, "--pdf", help="Export a PDF report."),
    html: bool = typer.Option(False, "--html", help="Export an HTML report."),
    json_out: bool = typer.Option(False, "--json", help="Export a normalized JSON report (also used by --compare)."),
    markdown: bool = typer.Option(False, "--markdown", help="Export a Markdown report."),
    score: bool = typer.Option(False, "--score", help="Print only the numeric security score."),
    risk: bool = typer.Option(False, "--risk", help="Show a risk analysis breakdown (by host, dangerous services)."),
    explain: bool = typer.Option(False, "--explain", help="Explain each finding in detail."),
    story: bool = typer.Option(False, "--story", help="Narrate a plausible attack path across the findings."),
    graph: bool = typer.Option(False, "--graph", help="Generate a PNG chart of findings by severity."),
    timeline: bool = typer.Option(False, "--timeline", help="Show score history for this tool/target over time."),
    filter_expr: Optional[str] = typer.Option(
        None, "--filter", help="Filter findings, e.g. --filter 'severity>=high' or --filter 'host=10.0.0.5'."
    ),
    ai_summary: bool = typer.Option(False, "--ai-summary", help="Generate an AI-style narrative summary."),
    ai_fix: bool = typer.Option(False, "--ai-fix", help="Generate an AI-style remediation plan."),
    output_dir: str = typer.Option(".", "--output-dir", help="Directory to write exported reports to."),
):
    """Analyze a single scan file and print/export results."""
    os.makedirs(output_dir, exist_ok=True)
    scan = _load_scan(file, tool)
    mode = "student" if student and not pro else "pro"

    if filter_expr:
        try:
            filtered = filter_findings(scan, filter_expr)
        except ValueError as e:
            console.print(f"[bold red]Filter error:[/bold red] {e}")
            raise typer.Exit(code=1)
        scan = ScanResult(meta=scan.meta, findings=filtered)

    score_result = score_scan(scan)
    record_scan(scan.meta.tool, scan.meta.target, score_result.score, score_result.counts)

    if score and not any([risk, explain, story, ai_summary, ai_fix, pdf, html, json_out, markdown, timeline, graph]):
        print(score_result.score)
        return

    findings = scan.sorted_findings()

    if timeline:
        history = load_history(tool=scan.meta.tool, target=scan.meta.target)
        _print_timeline(history, pretty)
        if not any([pdf, html, json_out, markdown, graph, risk, explain, story, ai_summary, ai_fix]):
            return

    if risk:
        r = risk_analysis(scan)
        _print_risk(r, pretty)

    if explain:
        for f in findings:
            console.print(ai.explain_finding(f, student=(mode == "student")) if pretty else "")
            if not pretty:
                print(ai.explain_finding(f, student=(mode == "student")))
                print("-" * 60)

    if story:
        text = ai.attack_story(scan)
        console.print(Panel(text, title="Attack Path Story") if pretty else text)

    ai_text = None
    if ai_summary:
        ai_text = ai.generate_with_claude(
            f"Summarize this security scan for a {'student' if mode == 'student' else 'professional'} audience:\n"
            + json_lib.dumps(scan.to_dict())
        ) or ai.ai_summary(scan, student=(mode == "student"))
        console.print(Panel(ai_text, title="AI Summary") if pretty else ai_text)

    if ai_fix:
        fix_text = ai.generate_with_claude(
            "Produce a prioritized remediation plan for this security scan:\n" + json_lib.dumps(scan.to_dict())
        ) or ai.ai_fix(scan)
        console.print(Panel(fix_text, title="AI Remediation Plan") if pretty else fix_text)

    if graph:
        from secinsight_cli.charts import write_severity_chart
        out_path = os.path.join(output_dir, f"{scan.meta.tool}_severity_chart.png")
        try:
            write_severity_chart(scan, out_path)
            console.print(f"[green]Chart written to {out_path}[/green]")
        except RuntimeError as e:
            console.print(f"[bold red]{e}[/bold red]")

    # Default terminal output (skip if the user only asked for exports/analysis flags)
    show_default = not any([risk, explain, story, ai_summary, ai_fix, score, timeline]) or full or summary or pretty
    if show_default:
        if pretty:
            _print_pretty(scan, findings, score_result, summary, full)
        else:
            _print_plain(scan, findings, score_result, summary, full)

    if pdf:
        out_path = os.path.join(output_dir, f"{scan.meta.tool}_report.pdf")
        write_pdf_report(scan, out_path, mode=mode, ai_summary_text=ai_text)
        console.print(f"[green]PDF report written to {out_path}[/green]")
    if html:
        out_path = os.path.join(output_dir, f"{scan.meta.tool}_report.html")
        with open(out_path, "w") as f:
            f.write(render_html(scan, mode=mode, ai_summary_text=ai_text))
        console.print(f"[green]HTML report written to {out_path}[/green]")
    if markdown:
        out_path = os.path.join(output_dir, f"{scan.meta.tool}_report.md")
        with open(out_path, "w") as f:
            f.write(render_markdown(scan, mode=mode, ai_summary_text=ai_text))
        console.print(f"[green]Markdown report written to {out_path}[/green]")
    if json_out:
        out_path = os.path.join(output_dir, f"{scan.meta.tool}_scan.json")
        with open(out_path, "w") as f:
            json_lib.dump(scan.to_dict(), f, indent=2)
        console.print(f"[green]JSON export written to {out_path}[/green]")


def _print_timeline(history: list[dict], pretty: bool):
    if not history:
        console.print("[dim]No history yet for this tool/target — run analyze a few times to build a timeline.[/dim]")
        return
    if pretty:
        table = Table(title="Score Timeline")
        table.add_column("Timestamp")
        table.add_column("Score")
        table.add_column("Critical")
        table.add_column("High")
        for row in history[-20:]:
            table.add_row(
                row["timestamp"][:19].replace("T", " "),
                str(row["score"]),
                str(row["counts"].get("critical", 0)),
                str(row["counts"].get("high", 0)),
            )
        console.print(table)
    else:
        for row in history[-20:]:
            print(f"{row['timestamp'][:19]}  score={row['score']}  "
                  f"critical={row['counts'].get('critical', 0)} high={row['counts'].get('high', 0)}")


def _print_risk(r: dict, pretty: bool):
    if pretty:
        console.print(Panel(r["summary"], title=f"Risk Analysis — Grade {r['grade']}"))
        if r["dangerous_services"]:
            table = Table(title="Dangerous exposed services")
            table.add_column("Host")
            table.add_column("Port")
            table.add_column("Service")
            table.add_column("Finding")
            for d in r["dangerous_services"]:
                table.add_row(str(d["host"]), str(d["port"]), str(d["service"]), d["title"])
            console.print(table)
    else:
        print(r["summary"])
        for d in r["dangerous_services"]:
            print(f"  DANGEROUS: {d['host']}:{d['port']} ({d['service']}) - {d['title']}")


@app.command()
def compare(
    old: str = typer.Argument(..., help="Path to the older normalized JSON scan (from --json)."),
    new: str = typer.Argument(..., help="Path to the newer normalized JSON scan (from --json)."),
    pretty: bool = typer.Option(False, "--pretty", help="Colorized, formatted terminal output."),
    json_out: bool = typer.Option(False, "--json", help="Print the comparison result as JSON."),
):
    """Compare two previously exported JSON scans to see what changed."""
    for path in (old, new):
        if not os.path.isfile(path):
            console.print(f"[bold red]Error:[/bold red] file not found: {path}")
            raise typer.Exit(code=1)

    def _load_json_scan(path: str) -> ScanResult:
        with open(path) as f:
            data = json_lib.load(f)
        return ScanResult.from_dict(data)

    old_scan = _load_json_scan(old)
    new_scan = _load_json_scan(new)
    result = compare_scans(old_scan, new_scan)

    if json_out:
        print(json_lib.dumps(result.to_dict(), indent=2))
        return

    if pretty:
        delta_color = "green" if result.score_delta >= 0 else "red"
        console.print(
            Panel(
                f"[bold]{result.old_score}[/bold] \u2192 [bold {delta_color}]{result.new_score}[/bold {delta_color}] "
                f"({'+' if result.score_delta >= 0 else ''}{result.score_delta})\n{result.summary()}",
                title="Scan Comparison",
            )
        )
        if result.new_findings:
            table = Table(title=f"New findings ({len(result.new_findings)})")
            table.add_column("Severity")
            table.add_column("Title")
            table.add_column("Host")
            for f in sorted(result.new_findings, key=lambda x: x.severity.rank):
                table.add_row(_severity_badge(f.severity), f.title, f.host or "-")
            console.print(table)
        if result.resolved_findings:
            table = Table(title=f"Resolved findings ({len(result.resolved_findings)})", style="dim")
            table.add_column("Severity")
            table.add_column("Title")
            table.add_column("Host")
            for f in sorted(result.resolved_findings, key=lambda x: x.severity.rank):
                table.add_row(f.severity.value.upper(), f.title, f.host or "-")
            console.print(table)
    else:
        print(result.summary())
        print(f"\nNew findings ({len(result.new_findings)}):")
        for f in result.new_findings:
            print(f"  + [{f.severity.value.upper()}] {f.title} ({f.host or '-'})")
        print(f"\nResolved findings ({len(result.resolved_findings)}):")
        for f in result.resolved_findings:
            print(f"  - [{f.severity.value.upper()}] {f.title} ({f.host or '-'})")


if __name__ == "__main__":
    app()
