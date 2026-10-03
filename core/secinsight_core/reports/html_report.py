from __future__ import annotations

import os
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape

from secinsight_core.models import ScanResult
from secinsight_core.scoring import score_scan

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "j2"]),
)

_GRADE_COLORS = {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#b91c1c"}


def render_html(scan: ScanResult, mode: str = "pro", ai_summary_text: str | None = None) -> str:
    template = _env.get_template("report.html.j2")
    score = score_scan(scan)
    return template.render(
        scan=scan,
        score=score,
        findings=[f.to_dict() for f in scan.sorted_findings()],
        mode=mode,
        ai_summary_text=ai_summary_text,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        score_color=_GRADE_COLORS.get(score.grade, "#6b7280"),
    )


def write_html_report(scan: ScanResult, out_path: str, mode: str = "pro", ai_summary_text: str | None = None) -> str:
    html = render_html(scan, mode=mode, ai_summary_text=ai_summary_text)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path
