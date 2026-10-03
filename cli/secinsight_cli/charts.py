"""Generates a PNG bar chart of severity counts for --graph, using matplotlib.
Kept separate so it's an optional dependency the CLI degrades gracefully
without (charts in the web GUI are done in React/Recharts instead)."""
from __future__ import annotations

from secinsight_core.models import ScanResult

_COLORS = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}


def write_severity_chart(scan: ScanResult, out_path: str) -> str:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        raise RuntimeError(
            "matplotlib is required for --graph. Install it with: pip install matplotlib"
        ) from e

    counts = scan.counts_by_severity()
    labels = ["critical", "high", "medium", "low", "info"]
    values = [counts.get(l, 0) for l in labels]
    colors = [_COLORS[l] for l in labels]

    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar([l.capitalize() for l in labels], values, color=colors)
    ax.set_title(f"{scan.meta.tool.upper()} findings by severity")
    ax.set_ylabel("Count")
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(v),
                 ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path
