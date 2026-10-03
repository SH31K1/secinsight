"""A tiny local history store for the CLI's --timeline flag.

Every time `secinsight analyze` runs, we append a row (target, tool, score,
counts, timestamp) to ~/.secinsight/history.jsonl. This lets --timeline work
completely standalone without requiring the FastAPI backend + Postgres.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

HISTORY_DIR = Path(os.environ.get("SECINSIGHT_HOME", str(Path.home() / ".secinsight")))
HISTORY_FILE = HISTORY_DIR / "history.jsonl"


def record_scan(tool: str, target: str | None, score: int, counts: dict) -> None:
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    row = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "target": target or "unknown",
        "score": score,
        "counts": counts,
    }
    with open(HISTORY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")


def load_history(tool: str | None = None, target: str | None = None) -> list[dict]:
    if not HISTORY_FILE.exists():
        return []
    rows = []
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if tool and row.get("tool") != tool:
                continue
            if target and row.get("target") != target:
                continue
            rows.append(row)
    return rows
