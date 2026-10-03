# Architecture

```
                     ┌─────────────────────┐
                     │   secinsight_core    │   (parsers, scoring, compare,
                     │                      │    ai, reports — pure Python,
                     │                      │    no framework dependencies)
                     └───────┬───────┬──────┘
                             │       │
                 ┌───────────┘       └───────────┐
                 ▼                               ▼
        ┌─────────────────┐             ┌──────────────────┐
        │  secinsight_cli  │             │  FastAPI backend  │
        │  (Typer + Rich)  │             │  (app/*)           │
        └─────────────────┘             └─────────┬─────────┘
                                                    │
                                                    ▼
                                          ┌───────────────────┐
                                          │   PostgreSQL       │
                                          │ (scans, reports)   │
                                          └───────────────────┘
                                                    ▲
                                                    │ REST (JSON)
                                                    │
                                          ┌───────────────────┐
                                          │  React + TS SPA    │
                                          │ Dashboard/Charts/  │
                                          │ Reports/Compare    │
                                          └───────────────────┘
```

## Why a shared core package

Both the CLI and the backend need to: parse a scan file, compute a score,
diff two scans, generate AI-style text, and render PDF/HTML/Markdown. Putting
all of that in `secinsight_core` (framework-agnostic, dependency-light) means:

- Parsers are tested once (`core/tests`) and used identically everywhere.
- The CLI can run fully offline (no DB, no network) using the same scoring
  and report-rendering code the backend uses.
- Adding a 9th scanner format only requires one new file in
  `core/secinsight_core/parsers/`, registered via `register(...)`.

## Data flow: analyzing a scan

1. A parser (`secinsight_core.parsers.*`) turns tool-specific output into a
   `ScanResult` (a `ScanMeta` + list of normalized `Finding`s).
2. `scoring.score_scan()` computes a 0-100 score with diminishing-return
   penalties per severity, plus a letter grade.
3. `ai.py` produces explanations/summaries/remediation/attack-story text,
   either from deterministic templates or (optionally) the real Anthropic API.
4. `reports/*.py` renders the `ScanResult` + score (+ optional AI text) into
   PDF (ReportLab), HTML (Jinja2), or Markdown.
5. The CLI writes these to disk directly; the backend persists the
   `ScanResult` JSON in Postgres (`ScanRecord.scan_json`) and generates report
   files on demand, tracking them in `ReportRecord` for later download.

## Extending

- **New scanner**: add `core/secinsight_core/parsers/<tool>.py` implementing
  `BaseParser` (`can_parse`, `parse`), call `register(YourParser())` at module
  level, then add the import to `parsers/base.py::load_all_parsers()`.
- **New CLI flag**: add a Typer `Option` in `cli/secinsight_cli/main.py` and
  wire it to the relevant `secinsight_core` function.
- **New API endpoint**: add a route in `backend/app/api/`, include its router
  in `backend/app/main.py`.
