# SecInsight AI

SecInsight AI turns raw output from security scanners into normalized findings,
security scores, human-readable explanations, and shareable reports — via a
CLI, a REST API, and a React dashboard.

## Components

| Component | Location | Stack |
|---|---|---|
| Core engine | `core/` | Python — parsers, scoring, comparison, AI explanations, report rendering |
| CLI | `cli/` | Python (Typer + Rich) |
| Backend API | `backend/` | FastAPI + SQLAlchemy + PostgreSQL |
| Frontend | `frontend/` | React + TypeScript + Tailwind + Recharts |

## Supported scanners

Nmap, Nikto, Burp Suite, OWASP ZAP, Nessus, OpenVAS, Gobuster, Dirsearch.

## Quick start (Docker)

```bash
docker compose up --build
```

- Frontend: http://localhost:8080
- Backend API docs: http://localhost:8000/docs
- Postgres: localhost:5432 (user/pass: `secinsight`/`secinsight`)

## Quick start (local dev)

```bash
make install

# Terminal 1
make run-backend      # http://localhost:8000

# Terminal 2
make run-frontend      # http://localhost:5173
```

By default the backend uses PostgreSQL (`DATABASE_URL`); for a zero-setup
local run you can instead export `DATABASE_URL=sqlite:///./dev.db` before
`make run-backend`.

## CLI usage

```bash
pip install -e core -e cli

secinsight analyze nmap.xml --pretty
secinsight analyze nikto.txt --student --pdf
secinsight analyze zap.xml --pro --full --risk --explain
secinsight analyze burp.xml --json --output-dir ./out
secinsight compare old.json new.json --pretty
secinsight tools
```

### Flags

| Flag | Description |
|---|---|
| `--pretty` | Colorized, formatted terminal output |
| `--summary` | Only the score/summary, no findings |
| `--full` | All findings with full detail |
| `--student` | Beginner-friendly explanations |
| `--pro` | Concise professional output (default) |
| `--pdf` / `--html` / `--json` / `--markdown` | Export a report |
| `--score` | Print only the numeric score |
| `--risk` | Risk analysis (by host, dangerous services) |
| `--explain` | Explain each finding |
| `--compare` | (via `secinsight compare`) diff two JSON scans |
| `--story` | Narrate a plausible attack path |
| `--graph` | PNG chart of severity counts |
| `--timeline` | Score history for this tool/target |
| `--filter` | Query findings, e.g. `severity>=high`, `host=10.0.0.5` |
| `--ai-summary` | AI-style narrative summary |
| `--ai-fix` | AI-style remediation plan |
| `--tool` | Force a parser instead of auto-detecting |
| `--output-dir` | Where exported reports are written |

`--ai-summary`/`--ai-fix` run a deterministic local generator by default;
set `ANTHROPIC_API_KEY` to have them call the real Claude API for richer prose
(see `core/secinsight_core/ai.py::generate_with_claude`).

## Testing

```bash
make test           # core + cli + backend
```

42 tests across the three Python packages (parsers for all 8 tools, scoring,
comparison, filtering, report rendering, and the full FastAPI surface).

## Architecture notes

- **`secinsight_core`** is the single source of truth for the domain model
  (`ScanResult`/`Finding`), parsing, scoring, diffing, AI text generation, and
  report rendering (PDF via ReportLab, HTML via Jinja2, Markdown natively).
  Both the CLI and the backend import it — there is no duplicated logic.
- **CLI** additionally keeps a local `~/.secinsight/history.jsonl` so
  `--timeline` works standalone without the database.
- **Backend** persists every analyzed scan (`ScanRecord`) and generated report
  (`ReportRecord`) in Postgres, and exposes score/risk/explain/AI/compare/report
  endpoints consumed by the React app.
- **Frontend** has a Dashboard (aggregate trend + recent scans), a scan detail
  view (findings, AI actions, report export), Charts, a Reports generator, and
  a Compare view — all driven by a Student/Professional mode toggle that's
  passed straight through to the backend's report/explain endpoints.
