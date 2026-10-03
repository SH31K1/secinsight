# SecInsight AI

**SecInsight AI** is a security-scan analysis platform that converts raw output from security tools into normalized findings, severity scores, risk analysis, explanations, comparisons, and shareable reports.

It provides:

- 🖥️ CLI for security-scan analysis
- 🌐 REST API with FastAPI
- 📊 React dashboard
- 🔍 Support for 8 security scanners
- 📈 Security scoring and severity analysis
- 🔄 Scan comparison
- 🤖 Local AI-style explanations and remediation
- 📄 PDF, HTML, Markdown, and JSON reports
- 🧪 Automated test suite

> **Project status:** Active development

---

## Supported Security Tools

SecInsight AI currently supports:

| Security Tool | Input |
|---|---|
| Nmap | XML |
| Nikto | TXT |
| Burp Suite | XML |
| OWASP ZAP | XML / JSON |
| Nessus | XML |
| OpenVAS | XML |
| Gobuster | TXT |
| Dirsearch | TXT |

---

## Architecture

```text
                    ┌─────────────────────┐
                    │   Security Scans    │
                    │ Nmap / ZAP / Burp   │
                    │ Nessus / Nikto ...  │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  SecInsight Core    │
                    │                     │
                    │ Parsers             │
                    │ Findings            │
                    │ Severity            │
                    │ Scoring             │
                    │ Comparison          │
                    │ AI explanations     │
                    │ Report generation   │
                    └───────┬─────┬───────┘
                            │     │
                  ┌─────────┘     └─────────┐
                  ▼                         ▼
          ┌───────────────┐        ┌────────────────┐
          │      CLI      │        │   REST API     │
          │ Typer + Rich  │        │ FastAPI        │
          └───────────────┘        └───────┬────────┘
                                           │
                                           ▼
                                  ┌────────────────┐
                                  │ React Dashboard│
                                  │ TypeScript      │
                                  │ Tailwind        │
                                  │ Recharts        │
                                  └────────────────┘
```

### Project structure

```text
secinsight/
├── core/                 # Parsing, scoring, comparison, reports, AI
├── cli/                  # Command-line interface
├── backend/              # FastAPI backend
├── frontend/             # React dashboard
├── docs/                 # Architecture and API documentation
├── Makefile
├── docker-compose.yml
└── README.md
```

---

## Features

### Scan Analysis

Automatically parse supported security-tool output and normalize it into a common finding model.

```bash
secinsight analyze nmap.xml --pretty
```

### Severity Analysis

Findings are categorized into:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

### Security Scoring

Each scan receives a normalized security score and grade based on its findings.

### Filtering

Filter results from the command line:

```bash
secinsight analyze scan.xml --filter "severity>=high"
```

Other examples include:

```text
severity>=critical
severity>=high
host=10.0.0.5
```

### Scan Comparison

Compare two scan results:

```bash
secinsight compare old.json new.json --pretty
```

### Reports

Generate reports in multiple formats:

```bash
secinsight analyze nmap.xml --pdf
secinsight analyze nmap.xml --html
secinsight analyze nmap.xml --json
secinsight analyze nmap.xml --markdown
```

### Risk Analysis

Analyze potentially dangerous services and hosts:

```bash
secinsight analyze nmap.xml --risk
```

### Explanations

Get explanations for individual findings:

```bash
secinsight analyze zap.xml --explain
```

### Student / Professional Modes

Student-friendly output:

```bash
secinsight analyze nikto.txt --student
```

Professional output:

```bash
secinsight analyze nikto.txt --pro
```

### AI-style Analysis

SecInsight includes a deterministic local generator by default:

```bash
secinsight analyze zap.xml --ai-summary
secinsight analyze zap.xml --ai-fix
```

For richer generated prose, an `ANTHROPIC_API_KEY` can optionally be provided through the environment.

No API key is required for the default local generator.

---

## CLI

Install the core and CLI packages:

```bash
pip install -e core -e cli
```

Check supported tools:

```bash
secinsight tools
```

Analyze a scan:

```bash
secinsight analyze scan.xml --pretty
```

Useful options:

| Option | Description |
|---|---|
| `--pretty` | Formatted terminal output |
| `--summary` | Show only score and summary |
| `--full` | Show complete finding details |
| `--student` | Beginner-friendly explanations |
| `--pro` | Professional output |
| `--pdf` | Generate PDF report |
| `--html` | Generate HTML report |
| `--json` | Generate JSON report |
| `--markdown` | Generate Markdown report |
| `--score` | Show only the numeric score |
| `--risk` | Analyze risky services |
| `--explain` | Explain findings |
| `--story` | Generate an attack-path narrative |
| `--graph` | Generate severity chart |
| `--timeline` | Show scan score history |
| `--filter` | Filter findings |
| `--ai-summary` | Generate AI-style summary |
| `--ai-fix` | Generate remediation guidance |
| `--tool` | Force a specific parser |
| `--output-dir` | Set report output directory |

---

## Docker Quick Start

Build and start the complete stack:

```bash
docker compose up --build
```

After startup:

| Service | URL |
|---|---|
| Frontend | http://localhost:8080 |
| Backend API | http://localhost:8000 |
| API documentation | http://localhost:8000/docs |
| PostgreSQL | localhost:5432 |

### PostgreSQL password

Docker Compose supports an environment variable:

```bash
export POSTGRES_PASSWORD="your-local-password"
docker compose up --build
```

If no password is supplied, the development fallback configured in `docker-compose.yml` is used.

**Do not use development credentials for production deployments.**

---

## Local Development

Install dependencies:

```bash
make install
```

Start the backend:

```bash
make run-backend
```

Backend:

```text
http://localhost:8000
```

Start the frontend in another terminal:

```bash
make run-frontend
```

Frontend:

```text
http://localhost:5173
```

### SQLite development mode

For a zero-setup local backend, SQLite can be used instead of PostgreSQL:

```bash
export DATABASE_URL=sqlite:///./dev.db
make run-backend
```

---

## Testing

Run the complete Python test suite:

```bash
make test
```

The test suite covers:

- Core domain models
- Scanner parsers
- Severity mapping
- Security scoring
- Finding filters
- Scan comparison
- Report generation
- CLI behavior
- FastAPI endpoints

---

## API

FastAPI documentation is available when the backend is running:

```text
http://localhost:8000/docs
```

Additional API documentation is available in:

```text
docs/api-reference.md
```

---

## Configuration

Common environment variables include:

```text
DATABASE_URL
CORS_ORIGINS
UPLOAD_DIR
REPORTS_DIR
ANTHROPIC_API_KEY
POSTGRES_PASSWORD
```

Keep secrets such as API keys and production database passwords outside the repository.

A local `.env` file can be used for development, but it should never be committed.

---

## Security Notice

SecInsight AI is intended for **authorized security testing, defensive analysis, education, and research**.

Only analyze systems and security-scan results that you are authorized to test.

The project does not provide authorization to scan third-party systems.

---

## Documentation

Additional documentation:

```text
docs/
├── architecture.md
└── api-reference.md
```

---

## Tech Stack

### Core

- Python
- XML / JSON / text parsers
- ReportLab
- Jinja2

### CLI

- Python
- Typer
- Rich

### Backend

- FastAPI
- SQLAlchemy
- PostgreSQL
- Alembic
- Pydantic

### Frontend

- React
- TypeScript
- Tailwind CSS
- Recharts
- Vite

### Infrastructure

- Docker
- Docker Compose

---

## License

Add your chosen open-source license before publishing the project.

For example, you can add an `MIT License` or another license appropriate for your project.

---

## Contributing

Contributions, bug reports, parser improvements, documentation updates, and feature ideas are welcome.

Before submitting a pull request:

```bash
make test
```

Please do not include:

- API keys
- passwords
- private keys
- real authentication tokens
- confidential scan results
- sensitive customer data

---

## Author

**SecInsight AI**

Built as a security-analysis and learning project combining scanner parsing, normalization, scoring, reporting, and web-based visualization.
