# API Reference

Base URL: `/api` (see `http://localhost:8000/docs` for interactive Swagger UI).

## Scans

| Method | Path | Description |
|---|---|---|
| GET | `/scans/tools` | List supported tool parsers |
| POST | `/scans` | Upload + parse + score a scan file. Form field `file`; optional query `tool` |
| GET | `/scans` | List scans (optional `?tool=`, `?limit=`) |
| GET | `/scans/{id}` | Get a scan + its findings (optional `?filter=`) |
| DELETE | `/scans/{id}` | Delete a scan |
| GET | `/scans/{id}/score` | Score + breakdown |
| GET | `/scans/{id}/risk` | Risk analysis (by host, dangerous services) |
| GET | `/scans/{id}/explain` | Per-finding explanations (`?student=true/false`) |
| GET | `/scans/{id}/ai-summary` | AI narrative summary (`?student=`) |
| GET | `/scans/{id}/ai-fix` | AI remediation plan |
| GET | `/scans/{id}/story` | Attack-path narrative |
| GET | `/scans/dashboard/overview` | Aggregate stats for the dashboard |

## Compare

| Method | Path | Description |
|---|---|---|
| GET | `/compare/{old_scan_id}/{new_scan_id}` | Diff two previously-uploaded scans |

## Reports

| Method | Path | Description |
|---|---|---|
| POST | `/reports/{scan_id}/generate` | Generate a report. Query: `format=pdf|html|markdown`, `mode=pro|student`, `ai_summary=true|false` |
| GET | `/reports` | List generated reports (optional `?scan_id=`) |
| GET | `/reports/{report_id}/download` | Download a previously generated report file |

## Finding fields

```json
{
  "finding_id": "a1b2c3d4e5f6a7b8",
  "title": "Open port 3389/tcp (rdp)",
  "severity": "high",
  "tool": "nmap",
  "description": "...",
  "host": "10.0.0.5",
  "port": 3389,
  "protocol": "tcp",
  "service": "rdp",
  "path": null,
  "cve": null,
  "cvss": null,
  "evidence": null,
  "recommendation": "Restrict RDP to a VPN or bastion host..."
}
```

Severity is one of `critical | high | medium | low | info`.
