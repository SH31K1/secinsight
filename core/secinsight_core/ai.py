"""AI-assisted explanations, summaries, remediation advice, and attack-path
storytelling.

By default this runs a deterministic, template-based "local AI" so the tool
works fully offline and in tests. If ANTHROPIC_API_KEY is set in the
environment, `--ai-summary`/`--ai-fix`/`--story`/`--explain` can optionally
call the real Anthropic API for richer prose (see `generate_with_claude`).
Both paths return plain text so the CLI/backend don't need to care which
one ran.
"""
from __future__ import annotations

import os
from typing import Optional

from secinsight_core.models import Finding, ScanResult, Severity
from secinsight_core.scoring import score_scan

_STUDENT_INTROS = {
    Severity.CRITICAL: "This is a critical issue — it means an attacker could very likely take over the system or steal data with little effort.",
    Severity.HIGH: "This is a high-severity issue. It's a serious weakness that a skilled attacker could exploit.",
    Severity.MEDIUM: "This is a medium-severity issue. It's not immediately catastrophic, but it weakens your security and could be combined with other issues.",
    Severity.LOW: "This is a low-severity issue. On its own it's minor, but it's worth fixing as good hygiene.",
    Severity.INFO: "This is informational — it's not a vulnerability by itself, just useful context about the target.",
}

_PRO_INTROS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
}


def explain_finding(finding: Finding, student: bool = True) -> str:
    """Human-readable explanation of a single finding (--explain)."""
    if student:
        intro = _STUDENT_INTROS[finding.severity]
        lines = [f"**{finding.title}**", intro]
        if finding.description:
            lines.append(f"What was found: {finding.description}")
        if finding.host:
            where = finding.host + (f":{finding.port}" if finding.port else "")
            lines.append(f"Where: {where}")
        if finding.cve:
            lines.append(f"Reference: {finding.cve} — you can look this up on the NVD or MITRE CVE database.")
        if finding.recommendation:
            lines.append(f"How to fix it: {finding.recommendation}")
        else:
            lines.append("How to fix it: " + _generic_fix_advice(finding))
        return "\n".join(lines)
    else:
        label = _PRO_INTROS[finding.severity]
        parts = [f"[{label}] {finding.title}"]
        if finding.host:
            parts.append(f"Host: {finding.host}" + (f":{finding.port}" if finding.port else ""))
        if finding.cve:
            parts.append(f"CVE: {finding.cve}" + (f" (CVSS {finding.cvss})" if finding.cvss else ""))
        if finding.description:
            parts.append(f"Detail: {finding.description}")
        if finding.recommendation:
            parts.append(f"Remediation: {finding.recommendation}")
        return " | ".join(parts)


def _generic_fix_advice(finding: Finding) -> str:
    if finding.cve:
        return "Patch the affected software to a version that fixes this CVE, then re-scan to confirm."
    if finding.port:
        return "Restrict network access to this port (firewall/security group) unless it must be public, and keep the service patched."
    if finding.path:
        return "Ensure this path isn't publicly accessible if it shouldn't be, and remove or protect any sensitive files it exposes."
    return "Review this finding against your security policy and remediate or document it as an accepted risk."


def ai_summary(scan: ScanResult, student: bool = False) -> str:
    """Overall narrative summary of a whole scan (--ai-summary)."""
    result = score_scan(scan)
    top = result.top_risks[:5]

    if student:
        lines = [
            f"Here's a plain-English summary of your {scan.meta.tool} scan"
            + (f" against {scan.meta.target}" if scan.meta.target else "") + ".",
            f"Overall security score: {result.score}/100 (grade {result.grade}).",
            result.summary,
        ]
        if top:
            lines.append("\nThe most important things to fix first:")
            for f in top:
                lines.append(f"- {f['title']}" + (f" on {f['host']}" if f.get("host") else ""))
        else:
            lines.append("No high-priority issues were found — nice work!")
        lines.append(
            "\nTip: start with anything marked 'critical' or 'high' since those are the easiest wins for an attacker."
        )
        return "\n".join(lines)
    else:
        lines = [result.summary]
        if top:
            lines.append("Priority findings:")
            for f in top:
                loc = f.get("host") or ""
                lines.append(f"  - [{f['severity'].upper()}] {f['title']} ({loc})")
        return "\n".join(lines)


def ai_fix(scan: ScanResult) -> str:
    """Aggregated remediation plan across the whole scan (--ai-fix)."""
    findings_needing_fix = [f for f in scan.sorted_findings() if f.severity != Severity.INFO]
    if not findings_needing_fix:
        return "No actionable findings — nothing to remediate."

    grouped: dict[str, list[Finding]] = {}
    for f in findings_needing_fix:
        key = f.recommendation or _generic_fix_advice(f)
        grouped.setdefault(key, []).append(f)

    lines = ["Remediation plan (grouped by fix, highest priority first):", ""]
    ordered = sorted(grouped.items(), key=lambda kv: min(f.severity.rank for f in kv[1]))
    for i, (fix, findings) in enumerate(ordered, 1):
        sev = min(findings, key=lambda f: f.severity.rank).severity.value.upper()
        titles = ", ".join(sorted({f.title for f in findings})[:3])
        lines.append(f"{i}. [{sev}] {fix}")
        lines.append(f"   Affects: {titles}" + (" ..." if len(findings) > 3 else ""))
    return "\n".join(lines)


def attack_story(scan: ScanResult) -> str:
    """Narrate a plausible attack path chaining findings together (--story)."""
    findings = scan.sorted_findings()
    if not findings:
        return "No findings were reported, so there's no attack path to tell."

    by_host: dict[str, list[Finding]] = {}
    for f in findings:
        by_host.setdefault(f.host or "the target", []).append(f)

    lines = ["Attack path narrative:", ""]
    step = 1
    for host, host_findings in by_host.items():
        entry_points = [f for f in host_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        recon = [f for f in host_findings if f.severity in (Severity.LOW, Severity.INFO)]

        if not entry_points and not recon:
            continue

        lines.append(f"Target: {host}")
        if recon:
            lines.append(
                f"  {step}. Reconnaissance reveals {len(recon)} exposed service/path(s), "
                f"including {recon[0].title.lower()}, giving an attacker a map of the attack surface."
            )
            step += 1
        if entry_points:
            worst = entry_points[0]
            lines.append(
                f"  {step}. The attacker targets '{worst.title}'"
                + (f" ({worst.cve})" if worst.cve else "")
                + f", a {worst.severity.value}-severity weakness, to gain an initial foothold."
            )
            step += 1
            if len(entry_points) > 1:
                lines.append(
                    f"  {step}. From there, additional weaknesses ({', '.join(f.title for f in entry_points[1:3])}) "
                    "could be chained to escalate privileges or move laterally."
                )
                step += 1
        lines.append("")

    lines.append(
        "Recommendation: close the highest-severity entry points first — they collapse the entire chain above them."
    )
    return "\n".join(lines)


def generate_with_claude(prompt: str, system: Optional[str] = None) -> Optional[str]:
    """Optional integration point: if ANTHROPIC_API_KEY is configured, use the
    real Anthropic API for richer natural-language output. Returns None if no
    key is configured or the call fails, so callers should fall back to the
    deterministic functions above.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic  # type: ignore

        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system or "You are a security analyst assistant.",
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")
    except Exception:
        return None
