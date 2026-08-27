"""Phase 5 — Reporting (private, to the program).

Builds a report from the engagement's logged findings — never from
reasoning alone, since every Finding on file was produced by Phase 2
(SAST) or a confirmed Phase 3/4 result. Never combines unrelated findings
into one entry; never inflates severity (report exactly what's on file).

Matches the platform's submission template (system prompt Phase 5) via
`--platform`: hackerone, bugcrowd, intigriti, jira, or the generic default.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..engagement import Engagement
from ..llm.client import LLMUnavailable, SentinelLLM
from ..llm.prompts import report_draft_prompt
from ..models import Finding

PLATFORMS = ("generic", "hackerone", "bugcrowd", "intigriti", "jira")

_PLATFORM_HINTS = {
    "generic": "generic Markdown",
    "hackerone": (
        "HackerOne report format: Title, Weakness (CWE), Severity (CVSS vector "
        "+ score), Summary, Steps to Reproduce, Supporting Material/References, Impact"
    ),
    "bugcrowd": (
        "Bugcrowd submission format: Title, Bug URL, Priority (P1-P5), "
        "Description, Steps to Reproduce, Impact, Suggested Fix"
    ),
    "intigriti": (
        "Intigriti submission format: Title, Domain, Endpoint, Vulnerability "
        "Type (CWE), Severity, Description, Proof of Concept, Impact, Recommendation"
    ),
    "jira": (
        "JIRA issue format: Summary, Issue Type=Bug, Priority, Description with "
        "Environment / Steps to Reproduce / Expected Result / Actual Result, Labels"
    ),
}


def _bugcrowd_priority(cvss: float | None) -> str:
    if cvss is None:
        return "Unscored — needs triage"
    if cvss >= 9:
        return "P1"
    if cvss >= 7:
        return "P2"
    if cvss >= 4:
        return "P3"
    if cvss > 0:
        return "P4"
    return "P5"


def _steps_block(finding: Finding) -> str:
    return "\n".join(f"{i}. {s}" for i, s in enumerate(finding.reproduction_steps, start=1)) or "(none on file)"


def _fallback_section(finding: Finding, platform: str) -> str:
    steps = _steps_block(finding)
    cvss_text = f"{finding.cvss} — {finding.cvss_reasoning}" if finding.cvss is not None else f"unscored — {finding.cvss_reasoning}"

    if platform == "hackerone":
        return (
            f"### {finding.title}\n\n"
            f"- **Weakness (CWE)**: (map from evidence below — not auto-classified)\n"
            f"- **Severity**: {cvss_text}\n"
            f"- **Asset**: {finding.asset}\n\n"
            f"**Summary**\n{finding.impact}\n\n"
            f"**Steps to Reproduce**\n{steps}\n\n"
            f"**Supporting Material / References**\n```\n{finding.evidence_redacted}\n```\n\n"
            f"**Impact**\n{finding.impact}\n"
        )
    if platform == "bugcrowd":
        return (
            f"### {finding.title}\n\n"
            f"- **Bug URL**: {finding.asset}\n"
            f"- **Priority**: {_bugcrowd_priority(finding.cvss)} (from CVSS {finding.cvss if finding.cvss is not None else 'unscored'})\n\n"
            f"**Description**\n{finding.impact}\n\n"
            f"**Steps to Reproduce**\n{steps}\n\n"
            f"**Impact**\n{finding.impact}\n\n"
            f"**Suggested Fix**\n{finding.remediation}\n"
        )
    if platform == "intigriti":
        return (
            f"### {finding.title}\n\n"
            f"- **Domain / Endpoint**: {finding.asset}\n"
            f"- **Vulnerability Type (CWE)**: (map from evidence below — not auto-classified)\n"
            f"- **Severity**: {cvss_text}\n\n"
            f"**Description**\n{finding.impact}\n\n"
            f"**Proof of Concept**\n{steps}\n\n"
            f"```\n{finding.evidence_redacted}\n```\n\n"
            f"**Impact**\n{finding.impact}\n\n"
            f"**Recommendation**\n{finding.remediation}\n"
        )
    if platform == "jira":
        return (
            f"### {finding.title}\n\n"
            f"- **Issue Type**: Bug\n"
            f"- **Priority**: {_bugcrowd_priority(finding.cvss)}\n"
            f"- **Labels**: security, {finding.source.value}, {finding.tool}\n\n"
            f"**Description**\n\n"
            f"*Environment*: {finding.asset}\n\n"
            f"*Steps to Reproduce*\n{steps}\n\n"
            f"*Expected Result*: no vulnerable behavior\n"
            f"*Actual Result*: {finding.impact}\n\n"
            f"**Evidence (redacted)**\n```\n{finding.evidence_redacted}\n```\n\n"
            f"**Remediation**\n{finding.remediation}\n"
        )

    # generic
    return (
        f"### {finding.title}\n\n"
        f"- **Source**: {finding.source.value}\n"
        f"- **Tool(s)**: {finding.tool}\n"
        f"- **Asset**: {finding.asset}\n"
        f"- **CVSS**: {cvss_text}\n"
        f"- **Status**: {finding.status}\n\n"
        f"**Reproduction**\n{steps}\n\n"
        f"**Evidence (redacted)**\n```\n{finding.evidence_redacted}\n```\n\n"
        f"**Impact**\n{finding.impact}\n\n"
        f"**Remediation**\n{finding.remediation}\n"
    )


def _finding_section(finding: Finding, llm: SentinelLLM | None, platform: str) -> str:
    import dataclasses
    import json

    if llm is not None:
        finding_json = json.dumps({**dataclasses.asdict(finding), "source": finding.source.value}, indent=2)
        try:
            return llm.ask(report_draft_prompt(finding_json, _PLATFORM_HINTS.get(platform, platform)))
        except LLMUnavailable:
            pass

    return _fallback_section(finding, platform)


def generate_report(engagement: Engagement, llm: SentinelLLM | None = None, platform: str = "generic") -> str:
    if platform not in PLATFORMS:
        raise ValueError(f"platform must be one of {PLATFORMS}, got '{platform}'")

    findings = engagement.findings or []
    by_source = Counter(f.source.value for f in findings)
    by_status = Counter(f.status for f in findings)

    sections = [_finding_section(f, llm, platform) for f in findings]

    coverage = engagement.root / "hypotheses_raw.md"
    coverage_text = coverage.read_text(encoding="utf-8") if coverage.exists() else "(no Phase 1.75 hypotheses on file)"

    report = f"""# Sentinel Engagement Report — {engagement.scope.program_name}

Generated: {datetime.now(timezone.utc).isoformat()}
Engagement ID: {engagement.id}
Engagement type: {engagement.scope.engagement_type.value}
Report template: {platform}

## Summary Dashboard

- Findings total: {len(findings)}
- By source: {dict(by_source)}
- By status: {dict(by_status)}

## Findings

{"".join(sections) if sections else "(no findings on file)"}

## Coverage Summary (retained, not necessarily submitted)

Hypotheses considered in Phase 1.75:

{coverage_text}
"""

    out_dir = engagement.root / "reports"
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"report_{platform}_{ts}.md"
    out_path.write_text(report, encoding="utf-8")
    engagement.logger.log_action("report_generated", {"path": str(out_path), "finding_count": len(findings), "platform": platform})
    engagement.set_phase("5_reporting_done")
    return str(out_path)
