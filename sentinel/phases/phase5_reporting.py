"""Phase 5 — Reporting (private, to the program).

Builds a Markdown report from the engagement's logged findings — never
from reasoning alone, since every Finding on file was produced by Phase 2
(SAST) or a confirmed Phase 3/4 result. Never combines unrelated findings
into one entry; never inflates severity (report exactly what's on file).
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from ..engagement import Engagement
from ..llm.client import LLMUnavailable, SentinelLLM
from ..llm.prompts import report_draft_prompt
from ..models import Finding


def _finding_section(finding: Finding, llm: SentinelLLM | None) -> str:
    import dataclasses
    import json

    finding_json = json.dumps({**dataclasses.asdict(finding), "source": finding.source.value}, indent=2)

    if llm is not None:
        try:
            return llm.ask(report_draft_prompt(finding_json, "generic Markdown"))
        except LLMUnavailable:
            pass

    return (
        f"### {finding.title}\n\n"
        f"- **Source**: {finding.source.value}\n"
        f"- **Tool(s)**: {finding.tool}\n"
        f"- **Asset**: {finding.asset}\n"
        f"- **CVSS**: {finding.cvss if finding.cvss is not None else 'unscored'} — {finding.cvss_reasoning}\n"
        f"- **Status**: {finding.status}\n\n"
        f"**Reproduction**\n" + "\n".join(f"1. {s}" for s in finding.reproduction_steps) + "\n\n"
        f"**Evidence (redacted)**\n```\n{finding.evidence_redacted}\n```\n\n"
        f"**Impact**\n{finding.impact}\n\n"
        f"**Remediation**\n{finding.remediation}\n"
    )


def generate_report(engagement: Engagement, llm: SentinelLLM | None = None) -> str:
    findings = engagement.findings or []
    by_source = Counter(f.source.value for f in findings)
    by_status = Counter(f.status for f in findings)

    sections = [_finding_section(f, llm) for f in findings]

    coverage = engagement.root / "hypotheses_raw.md"
    coverage_text = coverage.read_text(encoding="utf-8") if coverage.exists() else "(no Phase 1.75 hypotheses on file)"

    report = f"""# Sentinel Engagement Report — {engagement.scope.program_name}

Generated: {datetime.now(timezone.utc).isoformat()}
Engagement ID: {engagement.id}
Engagement type: {engagement.scope.engagement_type.value}

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
    out_path = out_dir / f"report_{ts}.md"
    out_path.write_text(report, encoding="utf-8")
    engagement.logger.log_action("report_generated", {"path": str(out_path), "finding_count": len(findings)})
    engagement.set_phase("5_reporting_done")
    return str(out_path)
