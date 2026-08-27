"""Sentinel CLI — the human-facing entrypoint to every phase.

Every command that can touch a live target goes through the approval gate
in sentinel.approval, which prompts interactively on stdin. There is no
"--yes" / "--force" flag anywhere in this file, on purpose: batching or
skipping approval defeats the entire point of the tool (Hard Constraint 1).
"""
import uuid
from pathlib import Path
from typing import List

import typer

from . import approval
from .engagement import Engagement, create_engagement, load_engagement
from .llm.client import LLMUnavailable, SentinelLLM
from .models import ProposalSource
from .phases import (
    phase1_25_dedup,
    phase1_5_threat_intel,
    phase1_75_hypotheses,
    phase1_scope,
    phase2_sast,
    phase3_dast,
    phase4_5_cleanup,
    phase4_verification,
    phase5_reporting,
    phase6_disclosure,
    phase7_retest,
)
from .tools.registry import list_tools

app = typer.Typer(help="Sentinel — approval-gated bug bounty / pentest agent.")


def _print_phase_banner(engagement: Engagement) -> None:
    typer.echo(f"[engagement={engagement.id}] [phase={engagement.current_phase}]")


def _load(engagement_id: str) -> Engagement:
    try:
        return load_engagement(engagement_id)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)


def _require_llm(model: str) -> SentinelLLM:
    return SentinelLLM(model=model)


# --------------------------------------------------------------------------
# Phase 1 — init / intake
# --------------------------------------------------------------------------


@app.command()
def init(
    program_name: str = typer.Argument(..., help="Program/target name."),
    scope: Path = typer.Option(..., "--scope", help="Path to a scope YAML doc (see examples/scope.example.yaml)."),
    engagement_id: str = typer.Option(None, "--id", help="Custom engagement id; auto-generated if omitted."),
):
    """Create a new engagement from a scope doc. Does not confirm scope yet — run `intake` next."""
    eid = engagement_id or f"{program_name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:6]}"
    eng = create_engagement(eid, scope)
    typer.echo(f"Created engagement '{eid}' for program '{eng.scope.program_name}'.")
    typer.echo("Next: sentinel intake --id " + eid)


@app.command()
def intake(engagement_id: str = typer.Option(..., "--id")):
    """Phase 1 — summarize scope/authorization and require explicit human confirmation."""
    eng = _load(engagement_id)
    confirmed = phase1_scope.run(eng)
    if not confirmed:
        typer.echo("Not confirmed. No further phase will run until this is confirmed.")
        raise typer.Exit(1)


# --------------------------------------------------------------------------
# Phase 1.25 — dedup / exclusion check
# --------------------------------------------------------------------------


@app.command("dedup-check")
def dedup_check(
    engagement_id: str = typer.Option(..., "--id"),
    description: str = typer.Option(..., "--description", help="Description of the hypothesis/target to check."),
    prior_reports: Path = typer.Option(None, "--prior-reports", help="Optional local text file of prior disclosed report summaries."),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    phase1_25_dedup.run(eng, description, prior_reports)


# --------------------------------------------------------------------------
# Phase 1.5 — threat intel
# --------------------------------------------------------------------------


@app.command("threat-intel")
def threat_intel(
    engagement_id: str = typer.Option(..., "--id"),
    stack: str = typer.Option(..., "--stack", help="Short description of the target's tech stack."),
    keywords: str = typer.Option(..., "--keywords", help="Comma-separated NVD keyword queries, e.g. 'nginx,graphql,django'."),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM synthesis; save raw sourced NVD data only."),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    llm = None if no_llm else _require_llm(model)
    kw_list = [k.strip() for k in keywords.split(",") if k.strip()]
    brief = phase1_5_threat_intel.run(eng, stack, kw_list, llm=llm)
    typer.echo(brief)


# --------------------------------------------------------------------------
# Phase 1.75 — hypotheses
# --------------------------------------------------------------------------


@app.command()
def hypotheses(
    engagement_id: str = typer.Option(..., "--id"),
    architecture: str = typer.Option(..., "--architecture", help="Short description of the target's architecture."),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    llm = _require_llm(model)
    try:
        hyps = phase1_75_hypotheses.run(eng, architecture, llm)
    except LLMUnavailable as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    for h in hyps:
        typer.echo(f"\n--- {h.id} (confidence={h.confidence}, status={h.status}) ---")
        typer.echo(h.rationale)


# --------------------------------------------------------------------------
# Phase 2 — SAST
# --------------------------------------------------------------------------


@app.command()
def sast(
    engagement_id: str = typer.Option(..., "--id"),
    run: List[str] = typer.Option(..., "--run", help='Repeatable: "tool_name=args", e.g. --run "semgrep=--config auto ."'),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
    no_llm: bool = typer.Option(False, "--no-llm"),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    tool_runs = []
    for spec in run:
        if "=" not in spec:
            typer.echo(f"Bad --run value '{spec}', expected tool_name=args", err=True)
            raise typer.Exit(1)
        name, args = spec.split("=", 1)
        tool_runs.append((name.strip(), args.strip()))
    llm = None if no_llm else _require_llm(model)
    findings = phase2_sast.run(eng, tool_runs, llm=llm)
    typer.echo(f"{len(findings)} finding(s) recorded. Run `sentinel findings --id {engagement_id}` to list.")


# --------------------------------------------------------------------------
# Phase 3 — DAST propose/approve/execute
# --------------------------------------------------------------------------


@app.command()
def propose(
    engagement_id: str = typer.Option(..., "--id"),
    tool: str = typer.Option(..., "--tool"),
    args: str = typer.Option(..., "--args"),
    target: str = typer.Option(..., "--target"),
    expected: str = typer.Option(..., "--expected", help="Expected outcome."),
    rationale: str = typer.Option(..., "--rationale"),
    source: str = typer.Option("baseline", "--source", help="baseline | threat_intel | novel_hypothesis"),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    try:
        src = ProposalSource(source)
    except ValueError:
        typer.echo(f"--source must be one of {[s.value for s in ProposalSource]}", err=True)
        raise typer.Exit(1)

    try:
        phase3_dast.propose_and_run(eng, tool, args, target, expected, rationale, source=src)
    except (approval.ScopeBlocked, approval.DestructiveActionBlocked, approval.EngagementTypeBlocked) as e:
        typer.echo(f"BLOCKED: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def checklist():
    """Print the Phase 3 baseline technique checklist."""
    for item in phase3_dast.BASELINE_CHECKLIST:
        typer.echo(f"- {item}")


# --------------------------------------------------------------------------
# Findings / Phase 4 / Phase 4.5
# --------------------------------------------------------------------------


@app.command()
def findings(engagement_id: str = typer.Option(..., "--id")):
    eng = _load(engagement_id)
    for f in eng.findings:
        typer.echo(f"{f.id}  [{f.status}]  {f.title}  (source={f.source.value}, tool={f.tool})")


@app.command()
def confirm(
    engagement_id: str = typer.Option(..., "--id"),
    finding_id: str = typer.Option(..., "--finding-id"),
):
    eng = _load(engagement_id)
    finding = next((f for f in eng.findings if f.id == finding_id), None)
    if finding is None:
        typer.echo(f"No finding '{finding_id}'.", err=True)
        raise typer.Exit(1)
    ok = phase4_verification.confirm_finding(eng, finding)
    typer.echo("Confirmed." if ok else "Not confirmed.")


@app.command()
def cleanup(
    engagement_id: str = typer.Option(..., "--id"),
    description: str = typer.Option(..., "--description"),
    target: str = typer.Option(..., "--target"),
):
    eng = _load(engagement_id)
    phase4_5_cleanup.propose_cleanup(eng, description, target)


@app.command("scan-leftover-state")
def scan_leftover_state(engagement_id: str = typer.Option(..., "--id")):
    eng = _load(engagement_id)
    hits = phase4_5_cleanup.scan_for_leftover_state(eng)
    if not hits:
        typer.echo("No obvious leftover-state hints found in the action log.")
    for h in hits:
        typer.echo(f"- {h['logged_at']}: {str(h['payload'])[:200]}")


# --------------------------------------------------------------------------
# Phase 5 — reporting
# --------------------------------------------------------------------------


@app.command()
def report(
    engagement_id: str = typer.Option(..., "--id"),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
    no_llm: bool = typer.Option(False, "--no-llm"),
):
    eng = _load(engagement_id)
    llm = None if no_llm else _require_llm(model)
    path = phase5_reporting.generate_report(eng, llm=llm)
    typer.echo(f"Report written to {path}")


# --------------------------------------------------------------------------
# Phase 6 — disclosure
# --------------------------------------------------------------------------


@app.command("disclose-gate")
def disclose_gate(
    engagement_id: str = typer.Option(..., "--id"),
    finding_id: str = typer.Option(..., "--finding-id"),
    approved_by: str = typer.Option(..., "--approved-by", help="Human researcher of record."),
):
    eng = _load(engagement_id)
    record = phase6_disclosure.run_disclosure_gate(eng, finding_id, approved_by)
    typer.echo(f"disclosure record id: {record.id}  all_clear={record.answers.all_clear()}")


@app.command("disclose-draft")
def disclose_draft(
    engagement_id: str = typer.Option(..., "--id"),
    finding_id: str = typer.Option(..., "--finding-id"),
    disclosure_id: str = typer.Option(..., "--disclosure-id"),
    discovery_date: str = typer.Option(..., "--discovery-date"),
    report_date: str = typer.Option(..., "--report-date"),
    vendor_response_date: str = typer.Option("", "--vendor-response-date"),
    fix_date: str = typer.Option("", "--fix-date"),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
    no_llm: bool = typer.Option(False, "--no-llm"),
):
    eng = _load(engagement_id)
    record = next((d for d in eng.disclosures if d.id == disclosure_id), None)
    if record is None:
        typer.echo(f"No disclosure record '{disclosure_id}'. Run disclose-gate first.", err=True)
        raise typer.Exit(1)
    timeline = {
        "discovery": discovery_date,
        "reported": report_date,
        "vendor_response": vendor_response_date,
        "fix": fix_date,
        "disclosure": "(pending)",
    }
    llm = None if no_llm else _require_llm(model)
    try:
        path = phase6_disclosure.draft_disclosure(eng, finding_id, record, timeline, llm=llm)
    except PermissionError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    typer.echo(f"Draft written to {path} (DRAFT — NOT PUBLISHED).")


@app.command()
def publish(
    engagement_id: str = typer.Option(..., "--id"),
    disclosure_id: str = typer.Option(..., "--disclosure-id"),
):
    eng = _load(engagement_id)
    record = next((d for d in eng.disclosures if d.id == disclosure_id), None)
    if record is None:
        typer.echo(f"No disclosure record '{disclosure_id}'.", err=True)
        raise typer.Exit(1)
    try:
        approved = phase6_disclosure.approve_publish(eng, record)
    except PermissionError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    typer.echo("Publish approved and logged." if approved else "Publish declined.")


# --------------------------------------------------------------------------
# Phase 7 — retest
# --------------------------------------------------------------------------


@app.command()
def retest(
    engagement_id: str = typer.Option(..., "--id"),
    finding_id: str = typer.Option(..., "--finding-id"),
    scope: Path = typer.Option(..., "--scope", help="Current scope doc to re-confirm against."),
):
    eng = _load(engagement_id)
    started = phase7_retest.start_retest(eng, finding_id, scope)
    if not started:
        raise typer.Exit(1)


@app.command("retest-outcome")
def retest_outcome(
    engagement_id: str = typer.Option(..., "--id"),
    finding_id: str = typer.Option(..., "--finding-id"),
    fix_holds: bool = typer.Option(..., "--fix-holds/--fix-does-not-hold"),
    notes: str = typer.Option("", "--notes"),
):
    eng = _load(engagement_id)
    phase7_retest.record_retest_outcome(eng, finding_id, fix_holds, notes)


# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------


@app.command("list-tools")
def list_tools_cmd(category: str = typer.Option(None, "--category")):
    for t in list_tools(category):
        flags = []
        if t.sast:
            flags.append("sast")
        if t.manual_only:
            flags.append("manual_only")
        if t.pentest_only:
            flags.append("pentest_only")
        if t.requires_credentials:
            flags.append("requires_credentials")
        typer.echo(f"{t.name:16} [{t.category:8}] {t.description}  {'(' + ','.join(flags) + ')' if flags else ''}")


def main():
    app()


if __name__ == "__main__":
    main()
