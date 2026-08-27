"""Sentinel CLI — the human-facing entrypoint to every phase.

Every command that can touch a live target goes through the approval gate
in sentinel.approval, which prompts interactively on stdin. There is no
"--yes" / "--force" flag anywhere in this file, on purpose: batching or
skipping approval defeats the entire point of the tool (Hard Constraint 1).
"""
import json
import uuid
from pathlib import Path
from typing import List

import typer

from . import approval
from .doctor import format_report, run_diagnostics
from .engagement import Engagement, create_engagement, load_engagement
from .llm.client import LLMUnavailable, SentinelLLM
from .models import ProposalSource
from .phases import (
    phase1_25_dedup,
    phase1_5_threat_intel,
    phase1_75_hypotheses,
    phase1_fingerprint,
    phase1_scope,
    phase2_sast,
    phase3_dast,
    phase4_5_cleanup,
    phase4_verification,
    phase5_reporting,
    phase6_disclosure,
    phase7_retest,
)
from .tools.freshness import check_nuclei_templates
from .tools.registry import list_tools

app = typer.Typer(help="Sentinel — approval-gated bug bounty / pentest agent.")


def _print_phase_banner(engagement: Engagement) -> None:
    status = f"STOPPED: {engagement.stop_reason}" if engagement.stopped else "active"
    typer.echo(f"[engagement={engagement.id}] [phase={engagement.current_phase}] [{status}]")


def _load(engagement_id: str) -> Engagement:
    try:
        return load_engagement(engagement_id)
    except FileNotFoundError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)


def _require_llm(model: str) -> SentinelLLM:
    return SentinelLLM(model=model)


# --------------------------------------------------------------------------
# Readiness check — run this first, before any engagement exists
# --------------------------------------------------------------------------


@app.command()
def doctor(
    scope: Path = typer.Option(None, "--scope", help="Optional scope doc to validate as part of the check."),
):
    """Concrete readiness check, not an assertion: is ANTHROPIC_API_KEY set
    and the anthropic package installed, which of the approved tools are
    actually on PATH, and (with --scope) does a given scope doc load
    cleanly. Run this before pointing the agent at a real engagement."""
    report = run_diagnostics(scope)
    typer.echo(format_report(report))


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


@app.command()
def status(engagement_id: str = typer.Option(..., "--id")):
    """Session continuity (Hard Constraint 15) — restate scope, authorization,
    findings, and pending state before doing anything else on a resumed engagement."""
    eng = _load(engagement_id)
    _print_phase_banner(eng)
    typer.echo(phase1_scope.summarize(eng))
    typer.echo(f"\nPhase 1 confirmed: {eng.phase1_confirmed}")
    typer.echo(f"Findings on file: {len(eng.findings)}")
    for f in eng.findings:
        typer.echo(f"  - {f.id}  [{f.status}]  {f.title}")
    typer.echo(f"Hypotheses on file: {len(eng.hypotheses)}")
    typer.echo(f"Disclosure records on file: {len(eng.disclosures)}")
    for d in eng.disclosures:
        typer.echo(f"  - {d.id}  all_clear={d.answers.all_clear()}  published={d.published}")

    staleness = phase1_5_threat_intel.staleness_warning(eng)
    if staleness:
        typer.echo(f"\n⚠ {staleness}")


@app.command("refresh-check")
def refresh_check(engagement_id: str = typer.Option(..., "--id")):
    """How current is the agent's picture of the threat landscape right
    now? Reports threat-intel brief age (Hard Constraint 5 / Phase 1.5:
    'the technique landscape shifts within weeks') and, if found, how
    stale the local nuclei-templates checkout looks. Purely informational
    — never updates anything on its own; it tells you what to re-run."""
    eng = _load(engagement_id)
    _print_phase_banner(eng)

    staleness = phase1_5_threat_intel.staleness_warning(eng)
    age = phase1_5_threat_intel.brief_age_days(eng)
    if staleness:
        typer.echo(f"⚠ threat-intel: {staleness}")
    else:
        typer.echo(f"✓ threat-intel: brief is {age:.1f} days old, within the {phase1_5_threat_intel.STALE_AFTER_DAYS}-day freshness window")

    templates = check_nuclei_templates()
    if templates.get("path") is None:
        typer.echo(f"? nuclei-templates: {templates['note']}")
    elif templates["stale"]:
        typer.echo(f"⚠ nuclei-templates: {templates['path']} is {templates['age_days']} days old — run `nuclei -update-templates`")
    else:
        typer.echo(f"✓ nuclei-templates: {templates['path']} is {templates['age_days']} days old")


@app.command()
def stop(
    engagement_id: str = typer.Option(..., "--id"),
    reason: str = typer.Option(..., "--reason", help="Why you're stopping — logged, and shown on every subsequent blocked action."),
):
    """Emergency stop (Hard Constraint 17). Halts every further target-touching
    action, disclosure step, and retest on this engagement immediately."""
    eng = _load(engagement_id)
    eng.stop(reason)
    typer.echo(f"Engagement '{engagement_id}' STOPPED: {reason}")
    typer.echo("No further action will proceed until `sentinel resume` is run explicitly.")


@app.command()
def resume(
    engagement_id: str = typer.Option(..., "--id"),
    reason: str = typer.Option(..., "--reason", help="Why re-authorization is happening now — required, logged."),
):
    """Explicit re-authorization after an emergency stop. Never implicit —
    silence or a topic change is never treated as resumption."""
    eng = _load(engagement_id)
    if not eng.stopped:
        typer.echo("Engagement is not currently stopped.")
        raise typer.Exit(1)
    eng.resume(reason)
    typer.echo(f"Engagement '{engagement_id}' RESUMED: {reason}")


# --------------------------------------------------------------------------
# Phase 1 — tech-stack fingerprinting
# --------------------------------------------------------------------------


@app.command("fingerprint-code")
def fingerprint_code(
    engagement_id: str = typer.Option(..., "--id"),
    path: Path = typer.Option(..., "--path", help="Local repo/checkout to scan for manifest files."),
):
    """Detect languages/frameworks/dependencies from local manifest files
    (package.json, requirements.txt, go.mod, Gemfile, composer.json,
    pom.xml, Dockerfile, ...). Local files only — no approval gate needed,
    same as any other Phase 2 SAST activity. Feeds threat-intel/hypotheses/
    suggest automatically unless you override with --stack/--architecture."""
    eng = _load(engagement_id)
    _print_phase_banner(eng)
    if not path.exists():
        typer.echo(f"Path does not exist: {path}", err=True)
        raise typer.Exit(1)
    detected = phase1_fingerprint.detect_local_stack(path)
    merged = phase1_fingerprint.save_local_stack(eng, detected)
    typer.echo(phase1_fingerprint.summarize_stack(merged))


@app.command("fingerprint-target")
def fingerprint_target(
    engagement_id: str = typer.Option(..., "--id"),
    target: str = typer.Option(..., "--target"),
    tool: str = typer.Option("whatweb", "--tool", help="whatweb | httpx | wappalyzer"),
):
    """Propose a tech-fingerprint scan against a live target. Still touches
    a target, so this goes through the exact same approval gate as any
    other Phase 3 proposal (passive recon is not an 'obviously safe'
    exception — Hard Constraint 1). On a successful run, tech hints parsed
    from the output are merged into detected_stack.json."""
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    tool_args = {"whatweb": "", "httpx": "-tech-detect -silent", "wappalyzer": ""}.get(tool, "")
    try:
        result = phase3_dast.propose_and_run(
            eng,
            tool=tool,
            args=f"{tool_args} {target}".strip(),
            target=target,
            expected_outcome="identify running technologies/frameworks/CMS",
            rationale="Phase 1 tech-stack fingerprinting",
            source=ProposalSource.BASELINE,
        )
    except (
        approval.EmergencyStopped,
        approval.ScopeBlocked,
        approval.DestructiveActionBlocked,
        approval.EngagementTypeBlocked,
        approval.EscalationNotRequested,
    ) as e:
        typer.echo(f"BLOCKED: {e}", err=True)
        raise typer.Exit(1)

    if result is None or result.exit_code != 0:
        return

    hints = phase1_fingerprint.extract_tech_hints(result.raw_output_redacted)
    existing = phase1_fingerprint.load_detected_stack(eng)
    existing.setdefault("live_target", {})[target] = hints
    (eng.root / phase1_fingerprint.STACK_PATH_NAME).write_text(
        json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    eng.logger.log_action("stack_fingerprinted_live", {"target": target, "hints": hints})
    typer.echo(f"Detected tech hints for {target}: {hints or '(none parsed)'}")


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
    stack: str = typer.Option(
        None, "--stack",
        help="Short description of the target's tech stack. Auto-filled from "
             "fingerprint-code/fingerprint-target output if omitted.",
    ),
    keywords: str = typer.Option(
        None, "--keywords",
        help="Comma-separated NVD keyword queries, e.g. 'nginx,graphql,django'. "
             "Auto-derived from the detected stack if omitted.",
    ),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM synthesis; save raw sourced NVD data only."),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)

    detected = phase1_fingerprint.load_detected_stack(eng)
    if stack is None:
        stack = phase1_fingerprint.summarize_stack(detected)
        typer.echo(f"No --stack given, using auto-detected stack:\n{stack}\n")

    if keywords is None:
        kw_list = phase1_fingerprint.derive_keywords(detected)
        if not kw_list:
            typer.echo(
                "No --keywords given and nothing to derive from a detected stack. "
                "Run `sentinel fingerprint-code` / `fingerprint-target` first, or pass --keywords.",
                err=True,
            )
            raise typer.Exit(1)
        typer.echo(f"No --keywords given, using auto-derived: {', '.join(kw_list)}\n")
    else:
        kw_list = [k.strip() for k in keywords.split(",") if k.strip()]

    llm = None if no_llm else _require_llm(model)
    brief = phase1_5_threat_intel.run(eng, stack, kw_list, llm=llm)
    typer.echo(brief)


# --------------------------------------------------------------------------
# Phase 1.75 — hypotheses
# --------------------------------------------------------------------------


@app.command()
def hypotheses(
    engagement_id: str = typer.Option(..., "--id"),
    architecture: str = typer.Option(
        None, "--architecture",
        help="Short description of the target's architecture. Auto-filled from "
             "the detected stack + scope summary if omitted.",
    ),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)

    staleness = phase1_5_threat_intel.staleness_warning(eng)
    if staleness:
        typer.echo(f"⚠ {staleness}\n")

    if architecture is None:
        detected = phase1_fingerprint.load_detected_stack(eng)
        architecture = (
            f"{phase1_scope.summarize(eng)}\n\n"
            f"Detected tech stack:\n{phase1_fingerprint.summarize_stack(detected)}"
        )
        typer.echo(f"No --architecture given, using auto-detected stack + scope summary.\n")

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
    llm_triage: bool = typer.Option(
        False,
        "--llm-triage",
        help=(
            "Explicit opt-in (Hard Constraint 10): send this run's redacted tool "
            "output — which can include source code context lines — to the "
            "configured LLM API for triage synthesis. Off by default; without it "
            "you get the raw (redacted) tool output as the finding evidence."
        ),
    ),
):
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    if llm_triage:
        typer.echo("⚠ --llm-triage is on: redacted tool output for this run will be sent to the LLM API.")
    tool_runs = []
    for spec in run:
        if "=" not in spec:
            typer.echo(f"Bad --run value '{spec}', expected tool_name=args", err=True)
            raise typer.Exit(1)
        name, args = spec.split("=", 1)
        tool_runs.append((name.strip(), args.strip()))
    llm = _require_llm(model) if llm_triage else None
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
    escalation_requested: bool = typer.Option(
        False,
        "--escalation-requested",
        help=(
            "Hard Constraint 4: only pass this if the human explicitly asked for "
            "this specific next step beyond confirming a vulnerability exists, "
            "after you flagged the risk to them. Without it, anything reading as "
            "lateral movement / exfil / persistence / a shell / privesc is blocked."
        ),
    ),
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
        phase3_dast.propose_and_run(
            eng, tool, args, target, expected, rationale, source=src, escalation_requested=escalation_requested
        )
    except (
        approval.EmergencyStopped,
        approval.ScopeBlocked,
        approval.DestructiveActionBlocked,
        approval.EngagementTypeBlocked,
        approval.EscalationNotRequested,
    ) as e:
        typer.echo(f"BLOCKED: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def checklist():
    """Print the Phase 3 baseline technique checklist."""
    for item in phase3_dast.BASELINE_CHECKLIST:
        typer.echo(f"- {item}")


@app.command()
def suggest(
    engagement_id: str = typer.Option(..., "--id"),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
):
    """Have the LLM draft candidate Phase 3 proposals from the scope,
    threat-intel brief (Phase 1.5), and hypotheses on file (Phase 1.75).
    This only drafts and saves to suggested_proposals.json — nothing is
    approved or executed. Review the output, then run one through the
    normal approval gate with `propose-suggested --index N`."""
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)
    staleness = phase1_5_threat_intel.staleness_warning(eng)
    if staleness:
        typer.echo(f"⚠ {staleness}\n")
    llm = _require_llm(model)
    try:
        suggestions = phase3_dast.suggest_proposals(eng, llm)
    except LLMUnavailable as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)

    for i, s in enumerate(suggestions):
        if "_unparsed" in s:
            typer.echo(f"[{i}] (LLM output didn't parse as JSON — see suggested_proposals.json)")
            continue
        typer.echo(f"[{i}] {s.get('tool')} {s.get('args')} -> {s.get('target')}  (source={s.get('source')})")
        typer.echo(f"     expected  : {s.get('expected_outcome')}")
        typer.echo(f"     rationale : {s.get('rationale')}")
    typer.echo(
        f"\n{len(suggestions)} suggestion(s) saved to {eng.root / 'suggested_proposals.json'}.\n"
        f"Run one: sentinel propose-suggested --id {engagement_id} --index N"
    )


@app.command("list-suggestions")
def list_suggestions(engagement_id: str = typer.Option(..., "--id")):
    eng = _load(engagement_id)
    path = eng.root / "suggested_proposals.json"
    if not path.exists():
        typer.echo("No suggestions on file. Run `sentinel suggest` first.")
        return
    for i, s in enumerate(json.loads(path.read_text(encoding="utf-8"))):
        typer.echo(f"[{i}] {s}")


@app.command("propose-suggested")
def propose_suggested(
    engagement_id: str = typer.Option(..., "--id"),
    index: int = typer.Option(..., "--index"),
    escalation_requested: bool = typer.Option(False, "--escalation-requested"),
):
    """Take suggestion #index from `sentinel suggest`'s output and run it
    through the exact same propose -> approve -> execute cycle as `propose`
    — a suggestion is a draft, not a pre-approved action."""
    eng = _load(engagement_id)
    phase1_scope.require_confirmed(eng)
    _print_phase_banner(eng)

    path = eng.root / "suggested_proposals.json"
    if not path.exists():
        typer.echo("No suggestions on file. Run `sentinel suggest` first.", err=True)
        raise typer.Exit(1)
    suggestions = json.loads(path.read_text(encoding="utf-8"))
    if index < 0 or index >= len(suggestions):
        typer.echo(f"--index must be between 0 and {len(suggestions) - 1}", err=True)
        raise typer.Exit(1)

    s = suggestions[index]
    if "_unparsed" in s or "tool" not in s or "target" not in s:
        typer.echo(
            "This suggestion isn't usable structured data — inspect "
            "suggested_proposals.json and use `sentinel propose` manually.",
            err=True,
        )
        raise typer.Exit(1)

    try:
        src = ProposalSource(s.get("source", "baseline"))
    except ValueError:
        typer.echo(f"Suggestion has an invalid source '{s.get('source')}' — defaulting to baseline.")
        src = ProposalSource.BASELINE

    try:
        phase3_dast.propose_and_run(
            eng,
            tool=s["tool"],
            args=s.get("args", ""),
            target=s["target"],
            expected_outcome=s.get("expected_outcome", ""),
            rationale=s.get("rationale", ""),
            source=src,
            escalation_requested=escalation_requested,
        )
    except (
        approval.EmergencyStopped,
        approval.ScopeBlocked,
        approval.DestructiveActionBlocked,
        approval.EngagementTypeBlocked,
        approval.EscalationNotRequested,
    ) as e:
        typer.echo(f"BLOCKED: {e}", err=True)
        raise typer.Exit(1)
    except KeyError as e:
        typer.echo(f"Suggested tool is not on the approved list: {e}", err=True)
        raise typer.Exit(1)


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
def correlate(engagement_id: str = typer.Option(..., "--id")):
    """Suggest groups of findings that might share one root cause (same
    asset, overlapping title language) — a suggestion only; nothing merges
    until you run `merge-findings`."""
    eng = _load(engagement_id)
    groups = phase4_verification.correlate_findings(eng)
    if not groups:
        typer.echo("No likely-duplicate groups found.")
        return
    for i, group in enumerate(groups, start=1):
        typer.echo(f"\nGroup {i} (asset={group[0].asset}):")
        for f in group:
            typer.echo(f"  - {f.id}  [{f.status}]  {f.title}")
        typer.echo(f"  -> if these are the same root cause: sentinel merge-findings --id {engagement_id} "
                    f"--keep {group[0].id} --absorb {','.join(f.id for f in group[1:])}")


@app.command("merge-findings")
def merge_findings_cmd(
    engagement_id: str = typer.Option(..., "--id"),
    keep: str = typer.Option(..., "--keep", help="Finding id to keep as the deduplicated root-cause finding."),
    absorb: str = typer.Option(..., "--absorb", help="Comma-separated finding ids to merge into --keep and mark duplicate."),
):
    eng = _load(engagement_id)
    absorb_ids = [a.strip() for a in absorb.split(",") if a.strip()]
    try:
        merged = phase4_verification.merge_findings(eng, keep, absorb_ids)
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    typer.echo(f"Merged {len(absorb_ids)} finding(s) into {merged.id} ({merged.title}).")


@app.command()
def cleanup(
    engagement_id: str = typer.Option(..., "--id"),
    description: str = typer.Option(..., "--description"),
    target: str = typer.Option(..., "--target"),
):
    eng = _load(engagement_id)
    try:
        phase4_5_cleanup.propose_cleanup(eng, description, target)
    except (approval.EmergencyStopped, approval.ScopeBlocked) as e:
        typer.echo(f"BLOCKED: {e}", err=True)
        raise typer.Exit(1)


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
    platform: str = typer.Option(
        "generic", "--platform",
        help=f"Match a platform's submission template. One of: {', '.join(phase5_reporting.PLATFORMS)}",
    ),
    model: str = typer.Option("claude-sonnet-4-5", "--model"),
    no_llm: bool = typer.Option(False, "--no-llm"),
):
    eng = _load(engagement_id)
    llm = None if no_llm else _require_llm(model)
    try:
        path = phase5_reporting.generate_report(eng, llm=llm, platform=platform)
    except ValueError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
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
    try:
        record = phase6_disclosure.run_disclosure_gate(eng, finding_id, approved_by)
    except approval.EmergencyStopped as e:
        typer.echo(f"BLOCKED: {e}", err=True)
        raise typer.Exit(1)
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
    except (PermissionError, approval.EmergencyStopped) as e:
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
    except (PermissionError, approval.EmergencyStopped) as e:
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
    try:
        started = phase7_retest.start_retest(eng, finding_id, scope)
    except approval.EmergencyStopped as e:
        typer.echo(f"BLOCKED: {e}", err=True)
        raise typer.Exit(1)
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
