"""Phase 3 — DAST (Dynamic Analysis). Every step here touches a live target,
so every step goes through the approval gate. No auto-chaining: one
proposal, one approval, one execution, one report back — the caller decides
what happens next.
"""
from __future__ import annotations

import json
import re

from .. import approval
from ..engagement import Engagement
from ..llm.client import SentinelLLM
from ..llm.prompts import dast_proposal_prompt
from ..models import ApprovalDecision, ExecutionResult, Proposal, ProposalSource
from .phase1_25_dedup import check_exclusions

BASELINE_CHECKLIST = [
    "HTTP request smuggling variants (CL.TE, TE.CL, H2C smuggling, HTTP/2 downgrade)",
    "Cache poisoning / cache deception via unkeyed inputs",
    "OAuth/OIDC flaws (redirect_uri bypass, PKCE downgrade, device-code phishing)",
    "Subdomain/cloud resource takeover (dangling CNAME to deprovisioned services)",
    "Race conditions in business logic (concurrent-request limit bypass)",
    "WebSocket/GraphQL subscription auth gaps (checked on connect, not per-message)",
    "SSRF via modern surfaces (webhooks, URL-preview, PDF/image render, cloud metadata/IMDS)",
    "API: GraphQL introspection/batching abuse, mass assignment, JWT alg confusion, broken object-level authorization",
]


def propose_and_run(
    engagement: Engagement,
    tool: str,
    args: str,
    target: str,
    expected_outcome: str,
    rationale: str,
    source: ProposalSource = ProposalSource.BASELINE,
    confirm_fn=input,
    escalation_requested: bool = False,
) -> ExecutionResult | None:
    """One full Phase 3 cycle: dedup/exclusion check -> propose -> approve
    (or refuse) -> execute -> report.

    Returns None if the proposal was blocked (stopped/scope/destructive/
    engagement-type/escalation), declined at the dedup/exclusion check, or
    denied by the human — callers should treat all of these as "did not
    run", the distinction is in the log. Raises the approval module's
    exceptions upward for blocked cases so the caller can't accidentally
    swallow them.
    """
    from ..tools.runner import run_tool  # local import: avoid import cycle at module load

    # Hard Constraint 13: don't spend an approval cycle on a hypothesis that
    # matches a standing program exclusion without flagging it first.
    exclusion_hits = check_exclusions(engagement, f"{tool} {args} {target} {rationale}")
    if exclusion_hits:
        print("\n⚠ This proposal matches a standing program exclusion — flag before spending an approval cycle:")
        for hit in exclusion_hits:
            print(f"  - {hit}")
        proceed = confirm_fn("Proceed anyway despite the likely exclusion match? [y/N]: ").strip().lower() == "y"
        engagement.logger.log_action(
            "dedup_exclusion_flagged",
            {"tool": tool, "target": target, "hits": exclusion_hits, "proceeded": proceed},
        )
        if not proceed:
            return None

    proposal = Proposal(
        tool=tool,
        args=args,
        target=target,
        expected_outcome=expected_outcome,
        rationale=rationale,
        source=source,
        phase="3_dast",
    )

    record = approval.gate(
        proposal,
        engagement.scope,
        engagement.logger,
        confirm_fn=confirm_fn,
        stopped=engagement.stopped,
        stop_reason=engagement.stop_reason,
        escalation_requested=escalation_requested,
    )
    if record.decision != ApprovalDecision.APPROVED:
        print(f"Not executed (decision={record.decision.value}).")
        return None

    result = run_tool(proposal, record)
    engagement.logger.log_action("execution_result", result)
    print("\n[RAW RESULT] (redacted)")
    print(result.raw_output_redacted)
    if result.interpretation:
        print(f"\n[INTERPRETATION]\n{result.interpretation}")
    return result


def _parse_json_array(raw: str) -> list[dict]:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n", "", text)
        text = re.sub(r"\n```\s*$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [{"_unparsed": raw}]
    if not isinstance(data, list):
        return [{"_unparsed": raw}]
    return [item for item in data if isinstance(item, dict)]


def suggest_proposals(engagement: Engagement, llm: SentinelLLM) -> list[dict]:
    """Ask the LLM to draft candidate Phase 3 proposals from the scope,
    threat-intel brief, and Phase 1.75 hypotheses on file. This only
    drafts and saves suggestions to disk — nothing here touches a target,
    requests approval, or executes anything. A suggestion becomes a real
    proposal only when fed into propose_and_run (e.g. via the CLI's
    `propose-suggested`), which runs it through the exact same approval
    gate as anything else."""
    from ..tools.registry import list_tools
    from .phase1_scope import summarize as summarize_scope

    threat_intel_path = engagement.root / "threat_intel_brief.md"
    threat_intel = threat_intel_path.read_text(encoding="utf-8") if threat_intel_path.exists() else "(no Phase 1.5 brief on file)"

    hyps_path = engagement.root / "hypotheses_raw.md"
    hyps_text = hyps_path.read_text(encoding="utf-8") if hyps_path.exists() else "(no Phase 1.75 hypotheses on file)"

    approved_names = ", ".join(sorted(t.name for t in list_tools()))
    checklist_text = "\n".join(f"- {item}" for item in BASELINE_CHECKLIST)

    raw = llm.ask(
        dast_proposal_prompt(summarize_scope(engagement), threat_intel, hyps_text, checklist_text, approved_names),
        max_tokens=3000,
    )
    suggestions = _parse_json_array(raw)

    out_path = engagement.root / "suggested_proposals.json"
    out_path.write_text(json.dumps(suggestions, indent=2, ensure_ascii=False), encoding="utf-8")
    engagement.logger.log_action(
        "proposals_suggested", {"count": len(suggestions), "path": str(out_path)}
    )
    return suggestions
