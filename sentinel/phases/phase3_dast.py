"""Phase 3 — DAST (Dynamic Analysis). Every step here touches a live target,
so every step goes through the approval gate. No auto-chaining: one
proposal, one approval, one execution, one report back — the caller decides
what happens next.
"""
from __future__ import annotations

from .. import approval
from ..engagement import Engagement
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
