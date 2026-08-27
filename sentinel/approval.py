"""The approval gate: Hard Constraints 1, 2, 3, 4, 14, 17.

This is the module that actually makes Sentinel safe. Every proposal that
touches a live target must pass through `gate()`. It is designed so that
even a compromised or careless caller cannot skip it silently:

  - an emergency stop, if set on the engagement, blocks everything until
    an explicit resume — checked before anything else
  - scope is re-checked here, not trusted from the caller
  - destructive patterns are hard-blocked BEFORE a human is even asked
  - escalation-flavored proposals (lateral movement, exfil, persistence,
    reverse shells, ...) are blocked unless the caller explicitly marks
    them as a human-requested next step, not proposed unprompted
  - approval is always a fresh, single-use, interactive confirmation —
    there is no "approve all" and no caching across proposals
  - every outcome (blocked, denied, approved) is logged
"""
from __future__ import annotations

import re

from .logging_utils import EngagementLogger
from .models import ApprovalDecision, ApprovalRecord, EngagementType, Proposal
from .scope import ScopeDoc, is_in_scope

# Curated, deliberately conservative denylist of flags/payload fragments that
# are destructive regardless of program or approval (Hard Constraint 3).
# This is a floor, not a ceiling: propose non-destructive alternatives
# (timing/OOB canaries) instead of anything on this list.
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"--dump(-all)?\b", re.I),          # sqlmap data exfil
    re.compile(r"--os-(shell|pwn)\b", re.I),        # sqlmap RCE
    re.compile(r"--sql-shell\b", re.I),
    re.compile(r"\bDROP\s+TABLE\b", re.I),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.I),
    re.compile(r"\bDELETE\s+FROM\b", re.I),
    re.compile(r"\brm\s+-rf\b"),
    re.compile(r"--purge\b", re.I),
    re.compile(r"\bformat\s+c:\b", re.I),
    re.compile(r"-X\s*DELETE\b"),                    # HTTP DELETE via curl/ffuf-style flags
    re.compile(r"--os-cmd[= ]+.*(rm |del |format )", re.I),  # commix destructive os-cmd
    re.compile(r"\bshutdown\b|\breboot\b", re.I),
]

_PENTEST_ONLY_TOOLS = {"crackmapexec", "netexec", "responder", "impacket"}

# Deliberately conservative: proposals that read as going beyond "confirm it
# exists" toward exploitation/persistence/lateral movement (Hard Constraint
# 4). Not exhaustive — a floor, not a ceiling — and text-matched against
# tool+args+rationale so a clearly-stated non-destructive intent in the
# rationale doesn't help you dodge it; it only widens what gets caught.
_ESCALATION_PATTERNS = [
    re.compile(r"\blateral( |-)?movement\b", re.I),
    re.compile(r"\bpriv(ilege)?[\s-]?esc(alation)?\b", re.I),
    re.compile(r"\bpivot(ing)?\b", re.I),
    re.compile(r"\bexfil(trat\w*)?\b", re.I),
    re.compile(r"\bharvest\w*\s+credential", re.I),
    re.compile(r"\breverse\s+shell\b", re.I),
    re.compile(r"\bmeterpreter\b", re.I),
    re.compile(r"\bbackdoor\b", re.I),
    re.compile(r"\bpersist(ence)?\b", re.I),
    re.compile(r"\bdomain\s+admin\b", re.I),
    re.compile(r"\b(full|complete)\s+(compromise|takeover)\b", re.I),
    re.compile(r"\bpost[\s-]?exploit\w*\b", re.I),
]


class ScopeBlocked(Exception):
    pass


class DestructiveActionBlocked(Exception):
    pass


class EngagementTypeBlocked(Exception):
    pass


class EscalationNotRequested(Exception):
    pass


class EmergencyStopped(Exception):
    pass


def check_destructive(tool: str, args: str) -> str | None:
    """Returns the matched pattern text if the proposal looks destructive, else None."""
    haystack = f"{tool} {args}"
    for pattern in _DESTRUCTIVE_PATTERNS:
        m = pattern.search(haystack)
        if m:
            return m.group(0)
    return None


def check_escalation(tool: str, args: str, rationale: str) -> str | None:
    """Returns the matched pattern text if the proposal reads as escalation
    beyond confirming a vulnerability's existence, else None."""
    haystack = f"{tool} {args} {rationale}"
    for pattern in _ESCALATION_PATTERNS:
        m = pattern.search(haystack)
        if m:
            return m.group(0)
    return None


def gate(
    proposal: Proposal,
    scope: ScopeDoc,
    logger: EngagementLogger,
    confirm_fn=input,
    stopped: bool = False,
    stop_reason: str = "",
    escalation_requested: bool = False,
) -> ApprovalRecord:
    """Run a single proposal through the full approval gate.

    Raises EmergencyStopped / ScopeBlocked / DestructiveActionBlocked /
    EngagementTypeBlocked / EscalationNotRequested instead of ever silently
    proceeding. On a clean pass, prompts the human with `confirm_fn` for a
    fresh yes/no and logs + returns the record either way.
    """
    # Hard Constraint 17: an emergency stop blocks everything, no exceptions,
    # checked before the proposal is even logged as attempted.
    if stopped:
        logger.log_action(
            "action_refused_engagement_stopped",
            {"tool": proposal.tool, "target": proposal.target, "stop_reason": stop_reason},
        )
        raise EmergencyStopped(
            f"Engagement is stopped ({stop_reason or 'no reason logged'}). "
            f"Re-authorize with `sentinel resume` before any further action."
        )

    logger.log_action("proposal_created", proposal)

    # Hard Constraint 16 / pentest-only tooling
    if proposal.tool.lower() in _PENTEST_ONLY_TOOLS and scope.engagement_type != EngagementType.PENTEST:
        record = ApprovalRecord(
            proposal_id=proposal.id,
            decision=ApprovalDecision.BLOCKED,
            reason=f"tool '{proposal.tool}' is pentest-only and this engagement_type is '{scope.engagement_type.value}'",
        )
        logger.log_action("approval_blocked", record)
        raise EngagementTypeBlocked(record.reason)

    # Hard Constraint 2: scope lock, re-checked here regardless of caller
    in_scope, reason = is_in_scope(scope, proposal.target)
    if not in_scope:
        record = ApprovalRecord(
            proposal_id=proposal.id,
            decision=ApprovalDecision.BLOCKED,
            reason=f"target out of scope: {reason}",
        )
        logger.log_action("approval_blocked", record)
        logger.log_action("out_of_scope_discovery", {"target": proposal.target, "reason": reason})
        raise ScopeBlocked(record.reason)

    # Hard Constraint 3: destructive actions never run, approval or not
    destructive_hit = check_destructive(proposal.tool, proposal.args)
    if destructive_hit:
        record = ApprovalRecord(
            proposal_id=proposal.id,
            decision=ApprovalDecision.BLOCKED,
            reason=f"destructive pattern matched: '{destructive_hit}'",
        )
        logger.log_action("approval_blocked", record)
        raise DestructiveActionBlocked(record.reason)

    # Hard Constraint 4: no escalation beyond "confirm it exists" unless the
    # human explicitly asked for this specific next step.
    escalation_hit = check_escalation(proposal.tool, proposal.args, proposal.rationale)
    if escalation_hit and not escalation_requested:
        record = ApprovalRecord(
            proposal_id=proposal.id,
            decision=ApprovalDecision.BLOCKED,
            reason=(
                f"reads as escalation beyond confirming existence ('{escalation_hit}'). "
                f"Only proceed if the human explicitly asked for this next step, and only "
                f"after flagging the risk to them — then re-propose with escalation_requested=True."
            ),
        )
        logger.log_action("approval_blocked", record)
        raise EscalationNotRequested(record.reason)

    # Hard Constraint 1: fresh, explicit, per-action human approval — no batching
    print("\n[PROPOSED ACTION]")
    print(f"  tool       : {proposal.tool}")
    print(f"  args       : {proposal.args}")
    print(f"  target     : {proposal.target}")
    print(f"  expected   : {proposal.expected_outcome}")
    print(f"  rationale  : {proposal.rationale}")
    print(f"  source     : {proposal.source.value}")
    print(f"  phase      : {proposal.phase}")
    if escalation_requested:
        print("  ⚠ marked as an explicitly human-requested escalation step")

    # Hard Constraint 9: flag, don't silently fix — auto-rewriting the args
    # a human is about to approve would violate "execute exactly what was
    # proposed, no silent modification." So this only warns; if it needs to
    # be in there, put it in --args yourself before approving.
    if scope.identity_requirement and scope.identity_requirement.strip() not in proposal.args:
        print(
            f"  ⚠ scope requires identity/attribution: '{scope.identity_requirement}' — "
            f"this does not appear verbatim in --args. Confirm it's actually being sent "
            f"(e.g. via a config/env default) or add it before approving."
        )

    answer = confirm_fn("Approve this exact action? [y/N]: ").strip().lower()

    decision = ApprovalDecision.APPROVED if answer == "y" else ApprovalDecision.DENIED
    record = ApprovalRecord(proposal_id=proposal.id, decision=decision, reason=answer)
    logger.log_action("approval_decision", record)
    return record
