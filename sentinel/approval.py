"""The approval gate: Hard Constraints 1, 2, 3, 4, 14.

This is the module that actually makes Sentinel safe. Every proposal that
touches a live target must pass through `gate()`. It is designed so that
even a compromised or careless caller cannot skip it silently:

  - scope is re-checked here, not trusted from the caller
  - destructive patterns are hard-blocked BEFORE a human is even asked
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


class ScopeBlocked(Exception):
    pass


class DestructiveActionBlocked(Exception):
    pass


class EngagementTypeBlocked(Exception):
    pass


def check_destructive(tool: str, args: str) -> str | None:
    """Returns the matched pattern text if the proposal looks destructive, else None."""
    haystack = f"{tool} {args}"
    for pattern in _DESTRUCTIVE_PATTERNS:
        m = pattern.search(haystack)
        if m:
            return m.group(0)
    return None


def gate(
    proposal: Proposal,
    scope: ScopeDoc,
    logger: EngagementLogger,
    confirm_fn=input,
) -> ApprovalRecord:
    """Run a single proposal through the full approval gate.

    Raises ScopeBlocked / DestructiveActionBlocked / EngagementTypeBlocked
    instead of ever silently proceeding. On a clean pass, prompts the human
    with `confirm_fn` for a fresh yes/no and logs + returns the record either way.
    """
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

    # Hard Constraint 1: fresh, explicit, per-action human approval — no batching
    print("\n[PROPOSED ACTION]")
    print(f"  tool       : {proposal.tool}")
    print(f"  args       : {proposal.args}")
    print(f"  target     : {proposal.target}")
    print(f"  expected   : {proposal.expected_outcome}")
    print(f"  rationale  : {proposal.rationale}")
    print(f"  source     : {proposal.source.value}")
    print(f"  phase      : {proposal.phase}")
    answer = confirm_fn("Approve this exact action? [y/N]: ").strip().lower()

    decision = ApprovalDecision.APPROVED if answer == "y" else ApprovalDecision.DENIED
    record = ApprovalRecord(proposal_id=proposal.id, decision=decision, reason=answer)
    logger.log_action("approval_decision", record)
    return record
