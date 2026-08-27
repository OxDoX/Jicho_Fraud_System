"""Core data model for Sentinel engagements.

Everything that gets logged, approved, or reported flows through these
dataclasses so the audit trail (Hard Constraint 12) has a single shape.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


class EngagementType(str, Enum):
    BUG_BOUNTY = "bug_bounty"
    PENTEST = "pentest"


class ProposalSource(str, Enum):
    BASELINE = "baseline"
    THREAT_INTEL = "threat_intel"
    NOVEL_HYPOTHESIS = "novel_hypothesis"


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    BLOCKED = "blocked"  # refused by the system itself (scope/destructive), never reached a human


@dataclass
class ScopeAsset:
    pattern: str  # domain, "*.example.com", CIDR, or URL prefix
    asset_type: str = "host"  # host | cidr | url


@dataclass
class ScopeDoc:
    program_name: str
    engagement_type: EngagementType
    in_scope: list[ScopeAsset] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    safe_harbor_confirmed: bool = False
    identity_requirement: str = ""
    rate_limit: str = ""
    blackout_windows: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class Proposal:
    tool: str
    args: str
    target: str
    expected_outcome: str
    rationale: str
    source: ProposalSource
    phase: str
    id: str = field(default_factory=lambda: new_id("prop"))
    created_at: str = field(default_factory=now_iso)


@dataclass
class ApprovalRecord:
    proposal_id: str
    decision: ApprovalDecision
    reason: str = ""
    id: str = field(default_factory=lambda: new_id("appr"))
    decided_at: str = field(default_factory=now_iso)


@dataclass
class ExecutionResult:
    proposal_id: str
    approval_id: str
    raw_output_redacted: str
    interpretation: str
    exit_code: Optional[int]
    id: str = field(default_factory=lambda: new_id("exec"))
    executed_at: str = field(default_factory=now_iso)


@dataclass
class Finding:
    title: str
    source: ProposalSource
    tool: str
    asset: str
    cvss: Optional[float]
    cvss_reasoning: str
    reproduction_steps: list[str]
    evidence_redacted: str
    impact: str
    remediation: str
    id: str = field(default_factory=lambda: new_id("find"))
    status: str = "open"  # open | reported | duplicate | wontfix | fixed
    created_at: str = field(default_factory=now_iso)


@dataclass
class Hypothesis:
    primitives: list[str]
    rationale: str
    confidence: str  # low | medium | high
    test_plan: str
    id: str = field(default_factory=lambda: new_id("hyp"))
    status: str = "untested"  # untested | tested | confirmed | refuted
    created_at: str = field(default_factory=now_iso)


@dataclass
class DisclosureGateAnswers:
    program_closed_or_policy_elapsed: bool = False
    written_clearance_reference: str = ""  # must be non-empty to count as documented
    poc_scrubbed_to_defender_only: bool = False
    no_real_user_data: bool = False

    def all_clear(self) -> bool:
        return (
            self.program_closed_or_policy_elapsed
            and bool(self.written_clearance_reference.strip())
            and self.poc_scrubbed_to_defender_only
            and self.no_real_user_data
        )


@dataclass
class DisclosureRecord:
    finding_id: str
    answers: DisclosureGateAnswers
    approved_by: str
    id: str = field(default_factory=lambda: new_id("disc"))
    logged_at: str = field(default_factory=now_iso)
    published: bool = False
    published_at: Optional[str] = None
