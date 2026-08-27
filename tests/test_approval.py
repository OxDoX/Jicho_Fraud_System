import pytest

from sentinel import approval
from sentinel.engagement import Engagement
from sentinel.models import EngagementType, ProposalSource, ScopeAsset, ScopeDoc, Proposal


def _engagement(tmp_path, engagement_type=EngagementType.BUG_BOUNTY):
    scope = ScopeDoc(
        program_name="Test",
        engagement_type=engagement_type,
        in_scope=[ScopeAsset(pattern="*.example.com")],
    )
    return Engagement("test-eng", scope, root=tmp_path)


def _proposal(**overrides):
    defaults = dict(
        tool="nuclei",
        args="-t cves/2025/ -rate-limit 5",
        target="https://app.example.com",
        expected_outcome="identify known CVEs",
        rationale="baseline scan",
        source=ProposalSource.BASELINE,
        phase="3_dast",
    )
    defaults.update(overrides)
    return Proposal(**defaults)


def test_out_of_scope_target_is_blocked(tmp_path):
    eng = _engagement(tmp_path)
    proposal = _proposal(target="https://evil.attacker.net")
    with pytest.raises(approval.ScopeBlocked):
        approval.gate(proposal, eng.scope, eng.logger, confirm_fn=lambda _: "y")


def test_destructive_sqlmap_flag_is_blocked_even_with_approval(tmp_path):
    eng = _engagement(tmp_path)
    proposal = _proposal(tool="sqlmap", args="-u https://app.example.com --dump")
    with pytest.raises(approval.DestructiveActionBlocked):
        approval.gate(proposal, eng.scope, eng.logger, confirm_fn=lambda _: "y")


def test_pentest_only_tool_blocked_on_bug_bounty_engagement(tmp_path):
    eng = _engagement(tmp_path, engagement_type=EngagementType.BUG_BOUNTY)
    proposal = _proposal(tool="crackmapexec", args="--users", target="app.example.com")
    with pytest.raises(approval.EngagementTypeBlocked):
        approval.gate(proposal, eng.scope, eng.logger, confirm_fn=lambda _: "y")


def test_pentest_only_tool_allowed_on_pentest_engagement_with_approval(tmp_path):
    eng = _engagement(tmp_path, engagement_type=EngagementType.PENTEST)
    proposal = _proposal(tool="crackmapexec", args="--users", target="app.example.com")
    record = approval.gate(proposal, eng.scope, eng.logger, confirm_fn=lambda _: "y")
    assert record.decision.value == "approved"


def test_human_denial_is_respected(tmp_path):
    eng = _engagement(tmp_path)
    proposal = _proposal()
    record = approval.gate(proposal, eng.scope, eng.logger, confirm_fn=lambda _: "n")
    assert record.decision.value == "denied"


def test_approval_is_logged(tmp_path):
    eng = _engagement(tmp_path)
    proposal = _proposal()
    approval.gate(proposal, eng.scope, eng.logger, confirm_fn=lambda _: "y")
    events = [r["event_type"] for r in eng.logger.read_action_log()]
    assert "proposal_created" in events
    assert "approval_decision" in events
