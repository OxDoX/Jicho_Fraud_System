import pytest

from sentinel import approval
from sentinel.engagement import Engagement
from sentinel.models import EngagementType, ProposalSource, ScopeAsset, ScopeDoc, Proposal


def _engagement(tmp_path):
    scope = ScopeDoc(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[ScopeAsset(pattern="*.example.com")],
    )
    return Engagement("test-eng", scope, root=tmp_path)


def _proposal(**overrides):
    defaults = dict(
        tool="metasploit",
        args="use exploit/multi/handler",
        target="https://app.example.com",
        expected_outcome="test",
        rationale="attempt lateral movement toward the internal network",
        source=ProposalSource.BASELINE,
        phase="3_dast",
    )
    defaults.update(overrides)
    return Proposal(**defaults)


def test_escalation_language_blocked_by_default(tmp_path):
    eng = _engagement(tmp_path)
    with pytest.raises(approval.EscalationNotRequested):
        approval.gate(_proposal(), eng.scope, eng.logger, confirm_fn=lambda _: "y")


def test_escalation_allowed_when_explicitly_requested(tmp_path):
    eng = _engagement(tmp_path)
    record = approval.gate(
        _proposal(), eng.scope, eng.logger, confirm_fn=lambda _: "y", escalation_requested=True
    )
    assert record.decision.value == "approved"


def test_reverse_shell_in_rationale_is_caught():
    hit = approval.check_escalation("nuclei", "-silent", "set up a reverse shell for further access")
    assert hit is not None


def test_baseline_recon_is_not_flagged_as_escalation():
    hit = approval.check_escalation("nuclei", "-t cves/2025/ -rate-limit 5", "baseline CVE scan")
    assert hit is None


def test_escalation_block_is_logged(tmp_path):
    eng = _engagement(tmp_path)
    with pytest.raises(approval.EscalationNotRequested):
        approval.gate(_proposal(), eng.scope, eng.logger, confirm_fn=lambda _: "y")
    events = [r["event_type"] for r in eng.logger.read_action_log()]
    assert "approval_blocked" in events
