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
        tool="nuclei",
        args="-silent",
        target="https://app.example.com",
        expected_outcome="test",
        rationale="test",
        source=ProposalSource.BASELINE,
        phase="3_dast",
    )
    defaults.update(overrides)
    return Proposal(**defaults)


def test_stopped_engagement_blocks_gate_even_with_approval(tmp_path):
    eng = _engagement(tmp_path)
    eng.stop("client asked us to pause")
    with pytest.raises(approval.EmergencyStopped):
        approval.gate(
            _proposal(), eng.scope, eng.logger, confirm_fn=lambda _: "y",
            stopped=eng.stopped, stop_reason=eng.stop_reason,
        )


def test_resume_requires_nonempty_reason(tmp_path):
    eng = _engagement(tmp_path)
    eng.stop("pause")
    with pytest.raises(ValueError):
        eng.resume("")


def test_resume_clears_stop_and_allows_gate_again(tmp_path):
    eng = _engagement(tmp_path)
    eng.stop("pause")
    eng.resume("client confirmed we can continue")
    assert eng.stopped is False
    record = approval.gate(
        _proposal(), eng.scope, eng.logger, confirm_fn=lambda _: "y",
        stopped=eng.stopped, stop_reason=eng.stop_reason,
    )
    assert record.decision.value == "approved"


def test_assert_not_stopped_raises_when_stopped(tmp_path):
    eng = _engagement(tmp_path)
    eng.stop("pause")
    with pytest.raises(approval.EmergencyStopped):
        eng.assert_not_stopped()


def test_assert_not_stopped_is_silent_when_active(tmp_path):
    eng = _engagement(tmp_path)
    eng.assert_not_stopped()  # should not raise


def test_stop_state_persists_across_reload(tmp_path):
    eng = _engagement(tmp_path)
    eng.stop("investigating an unexpected result")
    reloaded = Engagement("test-eng", eng.scope, root=tmp_path)
    assert reloaded.stopped is True
    assert reloaded.stop_reason == "investigating an unexpected result"
