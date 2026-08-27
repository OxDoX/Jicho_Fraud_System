from sentinel.engagement import Engagement
from sentinel.models import EngagementType, ScopeAsset, ScopeDoc
from sentinel.phases import phase3_dast


def _engagement(tmp_path, exclusions=None):
    scope = ScopeDoc(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[ScopeAsset(pattern="*.example.com")],
        exclusions=exclusions or [],
    )
    return Engagement("test-eng", scope, root=tmp_path)


def _answers(*values):
    queue = list(values)

    def confirm_fn(_prompt):
        return queue.pop(0)

    return confirm_fn


def test_exclusion_match_declined_stops_before_approval_gate(tmp_path):
    eng = _engagement(tmp_path, exclusions=["clickjacking on non-sensitive pages"])
    result = phase3_dast.propose_and_run(
        eng,
        tool="nuclei",
        args="-silent",
        target="https://app.example.com",
        expected_outcome="test",
        rationale="testing for a clickjacking issue on the login page",
        confirm_fn=_answers("n"),  # decline the exclusion-match prompt; gate is never reached
    )
    assert result is None
    events = [r["event_type"] for r in eng.logger.read_action_log()]
    assert "dedup_exclusion_flagged" in events
    assert "proposal_created" not in events  # never reached the gate


def test_exclusion_match_can_be_overridden_and_proceeds_to_gate(tmp_path):
    eng = _engagement(tmp_path, exclusions=["clickjacking on non-sensitive pages"])
    result = phase3_dast.propose_and_run(
        eng,
        tool="nuclei",
        args="-silent",
        target="https://app.example.com",
        expected_outcome="test",
        rationale="testing for a clickjacking issue on the login page",
        confirm_fn=_answers("y", "y"),  # override the exclusion warning, then approve
    )
    assert result is not None  # execution attempted (nuclei likely missing on PATH, still returns a result)
    events = [r["event_type"] for r in eng.logger.read_action_log()]
    assert "dedup_exclusion_flagged" in events
    assert "proposal_created" in events


def test_no_exclusion_match_skips_the_extra_prompt(tmp_path):
    eng = _engagement(tmp_path, exclusions=["clickjacking on non-sensitive pages"])
    result = phase3_dast.propose_and_run(
        eng,
        tool="nuclei",
        args="-silent",
        target="https://app.example.com",
        expected_outcome="test",
        rationale="baseline recon scan",
        confirm_fn=_answers("y"),  # only the approval prompt should fire
    )
    assert result is not None
    events = [r["event_type"] for r in eng.logger.read_action_log()]
    assert "dedup_exclusion_flagged" not in events
