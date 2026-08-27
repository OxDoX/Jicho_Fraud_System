from jicho.config import EngineConfig
from jicho.models import Alert
from jicho.prevention import Decision, decide, decide_safely


def _alert(rule_id, score, severity="CRITICAL", account_id="A1", txn_id="T1"):
    return Alert(
        rule_id=rule_id, rule_name=f"Rule {rule_id}", account_id=account_id, transaction_id=txn_id,
        timestamp="2026-01-01T00:00:00", severity=severity, score=score, description="test",
    )


def test_prevention_disabled_by_default_always_allows():
    cfg = EngineConfig()
    assert cfg.prevention_enabled is False
    decision = decide([_alert("R1", 95)], cfg)
    assert decision.decision == Decision.ALLOW


def test_block_requires_explicit_rule_whitelisting():
    """Even a CRITICAL, high-score alert must not block unless its rule_id
    is explicitly whitelisted -- this is the core safety property of the
    whole module.
    """
    cfg = EngineConfig(prevention_enabled=True, block_eligible_rule_ids=[])  # nothing whitelisted
    decision = decide([_alert("R1", 99)], cfg)
    assert decision.decision != Decision.BLOCK


def test_block_fires_only_for_whitelisted_rule_above_threshold():
    cfg = EngineConfig(prevention_enabled=True, block_eligible_rule_ids=["R1"], block_min_score=90)
    decision = decide([_alert("R1", 95)], cfg)
    assert decision.decision == Decision.BLOCK
    assert len(decision.triggering_alerts) == 1


def test_block_does_not_fire_below_block_min_score_even_if_whitelisted():
    cfg = EngineConfig(prevention_enabled=True, block_eligible_rule_ids=["R1"], block_min_score=90)
    decision = decide([_alert("R1", 85)], cfg)  # whitelisted rule, but score too low
    assert decision.decision != Decision.BLOCK


def test_hold_fires_for_non_whitelisted_high_score_alert():
    cfg = EngineConfig(prevention_enabled=True, block_eligible_rule_ids=["R99"], hold_min_score=75)
    decision = decide([_alert("R1", 95)], cfg)  # R1 not whitelisted for block
    assert decision.decision == Decision.HOLD


def test_allow_for_low_score_alert():
    cfg = EngineConfig(prevention_enabled=True, hold_min_score=75)
    decision = decide([_alert("R3", 60, severity="MEDIUM")], cfg)
    assert decision.decision == Decision.ALLOW


def test_multiple_alerts_take_most_severe_outcome():
    """One BLOCK-eligible alert among several must win, even if others on
    the same transaction would only warrant HOLD or ALLOW.
    """
    cfg = EngineConfig(prevention_enabled=True, block_eligible_rule_ids=["R1"], block_min_score=90, hold_min_score=75)
    alerts = [_alert("R3", 60, severity="MEDIUM"), _alert("R1", 95), _alert("R2", 78, severity="HIGH")]
    decision = decide(alerts, cfg)
    assert decision.decision == Decision.BLOCK


def test_decide_safely_fails_open_by_default():
    cfg = EngineConfig(prevention_enabled=True, block_eligible_rule_ids=["R1"])
    # Pass something that will break decide() internally (non-Alert objects)
    broken_alerts = [{"not": "an alert object"}]
    decision = decide_safely(broken_alerts, cfg)
    assert decision.decision == Decision.ALLOW


def test_decide_safely_fails_closed_when_configured():
    cfg = EngineConfig(prevention_enabled=True, block_eligible_rule_ids=["R1"], prevention_fail_mode="closed")
    broken_alerts = [{"not": "an alert object"}]
    decision = decide_safely(broken_alerts, cfg)
    assert decision.decision == Decision.HOLD


def test_prevention_config_rejects_invalid_fail_mode():
    import pytest
    with pytest.raises(Exception):
        EngineConfig(prevention_fail_mode="somethingelse")
