from datetime import timedelta

import pytest

from jicho.calibration import apply_suggestions, calibrate, calibrate_amount_thresholds, calibrate_velocity_thresholds
from jicho.config import EngineConfig
from jicho.exceptions import ConfigValidationError
from tests.conftest import make_df

CFG = EngineConfig()


def test_calibrate_amount_thresholds_needs_minimum_sample(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 100_000,
         "timestamp": base_time, "channel": "mobile_money"},
    ]
    suggestions = calibrate_amount_thresholds(make_df(rows), CFG)
    assert suggestions == []  # too few observations to calibrate meaningfully


def test_calibrate_amount_thresholds_uses_high_percentile(base_time):
    rows = [
        {"account_id": f"A{i}", "transaction_type": "withdrawal", "amount": 50_000 + i * 1000,
         "timestamp": base_time + timedelta(minutes=i), "channel": "mobile_money"}
        for i in range(30)
    ]
    suggestions = calibrate_amount_thresholds(make_df(rows), CFG)
    sim_swap_suggestion = next(s for s in suggestions if s.field_name == "sim_swap_amount_threshold")
    # 99th percentile of a 50,000-79,000 range should sit near the top of that range
    assert 75_000 <= sim_swap_suggestion.suggested_value <= 80_000


def test_calibrate_velocity_never_suggests_below_current_floor(base_time):
    # Very calm data — no bursts at all — should not suggest loosening below current config
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 10_000,
         "timestamp": base_time + timedelta(hours=i), "channel": "mobile_money"}
        for i in range(25)
    ]
    suggestions = calibrate_velocity_thresholds(make_df(rows), CFG)
    velocity_suggestion = next((s for s in suggestions if s.field_name == "velocity_txn_count"), None)
    if velocity_suggestion:
        assert velocity_suggestion.suggested_value >= CFG.velocity_txn_count


def test_apply_suggestions_does_not_mutate_original_config():
    from jicho.calibration import ThresholdSuggestion
    original = EngineConfig()
    suggestion = ThresholdSuggestion("sim_swap_amount_threshold", original.sim_swap_amount_threshold, 999_999, "test")
    new_config = apply_suggestions(original, [suggestion])
    assert original.sim_swap_amount_threshold != 999_999  # original untouched
    assert new_config.sim_swap_amount_threshold == 999_999


def test_calibrate_produces_backtest_alert_counts(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 0,
         "timestamp": base_time, "channel": "mobile_money", "event_type": "sim_swap"},
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 600_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "mobile_money"},
    ] + [
        {"account_id": f"A{i}", "transaction_type": "withdrawal", "amount": 50_000 + i * 500,
         "timestamp": base_time + timedelta(minutes=i), "channel": "mobile_money"}
        for i in range(2, 30)
    ]
    report = calibrate(make_df(rows), CFG)
    assert report.alert_count_current >= 0
    assert report.alert_count_suggested >= 0
    assert isinstance(report.to_dict(), dict)


def test_calibrate_amount_thresholds_never_suggests_a_non_positive_threshold(base_time):
    """Regression test for a real bug found during development: a dataset
    where enough transactions are logged at amount=0 (e.g. balance-check or
    authorization-only events — not hypothetical, several of this codebase's
    own test fixtures use amount=0 sim_swap marker rows) can pull even a
    high percentile down to 0. sim_swap_amount_threshold and
    card_testing_amount_threshold both have Field(gt=0) — suggesting 0 for
    either would produce a config that fails its own schema. Confirmed via
    apply_suggestions() before this fix: it silently accepted the invalid
    value via model_copy(), which does not re-validate.
    """
    rows = [
        {"account_id": f"A{i}", "transaction_type": "withdrawal", "amount": 0,
         "timestamp": base_time + timedelta(minutes=i), "channel": "mobile_money"}
        for i in range(25)
    ]
    suggestions = calibrate_amount_thresholds(make_df(rows), CFG)
    assert not any(s.field_name == "sim_swap_amount_threshold" for s in suggestions)

    pos_rows = [
        {"account_id": f"A{i}", "transaction_type": "pos_purchase", "amount": 0 if i < 10 else 5000,
         "timestamp": base_time + timedelta(minutes=i), "channel": "card"}
        for i in range(25)
    ]
    pos_suggestions = calibrate_amount_thresholds(make_df(pos_rows), CFG)
    assert not any(s.field_name == "card_testing_amount_threshold" for s in pos_suggestions)


def test_apply_suggestions_rejects_a_suggestion_that_violates_its_own_field_constraint():
    """Defense-in-depth regression test: even if some future suggestion
    function generates an invalid value despite the guard above,
    apply_suggestions() must not silently hand back a config that fails its
    own schema (which config.model_copy(update=...) would do, since it
    skips validation entirely) — it must fail loudly, the same guarantee
    load_config() already provides for a bad YAML file.
    """
    from jicho.calibration import ThresholdSuggestion
    bad_suggestion = ThresholdSuggestion("sim_swap_amount_threshold", CFG.sim_swap_amount_threshold, 0.0, "test")
    with pytest.raises(ConfigValidationError, match="invalid config"):
        apply_suggestions(CFG, [bad_suggestion])


def test_calibration_never_suggests_structuring_threshold_from_deposit_percentiles(base_time):
    """Regression test for a real bug found during development: calibrating
    structuring_threshold from this institution's own deposit percentiles
    conflated 'typical deposit size' with 'regulatory reporting cutoff' and
    silently broke R3 detection in backtesting (18 alerts -> 17, dropping the
    actual structuring pattern). structuring_threshold must never be
    suggested by this function.
    """
    rows = [
        {"account_id": f"A{i}", "transaction_type": "deposit", "amount": 200_000 + i * 5000,
         "timestamp": base_time + timedelta(minutes=i), "channel": "bank_transfer"}
        for i in range(30)
    ]
    suggestions = calibrate_amount_thresholds(make_df(rows), CFG)
    assert not any(s.field_name == "structuring_threshold" for s in suggestions)
