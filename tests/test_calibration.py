from datetime import timedelta

from jicho.calibration import apply_suggestions, calibrate, calibrate_amount_thresholds, calibrate_velocity_thresholds
from jicho.config import EngineConfig
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
