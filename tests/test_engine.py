import pytest

from jicho.config import EngineConfig, load_config
from jicho.engine import FraudEngine
from jicho.exceptions import ConfigValidationError, TransactionSchemaError
from jicho.models import validate_transactions
from tests.conftest import make_df


def test_default_config_is_valid():
    cfg = EngineConfig()
    assert cfg.sim_swap_amount_threshold > 0


def test_config_rejects_unknown_keys():
    with pytest.raises(Exception):
        EngineConfig(this_is_not_a_real_key=123)


def test_config_rejects_bad_offhours_window():
    with pytest.raises(Exception):
        EngineConfig(offhours_start=20, offhours_end=7)  # end before start


def test_load_config_missing_file_raises_clear_error():
    with pytest.raises(ConfigValidationError):
        load_config("/nonexistent/path/config.yaml")


def test_validate_transactions_rejects_missing_columns(base_time):
    import pandas as pd
    df = pd.DataFrame([{"transaction_id": "T1", "account_id": "A1"}])
    with pytest.raises(TransactionSchemaError):
        validate_transactions(df)


def test_validate_transactions_rejects_duplicate_ids(base_time):
    df = make_df([
        {"transaction_id": "DUPLICATE", "account_id": "A1", "transaction_type": "deposit",
         "amount": 1000, "timestamp": base_time, "channel": "mobile_money"},
    ])
    df2 = make_df([
        {"transaction_id": "DUPLICATE", "account_id": "A1", "transaction_type": "deposit",
         "amount": 1000, "timestamp": base_time, "channel": "mobile_money"},
    ])
    import pandas as pd
    combined = pd.concat([df, df2], ignore_index=True)
    with pytest.raises(TransactionSchemaError):
        validate_transactions(combined)


def test_validate_transactions_rejects_unknown_type(base_time):
    df = make_df([
        {"account_id": "A1", "transaction_type": "not_a_real_type",
         "amount": 1000, "timestamp": base_time, "channel": "mobile_money"},
    ])
    with pytest.raises(TransactionSchemaError):
        validate_transactions(df)


def test_validate_transactions_rejects_negative_amount(base_time):
    df = make_df([
        {"account_id": "A1", "transaction_type": "deposit",
         "amount": -500, "timestamp": base_time, "channel": "mobile_money"},
    ])
    with pytest.raises(TransactionSchemaError):
        validate_transactions(df)


def test_engine_runs_all_registered_rules_and_returns_sorted_alerts(base_time):
    from datetime import timedelta
    df = make_df([
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 0,
         "timestamp": base_time, "channel": "mobile_money", "event_type": "sim_swap"},
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 600_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "mobile_money"},
    ])
    engine = FraudEngine()
    alerts = engine.run(df)
    assert len(alerts) >= 1
    # sorted descending by score
    scores = [a.score for a in alerts]
    assert scores == sorted(scores, reverse=True)


def test_engine_isolates_a_failing_rule(monkeypatch, base_time):
    """A rule that raises must not prevent other rules' alerts from being returned."""
    from jicho.rules.base import get_registered_rules
    engine = FraudEngine()

    def broken_evaluate(self, df, config):
        raise RuntimeError("simulated failure")

    # Break one rule's evaluate method for this test only
    rules = get_registered_rules()
    target_cls = rules["R2"]
    monkeypatch.setattr(target_cls, "evaluate", broken_evaluate)

    df = make_df([
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 0,
         "timestamp": base_time, "channel": "mobile_money", "event_type": "sim_swap"},
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 600_000,
         "timestamp": base_time + __import__("datetime").timedelta(hours=1), "channel": "mobile_money"},
    ])
    alerts = engine.run(df)  # must not raise, despite R2 being broken
    assert any(a.rule_id == "R1" for a in alerts)
