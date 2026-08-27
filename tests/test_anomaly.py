from datetime import timedelta

from jicho.anomaly import ANOMALY_RULE_ID, detect_anomalies
from jicho.config import EngineConfig
from tests.conftest import make_df


def _normal_portfolio_rows(base_time, n=12):
    """n accounts with mildly varying, unremarkable inflow/outflow — no
    account should stand out from the rest on any feature.
    """
    rows = []
    for i in range(n):
        acct = f"ACC{i:03d}"
        rows.append({
            "account_id": acct, "transaction_type": "deposit",
            "amount": 45_000 + i * 1_000, "timestamp": base_time, "channel": "mobile_money",
        })
        rows.append({
            "account_id": acct, "transaction_type": "withdrawal",
            "amount": 20_000 + i * 500, "timestamp": base_time + timedelta(hours=1), "channel": "mobile_money",
        })
    return rows


def test_flags_account_with_wildly_outsized_outflow(base_time):
    """A single account sweeping out an amount orders of magnitude beyond
    every other account in the portfolio should be flagged, even though no
    named rule (R1-R18) is involved at all.
    """
    rows = _normal_portfolio_rows(base_time)
    rows.append({
        "account_id": "ACC999", "transaction_type": "withdrawal",
        "amount": 80_000_000, "timestamp": base_time + timedelta(hours=2), "channel": "mobile_money",
    })
    df = make_df(rows)

    alerts = detect_anomalies(df, EngineConfig())

    assert any(a.account_id == "ACC999" and a.rule_id == ANOMALY_RULE_ID for a in alerts)
    flagged = next(a for a in alerts if a.account_id == "ACC999")
    assert flagged.evidence["driving_feature"] == "total_outflow"
    assert flagged.evidence["modified_z_score"] >= EngineConfig().anomaly_zscore_threshold
    assert "statistical outlier" in flagged.description
    assert "named detection rules" in flagged.description


def test_excludes_accounts_already_covered_by_a_rule_alert(base_time):
    """An account already explained by a named rule this run must not also
    surface here under the "flagged independently of the named rules"
    framing — that would misrepresent an already-explained finding as a
    fresh, unexplained one. The account still counts toward the portfolio
    baseline; it's just not re-emitted as its own anomaly alert.
    """
    rows = _normal_portfolio_rows(base_time)
    rows.append({
        "account_id": "ACC999", "transaction_type": "withdrawal",
        "amount": 80_000_000, "timestamp": base_time + timedelta(hours=2), "channel": "mobile_money",
    })
    df = make_df(rows)

    alerts = detect_anomalies(df, EngineConfig(), exclude_accounts=frozenset({"ACC999"}))

    assert not any(a.account_id == "ACC999" for a in alerts)


def test_silent_on_a_portfolio_with_no_outliers(base_time):
    """Normal, unremarkable variation across accounts must not itself be
    flagged — this is the negative case proving the layer isn't just noisy.
    """
    df = make_df(_normal_portfolio_rows(base_time))

    alerts = detect_anomalies(df, EngineConfig())

    assert alerts == []


def test_skips_below_minimum_portfolio_size_even_with_an_extreme_outlier(base_time):
    """Regression/limitation test: below anomaly_min_accounts_for_baseline
    accounts, there's no meaningful baseline to compare against, so the
    layer must stay silent rather than flag off a near-empty sample — this
    is a documented structural limitation, not a bug to quietly work around.
    """
    rows = _normal_portfolio_rows(base_time, n=3)
    rows.append({
        "account_id": "ACC999", "transaction_type": "withdrawal",
        "amount": 80_000_000, "timestamp": base_time + timedelta(hours=2), "channel": "mobile_money",
    })
    df = make_df(rows)

    alerts = detect_anomalies(df, EngineConfig())

    assert alerts == []


def test_respects_anomaly_detection_enabled_false(base_time):
    """Config-gated off switch: even a portfolio with an obvious, flaggable
    outlier must return no alerts once the feature is disabled.
    """
    rows = _normal_portfolio_rows(base_time)
    rows.append({
        "account_id": "ACC999", "transaction_type": "withdrawal",
        "amount": 80_000_000, "timestamp": base_time + timedelta(hours=2), "channel": "mobile_money",
    })
    df = make_df(rows)

    alerts = detect_anomalies(df, EngineConfig(anomaly_detection_enabled=False))

    assert alerts == []


def test_not_registered_as_a_named_rule():
    """Sharp-line regression: the anomaly layer must never show up in the
    engine's rule registry — it is deliberately not a Rule subclass (see
    jicho/anomaly.py's module docstring), so FraudEngine.run() must not
    silently start returning ANOMALY-tagged alerts alongside R1-R18 ones.
    """
    from jicho.rules import get_registered_rules

    assert ANOMALY_RULE_ID not in get_registered_rules()
