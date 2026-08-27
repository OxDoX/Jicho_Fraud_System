from datetime import timedelta

from jicho.hunt_suggestions import annotate_alerts_with_hunts, suggest_hunts_for_alert
from jicho.hunting import FraudHunter
from jicho.models import Alert
from tests.conftest import make_df


def test_portfolio_alert_gets_no_suggestions(base_time):
    hunter = FraudHunter(make_df([
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 1000,
         "timestamp": base_time, "channel": "mobile_money"},
    ]))
    alert = Alert(
        rule_id="R9", rule_name="Synchronized Multi-Account Withdrawal Spike",
        account_id="PORTFOLIO", transaction_id="T1", timestamp=str(base_time),
        severity="HIGH", score=78, description="test",
    )
    assert suggest_hunts_for_alert(alert, hunter) == []


def test_layering_alert_gets_network_suggestion(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 1_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A2"},
        {"account_id": "A2", "transaction_type": "transfer_out", "amount": 900_000,
         "timestamp": base_time + timedelta(minutes=10), "channel": "bank_transfer", "counterparty_id": "A3"},
    ]
    hunter = FraudHunter(make_df(rows))
    alert = Alert(
        rule_id="R7", rule_name="Rapid Cross-Account Layering",
        account_id="A1", transaction_id="T1", timestamp=str(base_time),
        severity="CRITICAL", score=92, description="test",
    )
    suggestions = suggest_hunts_for_alert(alert, hunter)
    hunt_types = {s.hunt_type for s in suggestions}
    assert "account_network" in hunt_types
    network_suggestion = next(s for s in suggestions if s.hunt_type == "account_network")
    account_ids = {r["account_id"] for r in network_suggestion.results}
    assert "A2" in account_ids and "A3" in account_ids


def test_agent_anomaly_alert_hunts_the_agent_till(base_time):
    rows = [
        {"account_id": "C1", "transaction_type": "cash_in", "amount": 100_000,
         "timestamp": base_time, "channel": "agent", "agent_id": "AG1"},
        {"account_id": "C2", "transaction_type": "cash_out", "amount": 500_000,
         "timestamp": base_time, "channel": "agent", "agent_id": "AG1"},
    ]
    hunter = FraudHunter(make_df(rows))
    alert = Alert(
        rule_id="R5", rule_name="Agent Till Cash-Out Anomaly",
        account_id="AG1", transaction_id="T1", timestamp=str(base_time),
        severity="HIGH", score=70, description="test",
    )
    suggestions = suggest_hunts_for_alert(alert, hunter)
    hunt_types = {s.hunt_type for s in suggestions}
    assert "agent_till_activity" in hunt_types


def test_unknown_rule_id_gets_default_strategy(base_time):
    """A new rule (e.g. one drafted via the AI rule-authoring workflow) that
    isn't in RULE_HUNT_STRATEGY must still get hunting support automatically.
    """
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 1_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A2"},
    ]
    hunter = FraudHunter(make_df(rows))
    alert = Alert(
        rule_id="R99_NEW_AI_DRAFTED_RULE", rule_name="Hypothetical New Rule",
        account_id="A1", transaction_id="T1", timestamp=str(base_time),
        severity="HIGH", score=70, description="test",
    )
    suggestions = suggest_hunts_for_alert(alert, hunter)
    assert any(s.hunt_type == "account_network" for s in suggestions)


def test_annotate_alerts_with_hunts_preserves_alert_fields(base_time):
    hunter = FraudHunter(make_df([
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 1000,
         "timestamp": base_time, "channel": "mobile_money"},
    ]))
    alert = Alert(
        rule_id="R2", rule_name="Velocity Spike", account_id="A1", transaction_id="T1",
        timestamp=str(base_time), severity="HIGH", score=75, description="test",
    )
    enriched = annotate_alerts_with_hunts([alert], hunter)
    assert enriched[0]["rule_id"] == "R2"
    assert "suggested_hunts" in enriched[0]
    assert isinstance(enriched[0]["suggested_hunts"], list)
