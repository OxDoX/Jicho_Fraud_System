from datetime import timedelta

from jicho.config import EngineConfig
from jicho.realtime import ACCOUNT_LOCAL_RULE_IDS, RealtimeScorer

CFG = EngineConfig()


def _txn(account_id, ttype, amount, ts, **kwargs):
    base = {
        "transaction_id": f"T-{account_id}-{ts.isoformat()}", "account_id": account_id,
        "transaction_type": ttype, "amount": amount, "timestamp": ts, "channel": "mobile_money",
        "counterparty_id": None, "agent_id": None, "initiated_by_staff": False, "event_type": "transaction",
    }
    base.update(kwargs)
    return base


def test_realtime_scorer_catches_sim_swap_cashout_incrementally(base_time):
    scorer = RealtimeScorer(CFG)
    swap = _txn("A1", "withdrawal", 0, base_time, event_type="sim_swap")
    scorer.score_transaction(swap)

    withdrawal = _txn("A1", "withdrawal", 600_000, base_time + timedelta(hours=1))
    alerts = scorer.score_transaction(withdrawal)
    assert any(a.rule_id == "R1" for a in alerts)


def test_realtime_scorer_catches_velocity_spike_incrementally(base_time):
    scorer = RealtimeScorer(CFG)
    alerts = []
    for i in range(5):
        txn = _txn("A1", "withdrawal", 10_000, base_time + timedelta(minutes=i * 5))
        alerts.extend(scorer.score_transaction(txn))
    assert any(a.rule_id == "R2" for a in alerts)


def test_realtime_scorer_prunes_old_transactions(base_time):
    scorer = RealtimeScorer(CFG, retention=timedelta(minutes=10))
    scorer.score_transaction(_txn("A1", "withdrawal", 10_000, base_time))
    assert scorer.buffer_size("A1") == 1
    # a transaction well past the retention window should prune the old one
    scorer.score_transaction(_txn("A1", "withdrawal", 10_000, base_time + timedelta(hours=1)))
    assert scorer.buffer_size("A1") == 1


def test_realtime_scorer_only_returns_alerts_for_current_transaction(base_time):
    scorer = RealtimeScorer(CFG)
    swap = _txn("A1", "withdrawal", 0, base_time, event_type="sim_swap")
    result = scorer.score_transaction(swap)
    # scoring the sim_swap event itself shouldn't produce an alert about a
    # withdrawal that hasn't happened yet
    assert result == []


def test_account_local_rule_classification_excludes_cross_entity_rules():
    """Rules keyed by agent_id, merchant_id, a cross-account chain, or a
    portfolio-wide window must NOT be claimed as real-time-safe — this is
    the exact distinction that would silently under-detect if gotten wrong.
    """
    assert "R5" not in ACCOUNT_LOCAL_RULE_IDS  # agent_id-keyed
    assert "R7" not in ACCOUNT_LOCAL_RULE_IDS  # cross-account chain
    assert "R9" not in ACCOUNT_LOCAL_RULE_IDS  # portfolio-wide
    assert "R11" not in ACCOUNT_LOCAL_RULE_IDS  # merchant_id-keyed
    assert "R14" not in ACCOUNT_LOCAL_RULE_IDS  # merchant_id-keyed


def test_account_local_rule_classification_includes_caveated_card_keyed_rules():
    """R12 and R13 group by card_id, not account_id, but are deliberately
    included as real-time-eligible with a documented caveat (correct for the
    common case where a card belongs to one account). Pins this so it can't
    silently drift the other way either — docs/RULE_CATALOG.md previously
    disagreed with this exact classification for R13 until corrected.
    """
    assert "R12" in ACCOUNT_LOCAL_RULE_IDS
    assert "R13" in ACCOUNT_LOCAL_RULE_IDS


def test_realtime_scorer_isolates_accounts(base_time):
    scorer = RealtimeScorer(CFG)
    scorer.score_transaction(_txn("A1", "withdrawal", 10_000, base_time))
    scorer.score_transaction(_txn("A2", "withdrawal", 10_000, base_time))
    assert scorer.buffer_size("A1") == 1
    assert scorer.buffer_size("A2") == 1
