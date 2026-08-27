from datetime import timedelta

from jicho.config import EngineConfig
from jicho.rules.known_patterns import (
    AgentAnomalyRule,
    DormantAccountSweepRule,
    LoanDisbursementCashoutRule,
    MuleFaninRule,
    OffHoursInsiderRule,
    RapidLayeringRule,
    SimSwapCashoutRule,
    StructuringRule,
    SynchronizedWithdrawalSpikeRule,
    VelocitySpikeRule,
)
from tests.conftest import make_df

CFG = EngineConfig()


def test_sim_swap_cashout_fires_on_planted_pattern(base_time):
    df = make_df([
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 0,
         "timestamp": base_time, "channel": "mobile_money", "event_type": "sim_swap"},
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 600_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "mobile_money"},
    ])
    alerts = SimSwapCashoutRule().evaluate(df, CFG)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "R1"


def test_sim_swap_cashout_silent_without_swap(base_time):
    df = make_df([
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 600_000,
         "timestamp": base_time, "channel": "mobile_money"},
    ])
    assert SimSwapCashoutRule().evaluate(df, CFG) == []


def test_velocity_spike_fires_on_burst(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 10_000,
         "timestamp": base_time + timedelta(minutes=i * 5), "channel": "mobile_money"}
        for i in range(5)
    ]
    alerts = VelocitySpikeRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_velocity_spike_silent_on_normal_activity(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 10_000,
         "timestamp": base_time + timedelta(hours=i), "channel": "mobile_money"}
        for i in range(5)
    ]
    assert VelocitySpikeRule().evaluate(make_df(rows), CFG) == []


def test_structuring_fires_on_repeated_near_threshold_deposits(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "deposit", "amount": 9_500_000,
         "timestamp": base_time + timedelta(hours=i * 4), "channel": "bank_transfer"}
        for i in range(3)
    ]
    alerts = StructuringRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_mule_fanin_requires_both_fanin_and_sweepout(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_in", "amount": 100_000,
         "timestamp": base_time + timedelta(minutes=i * 10),
         "channel": "mobile_money", "counterparty_id": f"S{i}"}
        for i in range(5)
    ]
    rows.append({"account_id": "A1", "transaction_type": "transfer_out", "amount": 480_000,
                 "timestamp": base_time + timedelta(hours=1), "channel": "mobile_money", "counterparty_id": "OUT"})
    alerts = MuleFaninRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_mule_fanin_silent_without_sweepout(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_in", "amount": 100_000,
         "timestamp": base_time + timedelta(minutes=i * 10),
         "channel": "mobile_money", "counterparty_id": f"S{i}"}
        for i in range(5)
    ]
    assert MuleFaninRule().evaluate(make_df(rows), CFG) == []


def test_agent_anomaly_fires_on_high_cashout_ratio(base_time):
    rows = [
        {"account_id": "C1", "transaction_type": "cash_in", "amount": 100_000,
         "timestamp": base_time, "channel": "agent", "agent_id": "AG1"},
        {"account_id": "C2", "transaction_type": "cash_out", "amount": 500_000,
         "timestamp": base_time + timedelta(minutes=10), "channel": "agent", "agent_id": "AG1"},
    ]
    alerts = AgentAnomalyRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_offhours_insider_requires_staff_flag(base_time):
    late_night = base_time.replace(hour=2)
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 3_000_000,
         "timestamp": late_night, "channel": "bank_transfer", "initiated_by_staff": True},
    ]
    alerts = OffHoursInsiderRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1

    rows_no_staff = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 3_000_000,
         "timestamp": late_night, "channel": "bank_transfer", "initiated_by_staff": False},
    ]
    assert OffHoursInsiderRule().evaluate(make_df(rows_no_staff), CFG) == []


def test_rapid_layering_fires_on_hop_chain(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 1_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A2"},
        {"account_id": "A2", "transaction_type": "transfer_out", "amount": 950_000,
         "timestamp": base_time + timedelta(minutes=10), "channel": "bank_transfer", "counterparty_id": "A3"},
        {"account_id": "A3", "transaction_type": "transfer_out", "amount": 900_000,
         "timestamp": base_time + timedelta(minutes=20), "channel": "bank_transfer", "counterparty_id": "A4"},
    ]
    alerts = RapidLayeringRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1
    assert alerts[0].evidence["hop_count"] == 3


def test_dormant_account_sweep_fires_on_first_activity_drain(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_in", "amount": 2_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "VICTIM"},
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 1_900_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "bank_transfer", "counterparty_id": "NEXT"},
    ]
    alerts = DormantAccountSweepRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_synchronized_withdrawal_spike_needs_distinct_accounts(base_time):
    rows = [
        {"account_id": f"A{i}", "transaction_type": "withdrawal", "amount": 50_000,
         "timestamp": base_time + timedelta(minutes=i), "channel": "mobile_money"}
        for i in range(8)
    ]
    alerts = SynchronizedWithdrawalSpikeRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1
    assert alerts[0].account_id == "PORTFOLIO"


def test_loan_disbursement_cashout_fires_on_immediate_drain(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "loan_disbursement", "amount": 500_000,
         "timestamp": base_time, "channel": "mobile_money"},
        {"account_id": "A1", "transaction_type": "cash_out", "amount": 480_000,
         "timestamp": base_time + timedelta(minutes=30), "channel": "agent"},
    ]
    alerts = LoanDisbursementCashoutRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_emv_fallback_abuse_fires_on_high_ratio(base_time):
    rows = [
        {"account_id": f"A{i}", "transaction_type": "pos_purchase", "amount": 45_000,
         "timestamp": base_time + timedelta(minutes=i), "channel": "pos",
         "entry_mode": "swipe" if i < 6 else "chip", "merchant_id": "M1", "card_id": f"C{i}"}
        for i in range(8)
    ]
    from jicho.rules.known_patterns import EmvFallbackAbuseRule
    alerts = EmvFallbackAbuseRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1
    assert alerts[0].account_id == "M1"


def test_emv_fallback_silent_below_threshold(base_time):
    rows = [
        {"account_id": f"A{i}", "transaction_type": "pos_purchase", "amount": 45_000,
         "timestamp": base_time + timedelta(minutes=i), "channel": "pos",
         "entry_mode": "chip", "merchant_id": "M1", "card_id": f"C{i}"}
        for i in range(8)
    ]
    from jicho.rules.known_patterns import EmvFallbackAbuseRule
    assert EmvFallbackAbuseRule().evaluate(make_df(rows), CFG) == []


def test_card_testing_fires_on_burst_of_small_transactions(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "pos_purchase", "amount": 5_000,
         "timestamp": base_time + timedelta(minutes=i * 3), "channel": "pos",
         "entry_mode": "card_not_present", "merchant_id": f"M{i}", "card_id": "CARD1"}
        for i in range(4)
    ]
    from jicho.rules.known_patterns import CardTestingRule
    alerts = CardTestingRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1
    assert alerts[0].account_id == "CARD1"


def test_cross_border_card_velocity_fires_on_impossible_travel(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "pos_purchase", "amount": 300_000,
         "timestamp": base_time, "channel": "pos", "entry_mode": "chip",
         "merchant_id": "M1", "card_id": "CARD1", "terminal_country": "TZ"},
        {"account_id": "A2", "transaction_type": "pos_purchase", "amount": 280_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "pos", "entry_mode": "chip",
         "merchant_id": "M2", "card_id": "CARD1", "terminal_country": "KE"},
    ]
    from jicho.rules.known_patterns import CrossBorderCardVelocityRule
    alerts = CrossBorderCardVelocityRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_cross_border_card_velocity_silent_within_same_country(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "pos_purchase", "amount": 300_000,
         "timestamp": base_time, "channel": "pos", "entry_mode": "chip",
         "merchant_id": "M1", "card_id": "CARD1", "terminal_country": "TZ"},
        {"account_id": "A2", "transaction_type": "pos_purchase", "amount": 280_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "pos", "entry_mode": "chip",
         "merchant_id": "M2", "card_id": "CARD1", "terminal_country": "TZ"},
    ]
    from jicho.rules.known_patterns import CrossBorderCardVelocityRule
    assert CrossBorderCardVelocityRule().evaluate(make_df(rows), CFG) == []


def test_merchant_refund_anomaly_fires_on_high_refund_ratio(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "pos_purchase", "amount": 200_000,
         "timestamp": base_time, "channel": "pos", "merchant_id": "M1"},
        {"account_id": "A1", "transaction_type": "refund", "amount": 190_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "pos", "merchant_id": "M1"},
    ]
    from jicho.rules.known_patterns import MerchantRefundAnomalyRule
    alerts = MerchantRefundAnomalyRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1
    assert alerts[0].account_id == "M1"


def test_offline_authorization_abuse_fires_on_repeated_offline_auths(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "pos_purchase", "amount": 400_000,
         "timestamp": base_time + timedelta(minutes=i * 20), "channel": "pos",
         "auth_mode": "offline"}
        for i in range(3)
    ]
    from jicho.rules.known_patterns import OfflineAuthorizationAbuseRule
    alerts = OfflineAuthorizationAbuseRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_offline_authorization_silent_without_auth_mode_column(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "pos_purchase", "amount": 400_000,
         "timestamp": base_time, "channel": "pos"},
    ]
    from jicho.rules.known_patterns import OfflineAuthorizationAbuseRule
    assert OfflineAuthorizationAbuseRule().evaluate(make_df(rows), CFG) == []


def test_bec_payment_redirection_fires_after_beneficiary_change(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 0,
         "timestamp": base_time, "channel": "bank_transfer", "event_type": "beneficiary_change"},
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 2_000_000,
         "timestamp": base_time + timedelta(hours=2), "channel": "bank_transfer"},
    ]
    from jicho.rules.known_patterns import BecPaymentRedirectionRule
    alerts = BecPaymentRedirectionRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_bec_silent_without_beneficiary_change(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 2_000_000,
         "timestamp": base_time, "channel": "bank_transfer"},
    ]
    from jicho.rules.known_patterns import BecPaymentRedirectionRule
    assert BecPaymentRedirectionRule().evaluate(make_df(rows), CFG) == []


def test_credential_phishing_ato_fires_after_suspicious_login(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 0,
         "timestamp": base_time, "channel": "mobile_money", "event_type": "suspicious_login"},
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 600_000,
         "timestamp": base_time + timedelta(minutes=10), "channel": "mobile_money"},
    ]
    from jicho.rules.known_patterns import CredentialPhishingAtoRule
    alerts = CredentialPhishingAtoRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_atm_multi_terminal_anomaly_fires_on_impossible_travel(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 200_000,
         "timestamp": base_time, "channel": "atm", "terminal_id": "ATM01"},
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 200_000,
         "timestamp": base_time + timedelta(minutes=10), "channel": "atm", "terminal_id": "ATM99"},
    ]
    from jicho.rules.known_patterns import AtmMultiTerminalAnomalyRule
    alerts = AtmMultiTerminalAnomalyRule().evaluate(make_df(rows), CFG)
    assert len(alerts) == 1


def test_atm_multi_terminal_silent_at_same_terminal(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 200_000,
         "timestamp": base_time, "channel": "atm", "terminal_id": "ATM01"},
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 200_000,
         "timestamp": base_time + timedelta(minutes=10), "channel": "atm", "terminal_id": "ATM01"},
    ]
    from jicho.rules.known_patterns import AtmMultiTerminalAnomalyRule
    assert AtmMultiTerminalAnomalyRule().evaluate(make_df(rows), CFG) == []
