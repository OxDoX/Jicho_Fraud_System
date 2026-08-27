from datetime import timedelta

from jicho.hunting import FraudHunter
from tests.conftest import make_df


def test_search_filters_by_account_and_type(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 100_000,
         "timestamp": base_time, "channel": "mobile_money"},
        {"account_id": "A1", "transaction_type": "deposit", "amount": 50_000,
         "timestamp": base_time, "channel": "mobile_money"},
        {"account_id": "A2", "transaction_type": "withdrawal", "amount": 100_000,
         "timestamp": base_time, "channel": "mobile_money"},
    ]
    hunter = FraudHunter(make_df(rows))
    result = hunter.search(account_id="A1", transaction_type="withdrawal")
    assert len(result) == 1
    assert result.iloc[0]["account_id"] == "A1"


def test_search_filters_by_amount_range(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": amt,
         "timestamp": base_time, "channel": "mobile_money"}
        for amt in [10_000, 500_000, 2_000_000]
    ]
    hunter = FraudHunter(make_df(rows))
    result = hunter.search(min_amount=100_000, max_amount=1_000_000)
    assert len(result) == 1
    assert result.iloc[0]["amount"] == 500_000


def test_account_network_finds_direct_and_second_hop(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 1_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A2"},
        {"account_id": "A2", "transaction_type": "transfer_out", "amount": 900_000,
         "timestamp": base_time + timedelta(minutes=5), "channel": "bank_transfer", "counterparty_id": "A3"},
        {"account_id": "A9", "transaction_type": "transfer_out", "amount": 100_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A8"},  # unrelated
    ]
    hunter = FraudHunter(make_df(rows))
    network = hunter.account_network("A1", max_hops=2)
    account_ids = {n.account_id for n in network}
    assert account_ids == {"A1", "A2", "A3"}
    assert "A9" not in account_ids and "A8" not in account_ids


def test_account_network_respects_max_hops(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 1_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A2"},
        {"account_id": "A2", "transaction_type": "transfer_out", "amount": 900_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A3"},
    ]
    hunter = FraudHunter(make_df(rows))
    network = hunter.account_network("A1", max_hops=1)
    account_ids = {n.account_id for n in network}
    assert account_ids == {"A1", "A2"}  # A3 is 2 hops away, excluded


def test_shared_attribute_accounts_finds_device_reuse(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 100_000,
         "timestamp": base_time, "channel": "mobile_money", "device_id": "DEV1"},
        {"account_id": "A2", "transaction_type": "withdrawal", "amount": 100_000,
         "timestamp": base_time, "channel": "mobile_money", "device_id": "DEV1"},
        {"account_id": "A3", "transaction_type": "withdrawal", "amount": 100_000,
         "timestamp": base_time, "channel": "mobile_money", "device_id": "DEV2"},
    ]
    hunter = FraudHunter(make_df(rows))
    result = hunter.shared_attribute_accounts("A1", "device_id")
    assert result == ["A2"]


def test_shared_attribute_accounts_empty_without_column(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 100_000,
         "timestamp": base_time, "channel": "mobile_money"},
    ]
    hunter = FraudHunter(make_df(rows))
    assert hunter.shared_attribute_accounts("A1", "device_id") == []


def test_build_profile_summarizes_account_activity(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "deposit", "amount": 500_000,
         "timestamp": base_time, "channel": "mobile_money", "counterparty_id": "S1"},
        {"account_id": "A1", "transaction_type": "withdrawal", "amount": 200_000,
         "timestamp": base_time + timedelta(hours=1), "channel": "mobile_money"},
    ]
    hunter = FraudHunter(make_df(rows))
    profile = hunter.build_profile("A1")
    assert profile.transaction_count == 2
    assert profile.total_inflow == 500_000
    assert profile.total_outflow == 200_000


def test_find_similar_accounts_ranks_closest_first(base_time):
    rows = []
    # Reference account: 2 txns, moderate volume
    rows.append({"account_id": "REF", "transaction_type": "deposit", "amount": 500_000,
                 "timestamp": base_time, "channel": "mobile_money"})
    rows.append({"account_id": "REF", "transaction_type": "withdrawal", "amount": 400_000,
                 "timestamp": base_time, "channel": "mobile_money"})
    # Similar account: same shape
    rows.append({"account_id": "SIMILAR", "transaction_type": "deposit", "amount": 510_000,
                 "timestamp": base_time, "channel": "mobile_money"})
    rows.append({"account_id": "SIMILAR", "transaction_type": "withdrawal", "amount": 390_000,
                 "timestamp": base_time, "channel": "mobile_money"})
    # Very different account: high volume, many txns
    for i in range(20):
        rows.append({"account_id": "DIFFERENT", "transaction_type": "deposit", "amount": 50_000_000,
                     "timestamp": base_time + timedelta(minutes=i), "channel": "bank_transfer"})

    hunter = FraudHunter(make_df(rows))
    ranked = hunter.find_similar_accounts("REF", top_n=2)
    assert ranked[0][0] == "SIMILAR"
    assert ranked[0][1] < ranked[1][1]
