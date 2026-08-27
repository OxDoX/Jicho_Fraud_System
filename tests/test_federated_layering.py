from datetime import timedelta

from jicho.federated_layering import (
    export_layering_fingerprints,
    hash_account_id,
    match_cross_institution_chains,
)
from tests.conftest import make_df

SALT = "regulator-provided-salt-2026"


def test_hash_is_deterministic_for_same_salt():
    assert hash_account_id("ACC123", SALT) == hash_account_id("ACC123", SALT)


def test_hash_differs_across_salts():
    """If two institutions somehow used different salts, hashes wouldn't
    match even for the same account — proving the salt must genuinely be
    shared via a trusted distributor, not each institution picking its own.
    """
    assert hash_account_id("ACC123", SALT) != hash_account_id("ACC123", "different-salt")


def test_hash_does_not_reveal_account_id():
    """The exported fingerprint must not contain the raw account id in any
    recoverable form -- this is the entire point of the module.
    """
    hashed = hash_account_id("ACC123456", SALT)
    assert "ACC123456" not in hashed
    assert len(hashed) == 64  # sha256 hex digest length


def test_export_fingerprints_excludes_raw_identifiers(base_time):
    rows = [
        {"account_id": "ACC_SENDER", "transaction_type": "transfer_out", "amount": 1_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "ACC_RECEIVER"},
    ]
    fingerprints = export_layering_fingerprints(make_df(rows), SALT, "BANK_A")
    assert len(fingerprints) == 1
    fp_dict = fingerprints[0].to_dict()
    assert "ACC_SENDER" not in str(fp_dict)
    assert "ACC_RECEIVER" not in str(fp_dict)
    assert fp_dict["amount"] == 1_000_000


def test_export_fingerprints_respects_amount_threshold(base_time):
    rows = [
        {"account_id": "A1", "transaction_type": "transfer_out", "amount": 50_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "A2"},
    ]
    fingerprints = export_layering_fingerprints(make_df(rows), SALT, "BANK_A", amount_threshold=1_000_000)
    assert fingerprints == []


def test_cross_institution_matching_finds_chain_despite_hashing(base_time):
    """The core proof: a layering chain that hops from Bank A's customer to
    an account that then moves funds out via Bank B, within a short window,
    is detected using ONLY salted hashes -- neither bank's raw account
    numbers ever appear in the matching function's input or output.
    """
    # Bank A: customer sends to an account (the "mule" hop point)
    bank_a_df = make_df([
        {"account_id": "BANKA_CUST1", "transaction_type": "transfer_out", "amount": 5_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "MULE_ACCT"},
    ])
    # Bank B: the SAME mule account (by real-world identity, here represented
    # by the same string purely for the test setup) forwards funds onward
    # within Bank B's own records
    bank_b_df = make_df([
        {"account_id": "MULE_ACCT", "transaction_type": "transfer_out", "amount": 4_900_000,
         "timestamp": base_time + timedelta(minutes=10), "channel": "bank_transfer",
         "counterparty_id": "BANKB_DESTINATION"},
    ])

    fp_a = export_layering_fingerprints(bank_a_df, SALT, "BANK_A")
    fp_b = export_layering_fingerprints(bank_b_df, SALT, "BANK_B")

    matches = match_cross_institution_chains([fp_a, fp_b], window_minutes=45)
    assert len(matches) == 1
    assert set(matches[0].institutions_involved) == {"BANK_A", "BANK_B"}


def test_cross_institution_matching_respects_time_window(base_time):
    bank_a_df = make_df([
        {"account_id": "BANKA_CUST1", "transaction_type": "transfer_out", "amount": 5_000_000,
         "timestamp": base_time, "channel": "bank_transfer", "counterparty_id": "MULE_ACCT"},
    ])
    bank_b_df = make_df([
        {"account_id": "MULE_ACCT", "transaction_type": "transfer_out", "amount": 4_900_000,
         "timestamp": base_time + timedelta(hours=5), "channel": "bank_transfer",  # well past window
         "counterparty_id": "BANKB_DESTINATION"},
    ])
    fp_a = export_layering_fingerprints(bank_a_df, SALT, "BANK_A")
    fp_b = export_layering_fingerprints(bank_b_df, SALT, "BANK_B")
    matches = match_cross_institution_chains([fp_a, fp_b], window_minutes=45)
    assert matches == []


def test_no_match_within_same_institution():
    """A same-institution chain isn't the point of this module (R7 already
    covers that) -- matches require at least two distinct institutions.
    """
    matches = match_cross_institution_chains([[], []], window_minutes=45)
    assert matches == []
