"""
Data models and input validation.

Rationale: a fraud engine's output (Alert) may end up in a bank's case
management system or a regulator's hands, so its shape is a contract —
defined once here, not scattered as dict literals across rule files.
Input validation similarly ensures a malformed upstream data feed fails
loudly and specifically, rather than producing silently wrong alerts
(or worse, silently missing them).
"""

from dataclasses import dataclass, field
from typing import Any

import pandas as pd

from jicho.exceptions import TransactionSchemaError

REQUIRED_COLUMNS = {
    "transaction_id": "object",
    "account_id": "object",
    "transaction_type": "object",
    "amount": "number",
    "timestamp": "datetime",
    "channel": "object",
}

VALID_TRANSACTION_TYPES = {
    "deposit", "withdrawal", "transfer_in", "transfer_out",
    "cash_in", "cash_out", "sim_swap", "loan_disbursement",
    "pos_purchase", "refund",
}

VALID_ENTRY_MODES = {"chip", "swipe", "contactless", "manual", "card_not_present"}

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    account_id: str
    transaction_id: str
    timestamp: str
    severity: str
    score: int
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{self.severity}'; must be one of {VALID_SEVERITIES}")
        if not (0 <= self.score <= 100):
            raise ValueError(f"Score must be 0-100, got {self.score}")


def validate_transactions(df: pd.DataFrame) -> pd.DataFrame:
    """Validates a transactions DataFrame against the engine's required schema.

    Returns the DataFrame with `timestamp` coerced to datetime if needed.

    Raises:
        TransactionSchemaError: on missing columns, unparseable timestamps,
            unknown transaction types, or non-positive amounts.
    """
    missing = set(REQUIRED_COLUMNS) - set(df.columns)
    if missing:
        raise TransactionSchemaError(f"Missing required columns: {sorted(missing)}")

    if df["transaction_id"].duplicated().any():
        dupes = df.loc[df["transaction_id"].duplicated(), "transaction_id"].tolist()[:5]
        raise TransactionSchemaError(f"Duplicate transaction_id values found (showing up to 5): {dupes}")

    if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
        try:
            df = df.copy()
            df["timestamp"] = pd.to_datetime(df["timestamp"])
        except Exception as e:
            raise TransactionSchemaError(f"Could not parse 'timestamp' column as datetime: {e}") from e

    unknown_types = set(df["transaction_type"].dropna().unique()) - VALID_TRANSACTION_TYPES
    if unknown_types:
        raise TransactionSchemaError(
            f"Unknown transaction_type values: {sorted(unknown_types)}. "
            f"Valid types: {sorted(VALID_TRANSACTION_TYPES)}"
        )

    if (df["amount"] < 0).any():
        raise TransactionSchemaError("Negative amounts found — amount must be >= 0")

    if "initiated_by_staff" in df.columns:
        df = df.copy()
        df["initiated_by_staff"] = df["initiated_by_staff"].fillna(False).astype(bool)

    if "entry_mode" in df.columns:
        unknown_modes = set(df["entry_mode"].dropna().unique()) - VALID_ENTRY_MODES
        if unknown_modes:
            raise TransactionSchemaError(
                f"Unknown entry_mode values: {sorted(unknown_modes)}. Valid modes: {sorted(VALID_ENTRY_MODES)}"
            )

    # device_id, card_id, merchant_id, terminal_country are optional but,
    # if present, power hunting.shared_attribute_accounts and the POS rules —
    # no format validation beyond being plain identifier columns.
    return df
