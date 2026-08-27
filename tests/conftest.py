from datetime import datetime

import pandas as pd
import pytest


def make_df(rows: list[dict]) -> pd.DataFrame:
    """Builds a minimal valid transactions DataFrame from row dicts, filling defaults."""
    defaults = {
        "counterparty_id": None, "agent_id": None,
        "initiated_by_staff": False, "event_type": "transaction",
    }
    full_rows = []
    for i, r in enumerate(rows):
        row = {**defaults, "transaction_id": f"T{i:04d}", **r}
        full_rows.append(row)
    df = pd.DataFrame(full_rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


@pytest.fixture
def base_time():
    return datetime(2026, 1, 1, 9, 0, 0)
