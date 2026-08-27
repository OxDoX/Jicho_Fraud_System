"""
Fraud hunting: proactive, analyst-driven investigation over transaction data,
as distinct from the reactive rules engine (which only surfaces what a rule
was written to catch). This is where an investigator starts from a lead —
a suspicious account, a shared device, a hunch about a ring — rather than
waiting for an alert.

Every method here is deterministic and explainable by design, consistent
with the rest of this codebase: no black-box scoring, just transparent
graph traversal and named-feature comparison that an investigator (or a
bank examiner reviewing the tool) can follow step by step.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime

import pandas as pd

from jicho.logging_config import get_logger, mask_account_id

logger = get_logger(__name__)


@dataclass
class AccountProfile:
    account_id: str
    transaction_count: int
    total_inflow: float
    total_outflow: float
    distinct_counterparties: int
    channels_used: list[str]
    first_seen: str
    last_seen: str
    shared_agents: list[str] = field(default_factory=list)
    shared_devices: list[str] = field(default_factory=list)


@dataclass
class NetworkNode:
    account_id: str
    hop_distance: int
    connected_via: list[str]  # transaction_ids linking this account to the network


class FraudHunter:
    """Proactive hunting operations over a validated transactions DataFrame."""

    def __init__(self, df: pd.DataFrame):
        self.df = df

    def search(
        self,
        account_id: str | None = None,
        counterparty_id: str | None = None,
        channel: str | None = None,
        transaction_type: str | None = None,
        agent_id: str | None = None,
        device_id: str | None = None,
        card_id: str | None = None,
        merchant_id: str | None = None,
        min_amount: float | None = None,
        max_amount: float | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> pd.DataFrame:
        """Ad-hoc filtered search — the hunting equivalent of a SIEM query.

        All filters are AND-combined. Returns matching rows, sorted by time.
        """
        result = self.df
        if account_id is not None:
            result = result[result["account_id"] == account_id]
        if counterparty_id is not None:
            result = result[result["counterparty_id"] == counterparty_id]
        if channel is not None:
            result = result[result["channel"] == channel]
        if transaction_type is not None:
            result = result[result["transaction_type"] == transaction_type]
        if agent_id is not None and "agent_id" in result.columns:
            result = result[result["agent_id"] == agent_id]
        if device_id is not None and "device_id" in result.columns:
            result = result[result["device_id"] == device_id]
        if card_id is not None and "card_id" in result.columns:
            result = result[result["card_id"] == card_id]
        if merchant_id is not None and "merchant_id" in result.columns:
            result = result[result["merchant_id"] == merchant_id]
        if min_amount is not None:
            result = result[result["amount"] >= min_amount]
        if max_amount is not None:
            result = result[result["amount"] <= max_amount]
        if start_time is not None:
            result = result[result["timestamp"] >= start_time]
        if end_time is not None:
            result = result[result["timestamp"] <= end_time]

        logger.info(f"Hunt search returned {len(result)} matching transactions")
        return result.sort_values("timestamp")

    def account_network(self, seed_account_id: str, max_hops: int = 2) -> list[NetworkNode]:
        """Breadth-first traversal of the counterparty graph from a seed account.

        This is link analysis: starting from one suspicious account, find every
        account it's transacted with, and every account THOSE accounts have
        transacted with, out to max_hops. Fraud rings and layering chains show
        up as unusually dense or unusually long networks radiating from a seed
        — a pattern no single-account rule can see, but a human investigator
        can spot immediately once it's laid out.
        """
        if "counterparty_id" not in self.df.columns:
            return []

        visited: dict[str, NetworkNode] = {
            seed_account_id: NetworkNode(seed_account_id, 0, [])
        }
        queue = deque([(seed_account_id, 0)])

        while queue:
            current, hop = queue.popleft()
            if hop >= max_hops:
                continue

            outgoing = self.df[
                (self.df["account_id"] == current) & (self.df["counterparty_id"].notna())
            ]
            incoming = self.df[
                (self.df["counterparty_id"] == current) & (self.df["account_id"].notna())
            ]

            for _, row in outgoing.iterrows():
                neighbor = row["counterparty_id"]
                self._add_or_update_neighbor(visited, queue, neighbor, hop, row["transaction_id"])

            for _, row in incoming.iterrows():
                neighbor = row["account_id"]
                self._add_or_update_neighbor(visited, queue, neighbor, hop, row["transaction_id"])

        logger.info(
            f"Network traversal from {mask_account_id(seed_account_id)}: "
            f"{len(visited)} accounts within {max_hops} hops"
        )
        return sorted(visited.values(), key=lambda n: (n.hop_distance, n.account_id))

    @staticmethod
    def _add_or_update_neighbor(visited, queue, neighbor, hop, txn_id):
        if neighbor not in visited:
            visited[neighbor] = NetworkNode(neighbor, hop + 1, [txn_id])
            queue.append((neighbor, hop + 1))
        elif txn_id not in visited[neighbor].connected_via:
            visited[neighbor].connected_via.append(txn_id)

    def shared_attribute_accounts(self, account_id: str, attribute: str) -> list[str]:
        """Finds other accounts sharing a device_id or agent_id with the given account.

        Device/agent reuse across supposedly unrelated accounts is one of the
        strongest fraud-ring indicators available — legitimate customers don't
        normally share a phone or transact through the same agent till as
        strangers. `attribute` must be 'device_id' or 'agent_id'.
        """
        if attribute not in ("device_id", "agent_id") or attribute not in self.df.columns:
            return []

        account_values = self.df.loc[self.df["account_id"] == account_id, attribute].dropna().unique()
        if len(account_values) == 0:
            return []

        related = self.df[
            (self.df[attribute].isin(account_values)) & (self.df["account_id"] != account_id)
        ]
        result = sorted(related["account_id"].unique().tolist())
        logger.info(
            f"{mask_account_id(account_id)} shares {attribute} with {len(result)} other account(s)"
        )
        return result

    def build_profile(self, account_id: str) -> AccountProfile:
        """Builds a behavioral summary for one account — the basis for similarity hunting."""
        acct_df = self.df[self.df["account_id"] == account_id]
        inflow_types = {"deposit", "transfer_in", "cash_in", "loan_disbursement"}
        outflow_types = {"withdrawal", "transfer_out", "cash_out"}

        has_counterparty = "counterparty_id" in acct_df.columns
        return AccountProfile(
            account_id=account_id,
            transaction_count=len(acct_df),
            total_inflow=float(acct_df[acct_df["transaction_type"].isin(inflow_types)]["amount"].sum()),
            total_outflow=float(acct_df[acct_df["transaction_type"].isin(outflow_types)]["amount"].sum()),
            distinct_counterparties=int(acct_df["counterparty_id"].nunique()) if has_counterparty else 0,
            channels_used=sorted(acct_df["channel"].dropna().unique().tolist()),
            first_seen=str(acct_df["timestamp"].min()) if len(acct_df) else "",
            last_seen=str(acct_df["timestamp"].max()) if len(acct_df) else "",
            shared_agents=self.shared_attribute_accounts(account_id, "agent_id"),
            shared_devices=self.shared_attribute_accounts(account_id, "device_id"),
        )

    def find_similar_accounts(self, reference_account_id: str, top_n: int = 5) -> list[tuple[str, float]]:
        """Ranks other accounts by behavioral similarity to a reference (e.g. a
        confirmed fraud case), using explainable distance over named features
        (transaction count, inflow/outflow volume, counterparty spread) —
        deliberately NOT a black-box embedding, so the ranking can be explained
        to an investigator or auditor in plain terms.

        Returns a list of (account_id, distance) sorted ascending (closest first).
        """
        ref = self.build_profile(reference_account_id)
        ref_vector = [ref.transaction_count, ref.total_inflow, ref.total_outflow, ref.distinct_counterparties]

        candidates = [a for a in self.df["account_id"].unique() if a != reference_account_id]
        scored = []
        for acct in candidates:
            p = self.build_profile(acct)
            vec = [p.transaction_count, p.total_inflow, p.total_outflow, p.distinct_counterparties]
            # Normalized Euclidean distance over the four named features above.
            distance = sum(
                ((a - b) / (max(abs(a), abs(b), 1))) ** 2 for a, b in zip(ref_vector, vec)
            ) ** 0.5
            scored.append((acct, distance))

        scored.sort(key=lambda x: x[1])
        return scored[:top_n]
