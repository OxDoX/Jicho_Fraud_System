"""
Connects detection to hunting: when a rule fires, automatically run the
hunting operations an investigator would think to run next, so the alert
arrives with leads attached instead of a dead end.

Each rule has a tailored strategy — a layering alert (R7) should hunt
further hops than a structuring alert (R3), an agent-anomaly alert (R5)
should hunt the agent itself, not just the flagged account. Falls back to
a sensible default set for any rule without a specific strategy, including
rules added later via the AI-drafted rule workflow.
"""

from dataclasses import dataclass, field
from typing import Any

from jicho.hunting import FraudHunter
from jicho.models import Alert


@dataclass
class HuntSuggestion:
    hunt_type: str
    rationale: str
    results: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"hunt_type": self.hunt_type, "rationale": self.rationale, "results": self.results}


def _network_hunt(
    hunter: FraudHunter, account_id: str, max_hops: int, min_size_to_report: int = 2
) -> HuntSuggestion | None:
    network = hunter.account_network(account_id, max_hops=max_hops)
    if len(network) < min_size_to_report:
        return None
    return HuntSuggestion(
        hunt_type="account_network",
        rationale=(
            f"This account connects to {len(network)-1} other account(s) within {max_hops} hops "
            "via counterparty links — check whether they form a ring before closing this alert."
        ),
        results=[{"account_id": n.account_id, "hop": n.hop_distance} for n in network if n.account_id != account_id],
    )


def _shared_attribute_hunt(hunter: FraudHunter, account_id: str, attribute: str, label: str) -> HuntSuggestion | None:
    shared = hunter.shared_attribute_accounts(account_id, attribute)
    if not shared:
        return None
    return HuntSuggestion(
        hunt_type=f"shared_{attribute}",
        rationale=(
            f"{len(shared)} other account(s) share a {label} with this one — legitimate customers "
            f"don't normally share a {label} with strangers, this is a strong ring indicator."
        ),
        results=shared,
    )


def _similar_accounts_hunt(hunter: FraudHunter, account_id: str, top_n: int = 3) -> HuntSuggestion | None:
    similar = hunter.find_similar_accounts(account_id, top_n=top_n)
    if not similar:
        return None
    return HuntSuggestion(
        hunt_type="similar_accounts",
        rationale=(
            "Accounts with closely matching transaction behavior — worth checking whether this is "
            "a repeated pattern from the same operator rather than an isolated incident."
        ),
        results=[{"account_id": a, "distance": round(d, 3)} for a, d in similar],
    )


def _agent_till_hunt(hunter: FraudHunter, agent_id: str) -> HuntSuggestion | None:
    txns = hunter.search(agent_id=agent_id)
    accounts = sorted(txns["account_id"].unique().tolist()) if len(txns) else []
    if len(accounts) < 2:
        return None
    return HuntSuggestion(
        hunt_type="agent_till_activity",
        rationale=(
            f"{len(accounts)} distinct accounts transacted through this agent till — pull the full "
            "till history, not just this one flagged transaction, before deciding whether the agent "
            "itself is compromised or complicit."
        ),
        results=accounts,
    )


def _entity_activity_hunt(hunter: FraudHunter, entity_id: str, entity_type: str) -> HuntSuggestion | None:
    """For POS alerts, the alerted 'account_id' is actually a card_id or
    merchant_id — a different entity than the bank accounts the network/
    similarity hunts operate over. This pulls that entity's full transaction
    history directly instead of silently returning nothing meaningful.
    """
    kwargs = {entity_type: entity_id}
    txns = hunter.search(**kwargs)
    if len(txns) < 2:
        return None
    accounts_touched = sorted(txns["account_id"].dropna().unique().tolist())
    label = "card" if entity_type == "card_id" else "merchant"
    return HuntSuggestion(
        hunt_type=f"{entity_type}_activity",
        rationale=(
            f"This {label} has {len(txns)} transaction(s) touching {len(accounts_touched)} account(s) "
            f"in the dataset — pull the full {label} history before deciding this is an isolated incident."
        ),
        results=accounts_touched,
    )


# Rule-specific hunt strategies. Each entry is a list of (fn, kwargs) to run
# against the alert's account_id. Rules not listed here get DEFAULT_STRATEGY —
# this includes any rule added later via the AI-drafted rule workflow, so new
# rules get hunting support automatically without editing this map.
RULE_HUNT_STRATEGY: dict[str, list[tuple]] = {
    "R1": [("network", {"max_hops": 2}), ("similar", {})],  # SIM-swap cash-out
    "R4": [("network", {"max_hops": 2}), ("device", {}), ("similar", {})],  # mule fan-in
    "R5": [("agent_till", {}), ("device", {})],  # agent till anomaly — hunt the agent, not the account
    "R7": [("network", {"max_hops": 5}), ("device", {})],  # layering — hunt further than the detected chain
    "R8": [("network", {"max_hops": 3}), ("device", {}), ("agent", {})],  # dormant sweep — where did it go next?
    "R9": [],  # portfolio-level alert, no single account to hunt from
    "R10": [("device", {}), ("agent", {}), ("similar", {})],  # loan-app cashout
    "R11": [("merchant_activity", {})],  # EMV fallback abuse — merchant-level entity
    "R12": [("card_activity", {})],  # card testing — card-level entity
    "R13": [("card_activity", {})],  # cross-border card velocity — card-level entity
    "R14": [("merchant_activity", {})],  # merchant refund anomaly — merchant-level entity
    "R15": [("network", {"max_hops": 2}), ("similar", {})],  # offline authorization abuse
    "R16": [("network", {"max_hops": 3}), ("similar", {})],  # BEC — hunt where funds went
    "R17": [("network", {"max_hops": 3}), ("device", {})],  # ATO — hunt destination and shared devices
    "R18": [("network", {"max_hops": 2})],  # ATM multi-terminal anomaly
}

DEFAULT_STRATEGY: list[tuple] = [("network", {"max_hops": 2}), ("device", {}), ("agent", {}), ("similar", {})]


def suggest_hunts_for_alert(alert: Alert, hunter: FraudHunter) -> list[HuntSuggestion]:
    """Returns automatically-generated hunting leads for a fired alert.

    Portfolio-level alerts (account_id == "PORTFOLIO", e.g. R9) have no
    single account to hunt from and return an empty list — a human still
    has to identify which specific accounts to hunt first.
    """
    if alert.account_id == "PORTFOLIO":
        return []

    strategy = RULE_HUNT_STRATEGY.get(alert.rule_id, DEFAULT_STRATEGY)
    suggestions: list[HuntSuggestion] = []

    for kind, kwargs in strategy:
        result = None
        if kind == "network":
            result = _network_hunt(hunter, alert.account_id, max_hops=kwargs.get("max_hops", 2))
        elif kind == "device":
            result = _shared_attribute_hunt(hunter, alert.account_id, "device_id", "device")
        elif kind == "agent":
            result = _shared_attribute_hunt(hunter, alert.account_id, "agent_id", "agent till")
        elif kind == "similar":
            result = _similar_accounts_hunt(hunter, alert.account_id, top_n=kwargs.get("top_n", 3))
        elif kind == "agent_till":
            result = _agent_till_hunt(hunter, alert.account_id)
        elif kind == "card_activity":
            result = _entity_activity_hunt(hunter, alert.account_id, "card_id")
        elif kind == "merchant_activity":
            result = _entity_activity_hunt(hunter, alert.account_id, "merchant_id")

        if result is not None:
            suggestions.append(result)

    return suggestions


def annotate_alerts_with_hunts(alerts: list[Alert], hunter: FraudHunter) -> list[dict]:
    """Converts alerts to dicts with a `suggested_hunts` field attached — the
    shape consumed by the CLI's JSON export and the dashboard.
    """
    enriched = []
    for alert in alerts:
        hunts = suggest_hunts_for_alert(alert, hunter)
        record = {**alert.__dict__, "suggested_hunts": [h.to_dict() for h in hunts]}
        enriched.append(record)
    return enriched
