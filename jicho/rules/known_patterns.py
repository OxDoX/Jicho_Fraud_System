"""
Detection rules for East/Central/Southern African fraud typologies.

Each rule is independently testable (see tests/test_rules.py) and
registered automatically via @register_rule — the engine discovers them
at import time, no manual wiring required.
"""

from collections import defaultdict
from datetime import timedelta

import pandas as pd

from jicho.config import EngineConfig
from jicho.models import Alert
from jicho.rules.base import Rule, register_rule


@register_rule
class SimSwapCashoutRule(Rule):
    rule_id = "R1"
    rule_name = "SIM-Swap Cash-Out"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(hours=config.sim_swap_window_hours)
        swaps = df[df["event_type"] == "sim_swap"] if "event_type" in df.columns else df.iloc[0:0]
        for _, swap in swaps.iterrows():
            acct = swap["account_id"]
            t0 = swap["timestamp"]
            candidates = df[
                (df["account_id"] == acct)
                & (df["transaction_type"] == "withdrawal")
                & (df["timestamp"] >= t0)
                & (df["timestamp"] <= t0 + window)
                & (df["amount"] >= config.sim_swap_amount_threshold)
            ]
            for _, txn in candidates.iterrows():
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=acct, transaction_id=txn["transaction_id"],
                    timestamp=str(txn["timestamp"]), severity="CRITICAL", score=95,
                    description=(
                        f"Withdrawal of {txn['amount']:,.0f} occurred "
                        f"{(txn['timestamp']-t0)} after a SIM/device change on this account."
                    ),
                    evidence={"sim_swap_time": str(t0), "withdrawal_amount": float(txn["amount"])}
                ))
        return alerts


@register_rule
class VelocitySpikeRule(Rule):
    rule_id = "R2"
    rule_name = "Velocity Spike"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(minutes=config.velocity_window_minutes)
        txns = df[df["transaction_type"].isin(["withdrawal", "transfer_out", "cash_out"])].sort_values("timestamp")
        for acct, group in txns.groupby("account_id"):
            times = group["timestamp"].tolist()
            ids = group["transaction_id"].tolist()
            for i in range(len(times)):
                count = sum(1 for t in times if times[i] <= t <= times[i] + window)
                if count >= config.velocity_txn_count:
                    alerts.append(Alert(
                        rule_id=self.rule_id, rule_name=self.rule_name,
                        account_id=acct, transaction_id=ids[i],
                        timestamp=str(times[i]), severity="HIGH", score=75,
                        description=(
                            f"{count} outbound transactions within "
                            f"{config.velocity_window_minutes} minutes starting {times[i]}."
                        ),
                        evidence={"txn_count_in_window": count}
                    ))
                    break
        return alerts


@register_rule
class StructuringRule(Rule):
    rule_id = "R3"
    rule_name = "Structuring / Smurfing"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(hours=config.structuring_window_hours)
        threshold = config.structuring_threshold
        deposits = df[
            (df["transaction_type"].isin(["deposit", "cash_in"]))
            & (df["amount"] < threshold)
            & (df["amount"] >= threshold * 0.6)
        ].sort_values("timestamp")
        for acct, group in deposits.groupby("account_id"):
            times = group["timestamp"].tolist()
            ids = group["transaction_id"].tolist()
            for i in range(len(times)):
                window_txns = [t for t in times if times[i] <= t <= times[i] + window]
                if len(window_txns) >= config.structuring_min_txns:
                    alerts.append(Alert(
                        rule_id=self.rule_id, rule_name=self.rule_name,
                        account_id=acct, transaction_id=ids[i],
                        timestamp=str(times[i]), severity="MEDIUM", score=60,
                        description=(
                            f"{len(window_txns)} deposits just below the {threshold:,.0f} "
                            f"reporting threshold within {config.structuring_window_hours}h."
                        ),
                        evidence={"deposit_count": len(window_txns), "threshold": threshold}
                    ))
                    break
        return alerts


@register_rule
class MuleFaninRule(Rule):
    rule_id = "R4"
    rule_name = "Money-Mule Fan-In / Sweep-Out"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(hours=config.mule_fanin_window_hours)
        inflows = df[df["transaction_type"].isin(["deposit", "transfer_in", "cash_in"])]
        for acct, group in inflows.groupby("account_id"):
            group = group.sort_values("timestamp")
            for _, row in group.iterrows():
                t0 = row["timestamp"]
                window_inflows = group[(group["timestamp"] >= t0) & (group["timestamp"] <= t0 + window)]
                distinct_senders = window_inflows["counterparty_id"].nunique()
                if distinct_senders >= config.mule_fanin_sender_count:
                    total_in = window_inflows["amount"].sum()
                    outflows = df[
                        (df["account_id"] == acct)
                        & (df["transaction_type"].isin(["withdrawal", "transfer_out", "cash_out"]))
                        & (df["timestamp"] >= t0)
                        & (df["timestamp"] <= t0 + window)
                    ]
                    total_out = outflows["amount"].sum()
                    if total_in > 0 and (total_out / total_in) >= config.mule_outflow_ratio:
                        alerts.append(Alert(
                            rule_id=self.rule_id, rule_name=self.rule_name,
                            account_id=acct, transaction_id=row["transaction_id"],
                            timestamp=str(t0), severity="CRITICAL", score=90,
                            description=(
                                f"Received funds from {distinct_senders} distinct senders then moved out "
                                f"{total_out/total_in:.0%} of inflows within "
                                f"{config.mule_fanin_window_hours}h — classic mule pattern."
                            ),
                            evidence={
                                "distinct_senders": int(distinct_senders),
                                "outflow_ratio": float(total_out / total_in),
                            }
                        ))
                        break
        return alerts


@register_rule
class AgentAnomalyRule(Rule):
    rule_id = "R5"
    rule_name = "Agent Till Cash-Out Anomaly"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "agent_id" not in df.columns:
            return alerts
        agents = df[df["channel"] == "agent"]
        for agent_id, group in agents.groupby("agent_id"):
            if pd.isna(agent_id):
                continue
            cash_out = group[group["transaction_type"] == "cash_out"]["amount"].sum()
            cash_in = group[group["transaction_type"] == "cash_in"]["amount"].sum()
            if cash_in > 0 and (cash_out / cash_in) >= config.agent_cashout_ratio_threshold:
                last_txn = group.sort_values("timestamp").iloc[-1]
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=str(agent_id), transaction_id=last_txn["transaction_id"],
                    timestamp=str(last_txn["timestamp"]), severity="HIGH", score=70,
                    description=(
                        f"Agent till shows cash-out {cash_out/cash_in:.1f}x cash-in volume — "
                        "consistent with unrecorded OTC transactions bypassing customer wallets."
                    ),
                    evidence={"cash_out_total": float(cash_out), "cash_in_total": float(cash_in)}
                ))
        return alerts


@register_rule
class OffHoursInsiderRule(Rule):
    rule_id = "R6"
    rule_name = "Off-Hours Staff-Initiated Transaction"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "initiated_by_staff" not in df.columns:
            return alerts
        staff_txns = df[df["initiated_by_staff"] == True]  # noqa: E712
        for _, row in staff_txns.iterrows():
            hour = row["timestamp"].hour
            offhours = not (config.offhours_start <= hour < config.offhours_end)
            if offhours and row["amount"] >= config.offhours_amount_threshold:
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=row["account_id"], transaction_id=row["transaction_id"],
                    timestamp=str(row["timestamp"]), severity="HIGH", score=80,
                    description=(
                        f"Staff-initiated transaction of {row['amount']:,.0f} at "
                        f"{row['timestamp'].strftime('%H:%M')}, outside normal business hours — "
                        "possible insider collusion."
                    ),
                    evidence={"hour": int(hour), "amount": float(row["amount"])}
                ))
        return alerts


@register_rule
class RapidLayeringRule(Rule):
    rule_id = "R7"
    rule_name = "Rapid Cross-Account Layering"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(minutes=config.layering_window_minutes)
        transfers = df[df["transaction_type"] == "transfer_out"].sort_values("timestamp")
        chain = defaultdict(list)
        for _, row in transfers.iterrows():
            chain[row["account_id"]].append(
                (row["timestamp"], row["counterparty_id"], row["transaction_id"], row["amount"])
            )

        for acct in set(transfers["account_id"].unique()):
            hops, current, t_ref, path, seen = 0, acct, None, [], set()
            while current in chain and current not in seen:
                seen.add(current)
                entries = [e for e in chain[current] if (t_ref is None or e[0] >= t_ref)]
                if not entries:
                    break
                entries.sort(key=lambda e: e[0])
                t, nxt, txn_id, amt = entries[0]
                if t_ref is not None and t - t_ref > window:
                    break
                path.append((current, txn_id, t))
                hops += 1
                t_ref = t
                current = nxt
            if hops >= config.layering_hop_count:
                first_txn = path[0][1]
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=acct, transaction_id=first_txn,
                    timestamp=str(path[0][2]), severity="CRITICAL", score=92,
                    description=(
                        f"Funds moved through {hops} accounts within {config.layering_window_minutes} minutes — "
                        "pattern consistent with layering to exhaust per-institution monitoring thresholds."
                    ),
                    evidence={"hop_count": hops, "path": [p[0] for p in path]}
                ))
        return alerts


@register_rule
class DormantAccountSweepRule(Rule):
    rule_id = "R8"
    rule_name = "Dormant Account Sudden Inflow + Sweep"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(hours=config.dormant_sweep_window_hours)
        inflows = df[df["transaction_type"].isin(["transfer_in", "deposit"])].sort_values("timestamp")
        for acct, group in inflows.groupby("account_id"):
            history = df[df["account_id"] == acct].sort_values("timestamp")
            first_seen = history["timestamp"].min()
            for _, row in group.iterrows():
                if (row["timestamp"] - first_seen) > timedelta(minutes=1):
                    continue
                if row["amount"] < config.dormant_sweep_amount_threshold:
                    continue
                t0 = row["timestamp"]
                outflows = df[
                    (df["account_id"] == acct)
                    & (df["transaction_type"].isin(["transfer_out", "withdrawal", "cash_out"]))
                    & (df["timestamp"] >= t0)
                    & (df["timestamp"] <= t0 + window)
                ]
                total_out = outflows["amount"].sum()
                if row["amount"] > 0 and (total_out / row["amount"]) >= config.dormant_sweep_ratio:
                    alerts.append(Alert(
                        rule_id=self.rule_id, rule_name=self.rule_name,
                        account_id=acct, transaction_id=row["transaction_id"],
                        timestamp=str(t0), severity="CRITICAL", score=93,
                        description=(
                            f"Account with no prior activity received {row['amount']:,.0f} then swept out "
                            f"{total_out/row['amount']:.0%} of it within {config.dormant_sweep_window_hours}h — "
                            "matches the mule-account pattern seen on EFT rails without payee-name verification."
                        ),
                        evidence={
                            "inflow_amount": float(row["amount"]),
                            "outflow_ratio": float(total_out / row["amount"]),
                        }
                    ))
        return alerts


@register_rule
class SynchronizedWithdrawalSpikeRule(Rule):
    rule_id = "R9"
    rule_name = "Synchronized Multi-Account Withdrawal Spike"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(minutes=config.sync_spike_window_minutes)
        withdrawals = df[df["transaction_type"].isin(["withdrawal", "cash_out"])].sort_values("timestamp")
        for t0 in withdrawals["timestamp"].tolist():
            in_window = withdrawals[(withdrawals["timestamp"] >= t0) & (withdrawals["timestamp"] <= t0 + window)]
            distinct_accounts = in_window["account_id"].nunique()
            if distinct_accounts >= config.sync_spike_account_count:
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id="PORTFOLIO", transaction_id=in_window.iloc[0]["transaction_id"],
                    timestamp=str(t0), severity="HIGH", score=78,
                    description=(
                        f"{distinct_accounts} unrelated accounts attempted withdrawals within "
                        f"{config.sync_spike_window_minutes} minutes — consistent with a panic run "
                        "following an investment/forex scheme collapse or public scam alert."
                    ),
                    evidence={"distinct_accounts": int(distinct_accounts), "window_start": str(t0)}
                ))
                break
        return alerts


@register_rule
class LoanDisbursementCashoutRule(Rule):
    rule_id = "R10"
    rule_name = "Loan-App Disbursement Rapid Cash-Out"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(hours=config.loan_cashout_window_hours)
        disbursements = df[df["transaction_type"] == "loan_disbursement"]
        for _, row in disbursements.iterrows():
            acct = row["account_id"]
            t0 = row["timestamp"]
            cashouts = df[
                (df["account_id"] == acct)
                & (df["transaction_type"].isin(["withdrawal", "cash_out"]))
                & (df["timestamp"] >= t0)
                & (df["timestamp"] <= t0 + window)
            ]
            total_out = cashouts["amount"].sum()
            if row["amount"] > 0 and (total_out / row["amount"]) >= config.loan_cashout_ratio:
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=acct, transaction_id=row["transaction_id"],
                    timestamp=str(t0), severity="HIGH", score=82,
                    description=(
                        f"Loan disbursement of {row['amount']:,.0f} was {total_out/row['amount']:.0%} cashed out "
                        f"within {config.loan_cashout_window_hours}h of disbursement — pattern flagged by Interpol "
                        "as linked to fraudulent mobile loan-app rings."
                    ),
                    evidence={
                        "disbursement_amount": float(row["amount"]),
                        "cashout_ratio": float(total_out / row["amount"]),
                    }
                ))
        return alerts


@register_rule
class EmvFallbackAbuseRule(Rule):
    rule_id = "R11"
    rule_name = "EMV Fallback Abuse"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "entry_mode" not in df.columns or "merchant_id" not in df.columns:
            return alerts
        pos_txns = df[df["transaction_type"] == "pos_purchase"]
        for merchant_id, group in pos_txns.groupby("merchant_id"):
            if pd.isna(merchant_id) or len(group) < config.fallback_min_sample_size:
                continue
            fallback_count = (group["entry_mode"] == "swipe").sum()
            ratio = fallback_count / len(group)
            if ratio >= config.fallback_ratio_threshold:
                last_txn = group.sort_values("timestamp").iloc[-1]
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=str(merchant_id), transaction_id=last_txn["transaction_id"],
                    timestamp=str(last_txn["timestamp"]), severity="HIGH", score=76,
                    description=(
                        f"Merchant's magstripe-fallback rate is {ratio:.1%} of {len(group)} card-present "
                        "transactions — above Visa's 1.5% excessive-fallback threshold (VAMP, 2026). "
                        "Consistent with intentionally damaged chips forcing fallback to cloned magstripe cards."
                    ),
                    evidence={"fallback_ratio": float(ratio), "sample_size": int(len(group))}
                ))
        return alerts


@register_rule
class CardTestingRule(Rule):
    rule_id = "R12"
    rule_name = "Card Testing Pattern"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "card_id" not in df.columns:
            return alerts
        window = timedelta(minutes=config.card_testing_window_minutes)
        small_txns = df[
            (df["transaction_type"] == "pos_purchase")
            & (df["amount"] <= config.card_testing_amount_threshold)
        ].sort_values("timestamp")
        for card_id, group in small_txns.groupby("card_id"):
            if pd.isna(card_id):
                continue
            times = group["timestamp"].tolist()
            ids = group["transaction_id"].tolist()
            for i in range(len(times)):
                window_txns = [t for t in times if times[i] <= t <= times[i] + window]
                if len(window_txns) >= config.card_testing_min_txns:
                    alerts.append(Alert(
                        rule_id=self.rule_id, rule_name=self.rule_name,
                        account_id=str(card_id), transaction_id=ids[i],
                        timestamp=str(times[i]), severity="HIGH", score=79,
                        description=(
                            f"{len(window_txns)} small POS transactions "
                            f"(≤{config.card_testing_amount_threshold:,.0f}) on this card within "
                            f"{config.card_testing_window_minutes} minutes — pattern consistent with a "
                            "stolen card being tested for validity before a larger purchase."
                        ),
                        evidence={"txn_count": len(window_txns)}
                    ))
                    break
        return alerts


@register_rule
class CrossBorderCardVelocityRule(Rule):
    rule_id = "R13"
    rule_name = "Cross-Border Card Velocity"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "card_id" not in df.columns or "terminal_country" not in df.columns:
            return alerts
        window = timedelta(hours=config.impossible_travel_window_hours)
        pos_txns = df[df["transaction_type"] == "pos_purchase"].sort_values("timestamp")
        for card_id, group in pos_txns.groupby("card_id"):
            if pd.isna(card_id):
                continue
            rows = list(group.iterrows())
            for i in range(len(rows) - 1):
                _, row_a = rows[i]
                for j in range(i + 1, len(rows)):
                    _, row_b = rows[j]
                    gap = row_b["timestamp"] - row_a["timestamp"]
                    if gap > window:
                        break
                    if row_a["terminal_country"] != row_b["terminal_country"]:
                        alerts.append(Alert(
                            rule_id=self.rule_id, rule_name=self.rule_name,
                            account_id=str(card_id), transaction_id=row_b["transaction_id"],
                            timestamp=str(row_b["timestamp"]), severity="CRITICAL", score=91,
                            description=(
                                f"Same card used in {row_a['terminal_country']} then "
                                f"{row_b['terminal_country']} within {gap} — too fast for legitimate "
                                "travel, consistent with a cloned card used in two locations."
                            ),
                            evidence={
                                "country_a": row_a["terminal_country"],
                                "country_b": row_b["terminal_country"],
                                "gap_seconds": gap.total_seconds(),
                            }
                        ))
                        break
        return alerts


@register_rule
class MerchantRefundAnomalyRule(Rule):
    rule_id = "R14"
    rule_name = "Merchant Refund Anomaly"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "merchant_id" not in df.columns:
            return alerts
        for merchant_id, group in df.groupby("merchant_id"):
            if pd.isna(merchant_id):
                continue
            sales = group[group["transaction_type"] == "pos_purchase"]["amount"].sum()
            refunds = group[group["transaction_type"] == "refund"]["amount"].sum()
            if sales > 0 and (refunds / sales) >= config.refund_ratio_threshold:
                last_txn = group.sort_values("timestamp").iloc[-1]
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=str(merchant_id), transaction_id=last_txn["transaction_id"],
                    timestamp=str(last_txn["timestamp"]), severity="MEDIUM", score=64,
                    description=(
                        f"Refunds are {refunds/sales:.0%} of this merchant's sales volume — consistent "
                        "with return fraud or merchant collusion rather than genuine returns."
                    ),
                    evidence={
                        "refund_ratio": float(refunds / sales),
                        "sales_total": float(sales),
                        "refund_total": float(refunds),
                    }
                ))
        return alerts


@register_rule
class OfflineAuthorizationAbuseRule(Rule):
    rule_id = "R15"
    rule_name = "Offline Authorization Abuse"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "auth_mode" not in df.columns:
            return alerts
        window = timedelta(hours=config.offline_auth_window_hours)
        offline_txns = df[df["auth_mode"] == "offline"].sort_values("timestamp")
        for acct, group in offline_txns.groupby("account_id"):
            times = group["timestamp"].tolist()
            ids = group["transaction_id"].tolist()
            amounts = group["amount"].tolist()
            for i in range(len(times)):
                window_idx = [j for j in range(len(times)) if times[i] <= times[j] <= times[i] + window]
                if len(window_idx) >= config.offline_auth_count_threshold:
                    total = sum(amounts[j] for j in window_idx)
                    alerts.append(Alert(
                        rule_id=self.rule_id, rule_name=self.rule_name,
                        account_id=acct, transaction_id=ids[i],
                        timestamp=str(times[i]), severity="HIGH", score=81,
                        description=(
                            f"{len(window_idx)} offline-authorized transactions totaling {total:,.0f} "
                            f"within {config.offline_auth_window_hours}h — offline mode skips real-time "
                            "balance/velocity checks, a known vector for excess-spend fraud once a "
                            "terminal or network segment goes offline."
                        ),
                        evidence={"offline_txn_count": len(window_idx), "total_amount": float(total)}
                    ))
                    break
        return alerts


@register_rule
class BecPaymentRedirectionRule(Rule):
    rule_id = "R16"
    rule_name = "BEC-Pattern Payment Redirection"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(hours=config.bec_window_hours)
        changes = df[df["event_type"] == "beneficiary_change"] if "event_type" in df.columns else df.iloc[0:0]
        for _, change in changes.iterrows():
            acct = change["account_id"]
            t0 = change["timestamp"]
            candidates = df[
                (df["account_id"] == acct)
                & (df["transaction_type"] == "transfer_out")
                & (df["timestamp"] >= t0)
                & (df["timestamp"] <= t0 + window)
                & (df["amount"] >= config.bec_amount_threshold)
            ]
            for _, txn in candidates.iterrows():
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=acct, transaction_id=txn["transaction_id"],
                    timestamp=str(txn["timestamp"]), severity="CRITICAL", score=89,
                    description=(
                        f"A high-value transfer of {txn['amount']:,.0f} followed a beneficiary detail "
                        f"change by {(txn['timestamp']-t0)} — matches the standard BEC payment-redirection "
                        "signature: an urgent payment sent to a newly-changed beneficiary."
                    ),
                    evidence={"beneficiary_change_time": str(t0), "transfer_amount": float(txn["amount"])}
                ))
        return alerts


@register_rule
class CredentialPhishingAtoRule(Rule):
    rule_id = "R17"
    rule_name = "Credential-Phishing Account Takeover"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        window = timedelta(minutes=config.ato_window_minutes)
        logins = df[df["event_type"] == "suspicious_login"] if "event_type" in df.columns else df.iloc[0:0]
        for _, login in logins.iterrows():
            acct = login["account_id"]
            t0 = login["timestamp"]
            candidates = df[
                (df["account_id"] == acct)
                & (df["transaction_type"].isin(["transfer_out", "withdrawal"]))
                & (df["timestamp"] >= t0)
                & (df["timestamp"] <= t0 + window)
                & (df["amount"] >= config.ato_amount_threshold)
            ]
            for _, txn in candidates.iterrows():
                alerts.append(Alert(
                    rule_id=self.rule_id, rule_name=self.rule_name,
                    account_id=acct, transaction_id=txn["transaction_id"],
                    timestamp=str(txn["timestamp"]), severity="CRITICAL", score=88,
                    description=(
                        f"A transaction of {txn['amount']:,.0f} occurred {(txn['timestamp']-t0)} after a "
                        "flagged suspicious login (new device/location/impossible-travel login) — "
                        "consistent with account takeover following credential phishing, independent "
                        "of which channel (SIM-swap, malware, or phishing) delivered the credentials."
                    ),
                    evidence={"suspicious_login_time": str(t0), "amount": float(txn["amount"])}
                ))
        return alerts


@register_rule
class AtmMultiTerminalAnomalyRule(Rule):
    rule_id = "R18"
    rule_name = "Rapid Multi-Terminal ATM Withdrawal"

    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        alerts = []
        if "terminal_id" not in df.columns:
            return alerts
        window = timedelta(minutes=config.atm_multi_terminal_window_minutes)
        atm_txns = df[(df["channel"] == "atm") & (df["transaction_type"] == "withdrawal")].sort_values("timestamp")
        for acct, group in atm_txns.groupby("account_id"):
            rows = list(group.iterrows())
            for i in range(len(rows) - 1):
                _, row_a = rows[i]
                for j in range(i + 1, len(rows)):
                    _, row_b = rows[j]
                    gap = row_b["timestamp"] - row_a["timestamp"]
                    if gap > window:
                        break
                    if row_a["terminal_id"] != row_b["terminal_id"]:
                        alerts.append(Alert(
                            rule_id=self.rule_id, rule_name=self.rule_name,
                            account_id=acct, transaction_id=row_b["transaction_id"],
                            timestamp=str(row_b["timestamp"]), severity="HIGH", score=84,
                            description=(
                                f"Withdrawals at two physically distinct ATM terminals "
                                f"({row_a['terminal_id']} then {row_b['terminal_id']}) within {gap} — "
                                "too fast for legitimate travel between machines, consistent with a "
                                "cloned card or payment-switch routing abuse."
                            ),
                            evidence={
                                "terminal_a": row_a["terminal_id"], "terminal_b": row_b["terminal_id"],
                                "gap_seconds": gap.total_seconds(),
                            }
                        ))
                        break
        return alerts
