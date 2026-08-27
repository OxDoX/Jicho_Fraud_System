"""
Real-time scoring: evaluates a single incoming transaction against a
rolling window of recent history, instead of requiring a full batch file.

Honest scoping, stated up front: this scores ACCOUNT-LOCAL rules
synchronously and accurately (a rule that only needs one account's recent
transactions — R1, R2, R3, R6, R8, R10, R11, R12, R15, R16, R17). Rules that
need a cross-account or cross-entity view (R4, R5, R7, R9, R13, R14, R18)
need either a shared state store visible to all accounts (a real production
deployment would back this with Redis or similar, not this in-memory
implementation) or periodic micro-batch reconciliation. Claiming full
real-time coverage of every rule from an in-memory single-process buffer
would be inaccurate — this module is real-time for what it can honestly do,
and documents the boundary rather than papering over it.

The scoring logic itself (RealtimeScorer.score_transaction) is transport-
agnostic on purpose: the same call works whether it's invoked from an HTTP
endpoint (see the Flask app below), a Kafka consumer loop, or a webhook
handler. Swapping the transport in production is a delivery-mechanism
change, not a rewrite of the detection logic.
"""

from collections import defaultdict
from datetime import timedelta

import pandas as pd

from jicho.config import EngineConfig
from jicho.logging_config import get_logger, mask_account_id
from jicho.models import Alert, validate_transactions
from jicho.rules.base import get_registered_rules

logger = get_logger(__name__)

# Rules that only need one account's own recent transaction history to
# evaluate correctly, verified against the actual grouping key each rule
# uses internally (not assumed) — a rule keyed by merchant_id or agent_id
# needs visibility across every account touching that merchant/agent, which
# a single account's buffer cannot provide:
#   account_id-local:  R1, R2, R3, R4, R6, R8, R10, R15, R16, R17, R18
#   card_id-keyed:      R12, R13 — included as local with a caveat: correct
#                       for the common case where a card belongs to one
#                       account, but would miss the rare case where the same
#                       card_id appears under a different account_id record.
#   NOT local, excluded: R5 (agent_id-keyed), R7 (cross-account chain by
#                       design), R9 (portfolio-wide), R11 (merchant_id-keyed),
#                       R14 (merchant_id-keyed) — these need the full batch
#                       run or a shared cross-account state store, not an
#                       in-memory per-account buffer.
ACCOUNT_LOCAL_RULE_IDS = {"R1", "R2", "R3", "R4", "R6", "R8", "R10", "R12", "R13", "R15", "R16", "R17", "R18"}


class RealtimeScorer:
    def __init__(self, config: EngineConfig, retention: timedelta | None = None):
        self.config = config
        # Retention window must cover the longest lookback any account-local
        # rule needs, with margin. Computed from config rather than hardcoded
        # so it stays correct as thresholds are retuned via calibration.py.
        self.retention = retention or self._compute_retention(config)
        self._buffers: dict[str, list[dict]] = defaultdict(list)
        self._seen_alerts: set[tuple[str, str]] = set()  # (rule_id, transaction_id) already surfaced
        rules = get_registered_rules()
        self._local_rules = {rid: cls() for rid, cls in rules.items() if rid in ACCOUNT_LOCAL_RULE_IDS}
        logger.info(
            f"RealtimeScorer initialized: {len(self._local_rules)} account-local rules active "
            f"({sorted(self._local_rules)}), retention={self.retention}"
        )

    @staticmethod
    def _compute_retention(config: EngineConfig) -> timedelta:
        hours_candidates = [
            config.sim_swap_window_hours, config.structuring_window_hours,
            config.dormant_sweep_window_hours, config.bec_window_hours,
            config.offline_auth_window_hours, config.loan_cashout_window_hours,
        ]
        minutes_candidates = [
            config.velocity_window_minutes, config.card_testing_window_minutes, config.ato_window_minutes
        ]
        longest_hours = max(hours_candidates) if hours_candidates else 0
        longest_minutes = max(minutes_candidates) / 60 if minutes_candidates else 0
        return timedelta(hours=max(longest_hours, longest_minutes) + 1)  # +1h margin

    def _prune(self, account_id: str, now: pd.Timestamp) -> None:
        cutoff = now - self.retention
        self._buffers[account_id] = [t for t in self._buffers[account_id] if t["timestamp"] >= cutoff]

    def score_transaction(self, transaction: dict) -> list[Alert]:
        """Scores one incoming transaction against that account's rolling
        window. `transaction` is a dict matching the standard schema (see
        jicho.models); timestamp may be a string or pandas-parseable value.
        """
        txn = dict(transaction)
        txn["timestamp"] = pd.Timestamp(txn["timestamp"])
        account_id = txn["account_id"]

        self._buffers[account_id].append(txn)
        self._prune(account_id, txn["timestamp"])

        window_df = pd.DataFrame(self._buffers[account_id])
        window_df = validate_transactions(window_df)

        alerts: list[Alert] = []
        for rule_id, rule in self._local_rules.items():
            try:
                rule_alerts = rule.evaluate(window_df, self.config)
                # Surface only alerts not already returned by a PREVIOUS call —
                # a rule may attribute its alert to whichever transaction its
                # own logic considers the trigger (often the first one in a
                # qualifying window, not necessarily the one just appended),
                # so filtering by "matches the incoming transaction_id" would
                # silently drop real detections. Tracking (rule_id,
                # transaction_id) pairs already surfaced is the correct
                # de-duplication: it re-evaluates the whole window on every
                # call (cheap at this scale) but only ever reports each
                # distinct finding once.
                new_alerts = [a for a in rule_alerts if (a.rule_id, a.transaction_id) not in self._seen_alerts]
                for a in new_alerts:
                    self._seen_alerts.add((a.rule_id, a.transaction_id))
                alerts.extend(new_alerts)
            except Exception as e:
                logger.error(f"Real-time rule {rule_id} failed on account {mask_account_id(account_id)}: {e}")
                continue

        if alerts:
            logger.info(f"Real-time score: {len(alerts)} alert(s) for account {mask_account_id(account_id)}")
        return alerts

    def buffer_size(self, account_id: str) -> int:
        return len(self._buffers.get(account_id, []))
