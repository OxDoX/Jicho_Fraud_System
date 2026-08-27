"""
Prevention: turning a real-time alert into a block/hold/allow decision the
calling payment system can act on BEFORE a transaction completes.

This is a fundamentally different risk profile from alerting. An alert that
turns out to be a false positive costs an investigator a few minutes. A
BLOCK decision that turns out to be a false positive denies a real customer
access to their own money — a direct harm, a likely complaint, and
potentially a regulatory issue (timely availability of funds is often a
legal obligation, not just a service-quality nicety). This module is
written to that asymmetry throughout: BLOCK is the narrow, hard-to-reach
outcome; HOLD (step-up authentication or expedited manual review, not an
outright decline) is the default response to high-confidence-but-not-
proven-safe-to-block signals; ALLOW-with-async-alert (today's existing
behavior) remains the default for everything else.

Nothing here enables blocking by default — see EngineConfig.prevention_enabled
and block_eligible_rule_ids in jicho/config.py. An institution's risk and
compliance function must explicitly opt in, rule by rule, after reviewing
that rule's real-world false-positive rate.
"""

from dataclasses import dataclass, field
from enum import Enum

from jicho.config import EngineConfig
from jicho.logging_config import get_logger, mask_account_id
from jicho.models import Alert

logger = get_logger(__name__)


class Decision(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


@dataclass
class PreventionDecision:
    decision: Decision
    reason: str
    triggering_alerts: list[Alert] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "triggering_alert_ids": [(a.rule_id, a.transaction_id) for a in self.triggering_alerts],
        }


def decide(alerts: list[Alert], config: EngineConfig) -> PreventionDecision:
    """Combines all alerts fired for one transaction into a single decision.

    When multiple alerts fire, the most severe outcome wins (BLOCK > HOLD >
    ALLOW) — a transaction is never allowed through just because one of
    several firing rules happened to be a lower-confidence one.
    """
    if not config.prevention_enabled or not alerts:
        return PreventionDecision(Decision.ALLOW, "No prevention policy engaged, or no alerts fired.")

    block_candidates = [
        a for a in alerts
        if a.rule_id in config.block_eligible_rule_ids and a.score >= config.block_min_score
    ]
    if block_candidates:
        top = max(block_candidates, key=lambda a: a.score)
        logger.info(
            f"PREVENTION BLOCK: {top.rule_id} score={top.score} "
            f"account={mask_account_id(top.account_id)} txn={top.transaction_id}"
        )
        return PreventionDecision(
            Decision.BLOCK,
            f"{top.rule_id} ({top.rule_name}) fired at score {top.score}, at or above the "
            f"institution-approved block threshold ({config.block_min_score}) for a rule "
            "explicitly whitelisted for blocking.",
            triggering_alerts=block_candidates,
        )

    hold_candidates = [a for a in alerts if a.score >= config.hold_min_score]
    if hold_candidates:
        top = max(hold_candidates, key=lambda a: a.score)
        logger.info(
            f"PREVENTION HOLD: {top.rule_id} score={top.score} "
            f"account={mask_account_id(top.account_id)} txn={top.transaction_id}"
        )
        return PreventionDecision(
            Decision.HOLD,
            f"{top.rule_id} ({top.rule_name}) fired at score {top.score} — held for step-up "
            "authentication or expedited manual review rather than blocked outright, since "
            "this rule is not on the institution's block-eligible list.",
            triggering_alerts=hold_candidates,
        )

    return PreventionDecision(
        Decision.ALLOW,
        "Alert(s) fired below the hold threshold — logged for async investigation, "
        "transaction proceeds normally.",
        triggering_alerts=alerts,
    )


def decide_safely(alerts: list[Alert], config: EngineConfig) -> PreventionDecision:
    """Wraps decide() so a bug in the decision logic itself can never
    silently become an unreviewed BLOCK — it fails according to the
    institution's configured prevention_fail_mode instead. This is separate
    from decide()'s own logic being simple enough to rarely fail; it exists
    because the cost of an unexamined failure mode here is a customer denied
    their own money, which deserves an explicit, reviewed fallback rather
    than whatever an uncaught exception happens to do.
    """
    try:
        return decide(alerts, config)
    except Exception as e:
        logger.error(f"Prevention decision logic failed: {e}", exc_info=True)
        if config.prevention_fail_mode == "closed":
            return PreventionDecision(Decision.HOLD, f"Decision logic failed ({e}); failing closed per policy.")
        return PreventionDecision(Decision.ALLOW, f"Decision logic failed ({e}); failing open per policy.")
