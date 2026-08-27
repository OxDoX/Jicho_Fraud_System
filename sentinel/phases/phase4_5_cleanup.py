"""Phase 4.5 — Cleanup.

Reviews the action log for anything that created persistent state, and
proposes cleanup the same way as testing actions: one at a time, through
the same approval gate (cleanup still touches the target).
"""
from __future__ import annotations

from ..engagement import Engagement
from .phase3_dast import propose_and_run

# Event types in the action log whose payloads are worth a human's eyes when
# scanning for leftover state. This is a prompt for the human, not an
# automatic detector — created state is often only visible in raw_output text.
_STATE_CREATING_EVENT_TYPES = {"execution_result"}
_STATE_HINTS = (
    "created", "uploaded", "account", "token", "api key", "apikey", "webhook",
    "inserted", "registered", "subscribed", "enabled",
)


def scan_for_leftover_state(engagement: Engagement) -> list[dict]:
    hits = []
    for record in engagement.logger.read_action_log():
        if record["event_type"] not in _STATE_CREATING_EVENT_TYPES:
            continue
        text = str(record["payload"]).lower()
        if any(h in text for h in _STATE_HINTS):
            hits.append(record)
    return hits


def propose_cleanup(
    engagement: Engagement,
    description: str,
    target: str,
    confirm_fn=input,
):
    """Draft one cleanup action through the normal approval gate. Since
    cleanup is usually a manual step (delete via UI, revoke via dashboard),
    this uses the manual-cleanup tool, which the runner always drafts for
    the human rather than auto-executing."""
    from ..models import ProposalSource

    return propose_and_run(
        engagement,
        tool="manual-cleanup",
        args=description,
        target=target,
        expected_outcome="Persistent state removed / reverted.",
        rationale="Phase 4.5 cleanup of state created during testing.",
        source=ProposalSource.BASELINE,
        confirm_fn=confirm_fn,
    )
