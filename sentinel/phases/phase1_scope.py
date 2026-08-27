"""Phase 1 — Scope & Authorization Intake.

No tool touches a target before this phase is explicitly confirmed by the
human, every time an engagement is created or resumed (Hard Constraint 15).
"""
from __future__ import annotations

from ..engagement import Engagement


def summarize(engagement: Engagement) -> str:
    s = engagement.scope
    lines = [
        f"Program: {s.program_name}",
        f"Engagement type: {s.engagement_type.value}",
        "In-scope:",
        *[f"  - {a.pattern} ({a.asset_type})" for a in s.in_scope],
        "Out-of-scope:",
        *([f"  - {x}" for x in s.out_of_scope] or ["  (none listed)"]),
        "Exclusions (standing, do not spend approval cycles here without flagging):",
        *([f"  - {x}" for x in s.exclusions] or ["  (none listed)"]),
        f"Safe harbor confirmed: {s.safe_harbor_confirmed}",
        f"Identity/attribution requirement: {s.identity_requirement or '(not specified)'}",
        f"Rate limit: {s.rate_limit or '(not specified)'}",
        "Blackout windows:",
        *([f"  - {x}" for x in s.blackout_windows] or ["  (none listed)"]),
    ]
    return "\n".join(lines)


def run(engagement: Engagement, confirm_fn=input) -> bool:
    """Print the scope summary and require explicit confirmation before any
    other phase may run. Returns True iff confirmed."""
    print("\n=== PHASE 1 — SCOPE & AUTHORIZATION INTAKE ===")
    print(summarize(engagement))

    if not engagement.scope.safe_harbor_confirmed:
        print(
            "\n⚠ safe_harbor_confirmed is False in the scope doc. Per the legal "
            "safe-harbor check, do not assume coverage — get written clarification "
            "from the program before active testing, or confirm a signed SOW for "
            "a private pentest engagement."
        )

    answer = confirm_fn(
        "\nConfirm scope, authorization, and constraints as summarized above? [y/N]: "
    ).strip().lower()
    confirmed = answer == "y"

    engagement.logger.log_action(
        "phase1_intake_decision",
        {"confirmed": confirmed, "safe_harbor_confirmed": engagement.scope.safe_harbor_confirmed},
    )
    engagement.phase1_confirmed = confirmed
    if confirmed:
        engagement.set_phase("1.25_dedup_exclusion_check")
    engagement.save()
    return confirmed


def require_confirmed(engagement: Engagement) -> None:
    """Guard used by every later phase — refuses to proceed on an
    unconfirmed or stale engagement rather than assuming it's fine."""
    if not engagement.phase1_confirmed:
        raise RuntimeError(
            "Phase 1 scope/authorization has not been confirmed for this "
            "engagement. Run `sentinel intake` first."
        )
