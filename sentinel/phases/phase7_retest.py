"""Phase 7 — Retest on Remediation.

Treated as a new mini-engagement against the same Engagement object: scope
is re-confirmed against the live scope source before anything re-runs, and
every reproduction step goes back through the normal Phase 3 approval gate
— nothing here is exempt just because it worked before.
"""
from __future__ import annotations

from pathlib import Path

from ..engagement import Engagement
from ..scope import load_scope


def scope_has_changed(engagement: Engagement, current_scope_path: str | Path) -> bool:
    current = load_scope(current_scope_path)
    original = engagement.scope
    return (
        {a.pattern for a in current.in_scope} != {a.pattern for a in original.in_scope}
        or set(current.out_of_scope) != set(original.out_of_scope)
        or set(current.exclusions) != set(original.exclusions)
    )


def start_retest(engagement: Engagement, finding_id: str, current_scope_path: str | Path, confirm_fn=input) -> bool:
    if scope_has_changed(engagement, current_scope_path):
        print(
            "⚠ Scope has changed since this engagement's snapshot. Re-run "
            "Phase 1 intake against the new scope doc before retesting."
        )
        engagement.logger.log_action("retest_blocked_scope_changed", {"finding_id": finding_id})
        return False

    finding = next((f for f in engagement.findings if f.id == finding_id), None)
    if finding is None:
        raise ValueError(f"No finding with id '{finding_id}' on this engagement.")

    print(f"\n=== PHASE 7 — RETEST: {finding.title} ({finding.id}) ===")
    print("Original reproduction steps:")
    for step in finding.reproduction_steps:
        print(f"  - {step}")
    print(
        "\nRe-run these (and consider varying the technique slightly to probe "
        "for a narrow patch) via the normal Phase 3 propose_and_run flow — "
        "each step still needs its own fresh approval."
    )

    answer = confirm_fn("Proceed with retest for this finding? [y/N]: ").strip().lower()
    started = answer == "y"
    engagement.logger.log_action("retest_started" if started else "retest_declined", {"finding_id": finding_id})
    return started


def record_retest_outcome(engagement: Engagement, finding_id: str, fix_holds: bool, notes: str) -> None:
    finding = next((f for f in engagement.findings if f.id == finding_id), None)
    if finding is None:
        raise ValueError(f"No finding with id '{finding_id}' on this engagement.")

    finding.status = "fixed" if fix_holds else "open"
    engagement.logger.log_action(
        "retest_outcome",
        {"finding_id": finding_id, "fix_holds": fix_holds, "notes": notes, "new_status": finding.status},
    )
    engagement.save()
