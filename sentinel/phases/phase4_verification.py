"""Phase 4 — Verification & Correlation.

A finding only becomes "confirmed" here, and only from a real, approved,
executed, logged Phase 3 result — never from reasoning alone. Anything
touching auth, payments, or production data gets one more explicit
confirmation on top of the standard approval gate.
"""
from __future__ import annotations

from ..engagement import Engagement
from ..models import Finding

_SENSITIVE_KEYWORDS = ("auth", "login", "payment", "checkout", "billing", "production", "prod")


def touches_sensitive_area(finding: Finding) -> bool:
    haystack = f"{finding.title} {finding.asset} {finding.impact}".lower()
    return any(k in haystack for k in _SENSITIVE_KEYWORDS)


def confirm_finding(engagement: Engagement, finding: Finding, confirm_fn=input) -> bool:
    """Require a real executed result behind the finding, plus an extra
    explicit confirmation if it touches a sensitive area."""
    if not finding.reproduction_steps:
        print("Refusing to confirm: no reproduction steps on file (no executed, logged result).")
        engagement.logger.log_action(
            "finding_confirmation_refused", {"finding_id": finding.id, "reason": "no reproduction_steps"}
        )
        return False

    if touches_sensitive_area(finding):
        answer = confirm_fn(
            f"This finding touches a sensitive area (auth/payments/production) — "
            f"confirm you want to proceed and mark it confirmed: '{finding.title}' [y/N]: "
        ).strip().lower()
        if answer != "y":
            engagement.logger.log_action(
                "finding_confirmation_refused", {"finding_id": finding.id, "reason": "sensitive-area confirmation declined"}
            )
            return False

    finding.status = "confirmed" if finding.status == "open" else finding.status
    engagement.logger.log_action("finding_confirmed", finding)
    engagement.save()
    return True
