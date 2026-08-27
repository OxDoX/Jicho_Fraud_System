"""Phase 4 — Verification & Correlation.

A finding only becomes "confirmed" here, and only from a real, approved,
executed, logged Phase 3 result — never from reasoning alone. Anything
touching auth, payments, or production data gets one more explicit
confirmation on top of the standard approval gate.

Correlation groups findings that plausibly share one root cause (same
asset, overlapping title language) so a human can decide whether to merge
them into a single deduplicated finding — the tool only ever suggests and
mechanically merges evidence on explicit instruction; it never decides on
its own that two findings are "the same bug" (Hard Constraint: never
combine unrelated findings into one entry).
"""
from __future__ import annotations

from ..engagement import Engagement
from ..models import Finding

_SENSITIVE_KEYWORDS = ("auth", "login", "payment", "checkout", "billing", "production", "prod")
_STOPWORDS = {
    "the", "and", "for", "with", "from", "into", "onto", "this", "that", "findings",
    "issue", "vulnerability", "possible", "potential", "found", "scan", "test", "via",
}


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


def _significant_words(text: str) -> set[str]:
    return {w for w in text.lower().replace("/", " ").replace("-", " ").split() if len(w) > 3 and w not in _STOPWORDS}


def correlate_findings(engagement: Engagement, min_word_overlap: int = 2) -> list[list[Finding]]:
    """Suggest groups of findings that plausibly share one root cause: same
    asset, and enough overlapping significant words in the title to look
    like the same underlying bug reported from different angles (e.g. a
    SAST hit and its DAST confirmation). Purely a suggestion — nothing here
    changes finding state."""
    candidates = [f for f in engagement.findings if f.status != "duplicate"]
    groups: list[list[Finding]] = []
    used: set[str] = set()

    for i, a in enumerate(candidates):
        if a.id in used:
            continue
        group = [a]
        words_a = _significant_words(a.title)
        for b in candidates[i + 1:]:
            if b.id in used or b.asset != a.asset:
                continue
            words_b = _significant_words(b.title)
            if len(words_a & words_b) >= min_word_overlap:
                group.append(b)
                used.add(b.id)
        if len(group) > 1:
            used.add(a.id)
            groups.append(group)

    return groups


def merge_findings(engagement: Engagement, keep_id: str, absorb_ids: list[str]) -> Finding:
    """Mechanically merge evidence from absorb_ids into keep_id: dedupe and
    concatenate reproduction steps, append evidence blocks, mark the
    absorbed findings 'duplicate'. Does not rewrite title/impact/remediation
    — that's still a human call about what the root cause actually is."""
    by_id = {f.id: f for f in engagement.findings}
    if keep_id not in by_id:
        raise ValueError(f"No finding with id '{keep_id}' on this engagement.")
    keeper = by_id[keep_id]

    seen_steps = set(keeper.reproduction_steps)
    for absorb_id in absorb_ids:
        if absorb_id == keep_id:
            continue
        if absorb_id not in by_id:
            raise ValueError(f"No finding with id '{absorb_id}' on this engagement.")
        absorbed = by_id[absorb_id]
        for step in absorbed.reproduction_steps:
            if step not in seen_steps:
                keeper.reproduction_steps.append(step)
                seen_steps.add(step)
        keeper.evidence_redacted += f"\n\n--- merged from {absorbed.id} ({absorbed.title}) ---\n{absorbed.evidence_redacted}"
        absorbed.status = "duplicate"

    engagement.logger.log_action(
        "findings_merged", {"kept": keep_id, "absorbed": [i for i in absorb_ids if i != keep_id]}
    )
    engagement.save()
    return keeper
