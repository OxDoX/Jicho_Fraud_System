"""Phase 1.25 — Duplicate & Policy-Exclusion Check.

Cheap, local check: does a proposed hypothesis/target description mention
anything from the program's own published exclusion list, or match a line
in an optional local file of prior-disclosed-report summaries the human
supplies (pasted from Hacktivity/Bugcrowd disclosed/program changelog)?
This is a flag-to-human aid, not a source of truth — it never silently
drops a hypothesis, only surfaces the overlap (Hard Constraint 13).
"""
from __future__ import annotations

from pathlib import Path

from ..engagement import Engagement


def check_exclusions(engagement: Engagement, description: str) -> list[str]:
    hits = []
    lowered = description.lower()
    for excl in engagement.scope.exclusions:
        keywords = [w.strip().lower() for w in excl.replace("/", " ").split() if len(w.strip()) > 3]
        if keywords and any(k in lowered for k in keywords):
            hits.append(excl)
    return hits


def check_prior_disclosures(description: str, prior_reports_path: str | Path | None) -> list[str]:
    if not prior_reports_path:
        return []
    path = Path(prior_reports_path)
    if not path.exists():
        return []
    lowered_desc_words = {w.lower() for w in description.split() if len(w) > 4}
    hits = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        line_words = {w.lower() for w in line.split() if len(w) > 4}
        overlap = lowered_desc_words & line_words
        if len(overlap) >= 3:
            hits.append(line)
    return hits


def run(
    engagement: Engagement,
    description: str,
    prior_reports_path: str | Path | None = None,
) -> dict:
    exclusion_hits = check_exclusions(engagement, description)
    prior_hits = check_prior_disclosures(description, prior_reports_path)
    result = {
        "description": description,
        "exclusion_hits": exclusion_hits,
        "prior_disclosure_hits": prior_hits,
        "likely_excluded_or_duplicate": bool(exclusion_hits or prior_hits),
    }
    engagement.logger.log_action("dedup_exclusion_check", result)
    if result["likely_excluded_or_duplicate"]:
        print("⚠ This may be a duplicate or policy-excluded hypothesis — flag before testing:")
        for h in exclusion_hits:
            print(f"  - matches exclusion: {h}")
        for h in prior_hits:
            print(f"  - resembles prior disclosure line: {h}")
    return result
