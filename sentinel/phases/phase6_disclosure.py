"""Phase 6 — Public Disclosure. Separate, stricter approval chain than
testing (Hard Constraint 7). Triggered only when the human explicitly
initiates it for a specific, already-reported finding — this module is
never called from anywhere but an explicit CLI/human invocation.
"""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone

from ..engagement import Engagement
from ..llm.client import LLMUnavailable, SentinelLLM
from ..llm.prompts import disclosure_draft_prompt
from ..models import DisclosureGateAnswers, DisclosureRecord, Finding


def _find_finding(engagement: Engagement, finding_id: str) -> Finding | None:
    for f in engagement.findings:
        if f.id == finding_id:
            return f
    return None


def run_disclosure_gate(
    engagement: Engagement,
    finding_id: str,
    approved_by: str,
    confirm_fn=input,
) -> DisclosureRecord:
    """Ask each of the four disclosure-gate conditions one at a time,
    requiring a direct answer to each — never a blanket 'yes it's cleared'."""
    engagement.assert_not_stopped()

    finding = _find_finding(engagement, finding_id)
    if finding is None:
        raise ValueError(f"No finding with id '{finding_id}' on this engagement.")

    print(f"\n=== PHASE 6 — DISCLOSURE GATE for '{finding.title}' ({finding.id}) ===")
    print("Answer each condition individually. Any 'no' or empty answer refuses disclosure.\n")

    q1 = confirm_fn(
        "1) Has the program/vendor explicitly closed/resolved this, OR has the "
        "program's published disclosure timeline elapsed, OR has the vendor "
        "issued their own advisory/CVE already? [y/N]: "
    ).strip().lower() == "y"

    q2 = confirm_fn(
        "2) Paste the explicit written clearance reference (email subject/link, "
        "platform disclosure-approval message ID, or cited public policy URL). "
        "Leave blank if none exists: "
    ).strip()

    q3 = confirm_fn(
        "3) Confirm the draft will contain NO live/weaponized PoC — root cause, "
        "impact, and remediation only, reduced to what a defender needs to "
        "verify the fix. [y/N]: "
    ).strip().lower() == "y"

    q4 = confirm_fn(
        "4) Confirm NO data belonging to real users/customers appears anywhere "
        "in the draft, even redacted-looking — synthetic examples only. [y/N]: "
    ).strip().lower() == "y"

    answers = DisclosureGateAnswers(
        program_closed_or_policy_elapsed=q1,
        written_clearance_reference=q2,
        poc_scrubbed_to_defender_only=q3,
        no_real_user_data=q4,
    )
    record = DisclosureRecord(finding_id=finding.id, answers=answers, approved_by=approved_by)
    engagement.add_disclosure(record)

    if not answers.all_clear():
        missing = []
        if not answers.program_closed_or_policy_elapsed:
            missing.append("program has not confirmed closure/elapsed timeline/own advisory")
        if not answers.written_clearance_reference.strip():
            missing.append("no written clearance reference provided")
        if not answers.poc_scrubbed_to_defender_only:
            missing.append("PoC not confirmed scrubbed to defender-only detail")
        if not answers.no_real_user_data:
            missing.append("real user data not confirmed absent")
        print("\n✗ Disclosure REFUSED. Missing:")
        for m in missing:
            print(f"  - {m}")

    return record


def draft_disclosure(
    engagement: Engagement,
    finding_id: str,
    disclosure_record: DisclosureRecord,
    timeline: dict,
    llm: SentinelLLM | None = None,
) -> str:
    engagement.assert_not_stopped()

    if not disclosure_record.answers.all_clear():
        raise PermissionError(
            "Refusing to draft: this disclosure record did not clear all four gate conditions."
        )

    finding = _find_finding(engagement, finding_id)
    if finding is None:
        raise ValueError(f"No finding with id '{finding_id}' on this engagement.")

    finding_json = json.dumps({**dataclasses.asdict(finding), "source": finding.source.value}, indent=2)
    timeline_json = json.dumps(timeline, indent=2)

    if llm is not None:
        try:
            draft = llm.ask(disclosure_draft_prompt(finding_json, timeline_json), max_tokens=3000)
        except LLMUnavailable as e:
            draft = f"DRAFT — NOT PUBLISHED. (LLM drafting unavailable: {e})\n\n{finding_json}"
    else:
        draft = f"DRAFT — NOT PUBLISHED.\n\n{finding_json}\n\nTimeline:\n{timeline_json}"

    out_dir = engagement.root / "disclosures"
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"{finding_id}_{ts}_DRAFT.md"
    out_path.write_text(draft, encoding="utf-8")
    engagement.logger.log_disclosure("disclosure_draft_created", {"path": str(out_path), "finding_id": finding_id})
    return str(out_path)


def approve_publish(
    engagement: Engagement,
    disclosure_record: DisclosureRecord,
    confirm_fn=input,
) -> bool:
    """The one-shot, irreversible publish approval (system prompt Phase 6
    Step 4). This function only flips the local record/log — actually
    posting anywhere is a human action outside this tool's scope."""
    engagement.assert_not_stopped()

    if not disclosure_record.answers.all_clear():
        raise PermissionError("Refusing to approve publish: gate conditions not all clear.")

    answer = confirm_fn(
        "FINAL, ONE-SHOT CONFIRMATION: publish this disclosure now? This is "
        "irreversible once posted. [y/N]: "
    ).strip().lower()
    approved = answer == "y"
    if approved:
        disclosure_record.published = True
        disclosure_record.published_at = datetime.now(timezone.utc).isoformat()
    engagement.logger.log_disclosure(
        "publish_decision", {"disclosure_id": disclosure_record.id, "approved": approved}
    )
    engagement.save()
    return approved
