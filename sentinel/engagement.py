"""Engagement container: ties scope + logger + persisted state together.

One engagement = one program/target on one branch of work (Hard Constraint
16: never reuse state across engagements). All state lives under
`engagements/<id>/` as plain JSON/JSONL so it's inspectable and diffable.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from .logging_utils import EngagementLogger
from .models import (
    DisclosureRecord,
    EngagementType,
    Finding,
    Hypothesis,
    ScopeDoc,
    now_iso,
)
from .scope import load_scope

ENGAGEMENTS_ROOT = Path("engagements")


def _to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if hasattr(obj, "value") and not isinstance(obj, (str, int, float, bool)):
        return obj.value
    return obj


class Engagement:
    def __init__(self, engagement_id: str, scope: ScopeDoc, root: Path | None = None):
        self.id = engagement_id
        self.scope = scope
        self.root = (root or ENGAGEMENTS_ROOT) / engagement_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.logger = EngagementLogger(self.root)
        self.state_path = self.root / "state.json"
        self.findings: list[Finding] = []
        self.hypotheses: list[Hypothesis] = []
        self.disclosures: list[DisclosureRecord] = []
        self.current_phase: str = "1_scope_intake"
        self.phase1_confirmed: bool = False
        self.stopped: bool = False
        self.stop_reason: str = ""
        self._load_state()

    # --- persistence ---

    def _load_state(self) -> None:
        if not self.state_path.exists():
            return
        data = json.loads(self.state_path.read_text())
        self.current_phase = data.get("current_phase", self.current_phase)
        self.phase1_confirmed = data.get("phase1_confirmed", False)
        self.stopped = data.get("stopped", False)
        self.stop_reason = data.get("stop_reason", "")
        # findings/hypotheses/disclosures are kept as raw dicts on disk;
        # phases that need typed objects re-hydrate lazily where needed.
        self._raw_findings = data.get("findings", [])
        self._raw_hypotheses = data.get("hypotheses", [])
        self._raw_disclosures = data.get("disclosures", [])

    def save(self) -> None:
        data = {
            "id": self.id,
            "program_name": self.scope.program_name,
            "engagement_type": self.scope.engagement_type.value,
            "current_phase": self.current_phase,
            "phase1_confirmed": self.phase1_confirmed,
            "stopped": self.stopped,
            "stop_reason": self.stop_reason,
            "updated_at": now_iso(),
            "findings": [_to_jsonable(f) for f in self.findings] or getattr(self, "_raw_findings", []),
            "hypotheses": [_to_jsonable(h) for h in self.hypotheses] or getattr(self, "_raw_hypotheses", []),
            "disclosures": [_to_jsonable(d) for d in self.disclosures] or getattr(self, "_raw_disclosures", []),
        }
        self.state_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def set_phase(self, phase: str) -> None:
        self.current_phase = phase
        self.logger.log_action("phase_transition", {"phase": phase})
        self.save()

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.logger.log_action("finding_added", finding)
        self.save()

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self.hypotheses.append(hypothesis)
        self.logger.log_action("hypothesis_added", hypothesis)
        self.save()

    def add_disclosure(self, record: DisclosureRecord) -> None:
        self.disclosures.append(record)
        self.logger.log_disclosure("disclosure_record", record)
        self.save()

    # --- emergency stop (Hard Constraint 17) ---

    def stop(self, reason: str) -> None:
        """Halt all further activity on this engagement immediately. No
        further proposal, disclosure, or retest action will proceed until
        `resume()` is called explicitly — silence or a topic change never
        counts as resumption."""
        self.stopped = True
        self.stop_reason = reason
        self.logger.log_action("emergency_stop", {"reason": reason})
        self.save()

    def resume(self, reason: str) -> None:
        """Explicit, logged re-authorization. Requires a reason so the
        audit trail shows this was a deliberate human decision, not a
        default."""
        if not reason.strip():
            raise ValueError("resume() requires a non-empty reason — explicit re-authorization only.")
        self.stopped = False
        previous_reason = self.stop_reason
        self.stop_reason = ""
        self.logger.log_action("emergency_resume", {"previous_stop_reason": previous_reason, "resume_reason": reason})
        self.save()

    def assert_not_stopped(self) -> None:
        if self.stopped:
            from .approval import EmergencyStopped

            raise EmergencyStopped(
                f"Engagement is stopped ({self.stop_reason or 'no reason logged'}). "
                f"Re-authorize with `sentinel resume` before any further action."
            )


def create_engagement(engagement_id: str, scope_path: str | Path) -> Engagement:
    scope = load_scope(scope_path)
    eng = Engagement(engagement_id, scope)
    # Snapshot the scope doc into the engagement dir so it can never drift
    # out from under an in-progress engagement (Hard Constraint 15: restate
    # scope at the start of any resumed session from what was actually
    # confirmed, not whatever the source file has been edited to since).
    snapshot = eng.root / "scope_snapshot.yaml"
    snapshot.write_text(Path(scope_path).read_text())
    eng.logger.log_action(
        "engagement_created",
        {
            "id": engagement_id,
            "program_name": scope.program_name,
            "engagement_type": scope.engagement_type.value,
            "scope_source": str(scope_path),
        },
    )
    eng.save()
    return eng


def load_engagement(engagement_id: str, root: Path | None = None) -> Engagement:
    eng_root = (root or ENGAGEMENTS_ROOT) / engagement_id
    scope_snapshot = eng_root / "scope_snapshot.yaml"
    if not scope_snapshot.exists():
        raise FileNotFoundError(
            f"No scope_snapshot.yaml under {eng_root} — was this engagement created with `sentinel init`?"
        )
    scope = load_scope(scope_snapshot)
    return Engagement(engagement_id, scope, root=root)
