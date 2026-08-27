"""Timestamped, append-only audit logging (Hard Constraint 12).

Two separate logs per engagement:
  action_log.jsonl      — every proposal, approval/denial, execution, interpretation
  disclosure_log.jsonl  — the Phase 6 clearance chain only

Both are append-only JSONL so the file itself is the reproduction record;
nothing is ever rewritten in place.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from .models import now_iso


def _to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        d = dataclasses.asdict(obj)
        return {k: _to_jsonable(v) for k, v in d.items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    if hasattr(obj, "value") and not isinstance(obj, (str, int, float, bool)):
        # Enum
        return obj.value
    return obj


class EngagementLogger:
    def __init__(self, engagement_dir: str | Path):
        self.dir = Path(engagement_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.action_log = self.dir / "action_log.jsonl"
        self.disclosure_log = self.dir / "disclosure_log.jsonl"

    def _append(self, path: Path, event_type: str, payload: Any) -> None:
        record = {
            "logged_at": now_iso(),
            "event_type": event_type,
            "payload": _to_jsonable(payload),
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def log_action(self, event_type: str, payload: Any) -> None:
        self._append(self.action_log, event_type, payload)

    def log_disclosure(self, event_type: str, payload: Any) -> None:
        self._append(self.disclosure_log, event_type, payload)

    def read_action_log(self) -> list[dict]:
        return self._read(self.action_log)

    def read_disclosure_log(self) -> list[dict]:
        return self._read(self.disclosure_log)

    @staticmethod
    def _read(path: Path) -> list[dict]:
        if not path.exists():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
