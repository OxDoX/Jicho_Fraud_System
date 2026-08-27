"""Best-effort local checks for whether installed tool template sets look
stale — e.g. nuclei's community templates, which pick up new CVE coverage
constantly. Purely informational and purely local (a directory mtime
check): this never auto-updates anything on its own. It only tells you
when to run the tool's own update command yourself, keeping "the agent
updates itself" scoped to keeping its knowledge current, not to it
silently changing what runs on your machine.
"""
from __future__ import annotations

import time
from pathlib import Path

STALE_AFTER_DAYS = 14

_NUCLEI_TEMPLATE_DIRS = [
    Path.home() / "nuclei-templates",
    Path.home() / ".local" / "nuclei-templates",
    Path.home() / ".config" / "nuclei" / "nuclei-templates",
]


def check_nuclei_templates() -> dict:
    for d in _NUCLEI_TEMPLATE_DIRS:
        if d.exists():
            age_days = (time.time() - d.stat().st_mtime) / 86400
            return {
                "path": str(d),
                "age_days": round(age_days, 1),
                "stale": age_days > STALE_AFTER_DAYS,
            }
    return {
        "path": None,
        "age_days": None,
        "stale": None,
        "note": "no nuclei-templates directory found at known locations — "
        "run `nuclei -update-templates` once to create one",
    }
