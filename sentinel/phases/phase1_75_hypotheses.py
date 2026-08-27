"""Phase 1.75 — Novel Attack-Chain Hypothesis Generation.

LLM-only (no target touched). Requires the Phase 1.5 brief to exist so
hypotheses are grounded in sourced material rather than pure recall.
Hypotheses feed Phase 3 under the exact same approval gate as everything
else — nothing here is treated as confirmed.
"""
from __future__ import annotations

import re

from ..engagement import Engagement
from ..llm.client import SentinelLLM
from ..llm.prompts import hypothesis_prompt
from ..models import Hypothesis

_CONFIDENCE_RE = re.compile(r"confidence[:\s]+\s*(low|medium|high)", re.I)
_BLOCK_SPLIT_RE = re.compile(r"\n(?=\d+[.)]\s|Hypothesis\s*\d*[:.])", re.I)


def _parse_hypotheses(text: str) -> list[Hypothesis]:
    blocks = [b.strip() for b in _BLOCK_SPLIT_RE.split(text) if b.strip()]
    hyps = []
    for block in blocks:
        conf_match = _CONFIDENCE_RE.search(block)
        confidence = conf_match.group(1).lower() if conf_match else "unspecified"
        hyps.append(
            Hypothesis(
                primitives=[],  # left empty; full detail lives in `rationale` (raw block text)
                rationale=block,
                confidence=confidence,
                test_plan="(see rationale text for the least-destructive test approach)",
            )
        )
    return hyps


def run(engagement: Engagement, architecture_summary: str, llm: SentinelLLM) -> list[Hypothesis]:
    brief_path = engagement.root / "threat_intel_brief.md"
    threat_intel_brief = brief_path.read_text(encoding="utf-8") if brief_path.exists() else "(no Phase 1.5 brief on file)"

    raw = llm.ask(hypothesis_prompt(architecture_summary, threat_intel_brief), max_tokens=3000)
    hyps = _parse_hypotheses(raw)

    hyps_path = engagement.root / "hypotheses_raw.md"
    hyps_path.write_text(raw, encoding="utf-8")

    for h in hyps:
        engagement.add_hypothesis(h)

    engagement.logger.log_action(
        "hypotheses_generated", {"count": len(hyps), "raw_path": str(hyps_path)}
    )
    engagement.set_phase("1.75_hypotheses_done")
    return hyps
