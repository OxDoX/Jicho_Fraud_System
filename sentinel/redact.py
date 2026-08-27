"""Redaction of PII, tokens, and credentials (Hard Constraint 11).

Applied to every piece of tool output before it is logged, printed, or put
into a report. Default behavior fully masks the secret value; pass
keep_edges=True to retain only its first/last 4 characters, for the rare
case a report needs to show *that* a value matched without disclosing it.
Where a pattern is a label=value pair (api_key=..., password=...), only the
value is masked — the label stays legible so the report is still readable.
"""
from __future__ import annotations

import re

_FULL_MASK_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # aws_access_key
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),  # jwt
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email
    re.compile(r"\b(?:\d[ -]*?){13,16}\b"),  # credit_card
]

# (label_group_pattern, value_group_pattern) combined into one regex with
# two named groups so the label can be preserved and only the value masked.
_LABELED_VALUE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(?P<label>aws_secret_access_key\s*[:=]\s*['\"]?)(?P<value>[A-Za-z0-9/+=]{40})(?P<trail>['\"]?)"),
    re.compile(r"(?i)(?P<label>bearer\s+)(?P<value>[A-Za-z0-9._~+/-]{10,}=*)(?P<trail>)"),
    re.compile(
        r"(?i)(?P<label>\b(?:api[_-]?key|api[_-]?secret|access[_-]?token|client[_-]?secret)\b\s*[:=]\s*['\"]?)"
        r"(?P<value>[A-Za-z0-9._-]{8,})(?P<trail>['\"]?)"
    ),
    re.compile(r"(?i)(?P<label>\bpass(?:word)?\b\s*[:=]\s*['\"]?)(?P<value>[^\s'\"]{4,})(?P<trail>['\"]?)"),
]


def _masked_value(value: str, keep_edges: bool) -> str:
    if not keep_edges or len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:4]}…[REDACTED]…{value[-4:]}"


def redact(text: str, keep_edges: bool = False) -> str:
    if not text:
        return text
    redacted = text
    for pattern in _LABELED_VALUE_PATTERNS:
        redacted = pattern.sub(
            lambda m: f"{m.group('label')}{_masked_value(m.group('value'), keep_edges)}{m.group('trail')}",
            redacted,
        )
    for pattern in _FULL_MASK_PATTERNS:
        redacted = pattern.sub(lambda m: _masked_value(m.group(0), keep_edges), redacted)
    return redacted


def redact_dict(data: dict, keep_edges: bool = False) -> dict:
    out = {}
    for k, v in data.items():
        if isinstance(v, str):
            out[k] = redact(v, keep_edges)
        elif isinstance(v, dict):
            out[k] = redact_dict(v, keep_edges)
        elif isinstance(v, list):
            out[k] = [redact(i, keep_edges) if isinstance(i, str) else i for i in v]
        else:
            out[k] = v
    return out
