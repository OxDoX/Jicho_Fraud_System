"""`sentinel doctor` — a readiness check, not a claim.

Everything in sentinel/ is testable and tested without any of this: the
approval gate, scope lock, redaction, and audit logging all work with zero
external setup. What actually varies machine-to-machine is (1) whether an
LLM key is configured, and (2) which of the approved open-source tools are
actually installed. This module answers both questions concretely instead
of leaving them as an assertion in a README.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .scope import ScopeError, load_scope
from .tools.registry import list_tools


@dataclass
class ToolStatus:
    name: str
    category: str
    installed: bool
    manual_only: bool
    install_hint: str


@dataclass
class DoctorReport:
    api_key_set: bool
    anthropic_importable: bool
    tool_statuses: list[ToolStatus] = field(default_factory=list)
    scope_path: str | None = None
    scope_valid: bool | None = None
    scope_error: str | None = None
    scope_program_name: str | None = None

    @property
    def installed_count(self) -> int:
        return sum(1 for t in self.tool_statuses if t.installed or t.manual_only)

    @property
    def total_count(self) -> int:
        return len(self.tool_statuses)

    @property
    def llm_ready(self) -> bool:
        return self.api_key_set and self.anthropic_importable


def _check_tool(spec) -> ToolStatus:
    # manual_only tools (Burp, Metasploit, ...) are never run by the
    # subprocess runner, so "installed" doesn't apply the same way — they
    # just need to exist on the human's machine when they go use them.
    installed = spec.manual_only or shutil.which(spec.binary) is not None
    return ToolStatus(
        name=spec.name,
        category=spec.category,
        installed=installed,
        manual_only=spec.manual_only,
        install_hint=spec.install_hint,
    )


def run_diagnostics(scope_path: str | Path | None = None) -> DoctorReport:
    report = DoctorReport(
        api_key_set=bool(os.environ.get("ANTHROPIC_API_KEY")),
        anthropic_importable=importlib.util.find_spec("anthropic") is not None,
        tool_statuses=[_check_tool(spec) for spec in list_tools()],
    )

    if scope_path is not None:
        report.scope_path = str(scope_path)
        try:
            scope = load_scope(scope_path)
            report.scope_valid = True
            report.scope_program_name = scope.program_name
        except ScopeError as e:
            report.scope_valid = False
            report.scope_error = str(e)

    return report


def format_report(report: DoctorReport) -> str:
    lines = ["=== Sentinel readiness check ===", ""]

    lines.append("LLM (threat-intel synthesis, hypotheses, suggest, report/disclosure drafting):")
    if report.api_key_set:
        lines.append("  ✓ ANTHROPIC_API_KEY is set")
    else:
        lines.append("  ✗ ANTHROPIC_API_KEY is not set — LLM-assisted commands will refuse to run")
    if report.anthropic_importable:
        lines.append("  ✓ anthropic package importable")
    else:
        lines.append("  ✗ anthropic package not installed — pip install anthropic (or: pip install -e '.[llm]')")
    lines.append(f"  -> LLM features ready: {report.llm_ready}")
    lines.append("")

    lines.append(f"Approved tools: {report.installed_count}/{report.total_count} installed or manual-drafted")
    by_category: dict[str, list[ToolStatus]] = {}
    for t in report.tool_statuses:
        by_category.setdefault(t.category, []).append(t)
    for category, tools in sorted(by_category.items()):
        lines.append(f"  [{category}]")
        for t in sorted(tools, key=lambda x: x.name):
            if t.manual_only:
                mark = "~"
                note = "manual_only — drafted for you, install on your own schedule"
            elif t.installed:
                mark = "✓"
                note = "installed"
            else:
                mark = "✗"
                note = f"not on PATH — {t.install_hint}"
            lines.append(f"    {mark} {t.name}: {note}")
    lines.append("")

    if report.scope_path is not None:
        lines.append(f"Scope doc: {report.scope_path}")
        if report.scope_valid:
            lines.append(f"  ✓ loads correctly (program: {report.scope_program_name})")
        else:
            lines.append(f"  ✗ {report.scope_error}")
        lines.append("")
    else:
        lines.append("Scope doc: none checked — pass --scope <path> to validate one")
        lines.append("")

    missing_hard = [t.name for t in report.tool_statuses if not t.installed and not t.manual_only]
    lines.append("Next steps:")
    if not report.llm_ready:
        lines.append("  - set ANTHROPIC_API_KEY (and `pip install anthropic`) to enable LLM-assisted commands")
    if missing_hard:
        lines.append(f"  - install whichever of these {len(missing_hard)} tools you actually plan to use (see hints above)")
    if report.scope_path is None:
        lines.append("  - write a real scope.yaml for your actual authorized engagement (see examples/scope.example.yaml) and pass --scope to validate it")
    if report.llm_ready and not missing_hard and report.scope_valid:
        lines.append("  - none — this machine is ready for a real engagement")

    return "\n".join(lines)
