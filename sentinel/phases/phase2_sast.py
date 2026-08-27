"""Phase 2 — SAST (Static Analysis). No approval gate: this never sends a
request to a live target, it only reads local code/IaC/containers.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess

from ..engagement import Engagement
from ..llm.client import LLMUnavailable, SentinelLLM
from ..llm.prompts import sast_triage_prompt
from ..models import Finding, ProposalSource
from ..redact import redact
from ..tools.registry import get_tool

DEFAULT_SAST_TIMEOUT = 600


def run_sast_tool(tool_name: str, args: str, timeout: int = DEFAULT_SAST_TIMEOUT) -> dict:
    spec = get_tool(tool_name)
    if not spec.sast:
        raise ValueError(f"'{tool_name}' is not registered as a sast tool — refusing to run it here.")
    if not shutil.which(spec.binary):
        return {"tool": tool_name, "error": f"'{spec.binary}' not on PATH. Install: {spec.install_hint}"}

    cmd = [spec.binary, *shlex.split(args)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "tool": tool_name,
            "cmd": " ".join(cmd),
            "exit_code": proc.returncode,
            "stdout": redact(proc.stdout),
            "stderr": redact(proc.stderr),
        }
    except subprocess.TimeoutExpired:
        return {"tool": tool_name, "cmd": " ".join(cmd), "error": f"timed out after {timeout}s"}


def run(
    engagement: Engagement,
    tool_runs: list[tuple[str, str]],  # [(tool_name, args), ...]
    llm: SentinelLLM | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for tool_name, args in tool_runs:
        result = run_sast_tool(tool_name, args)
        engagement.logger.log_action("sast_run", result)

        if "error" in result:
            print(f"[{tool_name}] {result['error']}")
            continue

        raw_output = result["stdout"] or result["stderr"]
        triage_text = raw_output
        if llm is not None:
            try:
                triage_text = llm.ask(sast_triage_prompt(tool_name, raw_output[:8000]))
            except LLMUnavailable:
                pass  # fall back to raw output, still useful

        finding = Finding(
            title=f"{tool_name} findings — {engagement.scope.program_name}",
            source=ProposalSource.BASELINE,
            tool=tool_name,
            asset="(local codebase)",
            cvss=None,
            cvss_reasoning="Not scored — SAST triage output; score per confirmed finding after DAST verification.",
            reproduction_steps=[f"Run: {result['cmd']}"],
            evidence_redacted=triage_text[:4000],
            impact="(triage pending human review)",
            remediation="(see triage output for suggested Phase 3 confirmation step)",
        )
        findings.append(finding)
        engagement.add_finding(finding)

    engagement.set_phase("2_sast_done")
    return findings
