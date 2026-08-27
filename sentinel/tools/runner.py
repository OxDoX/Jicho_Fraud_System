"""Safe execution of an approved, approved-for-this-action tool.

`run_tool` is only ever called AFTER `sentinel.approval.gate()` has returned
an ApprovalDecision.APPROVED record — callers in phases/phase3_dast.py
enforce that ordering. This module does not re-check approval; it checks
tool provenance (is it actually on disk, is it the registry entry) and
executes exactly what was proposed, no silent modification (system prompt,
Phase 3 step 3).
"""
from __future__ import annotations

import shlex
import shutil
import subprocess

from ..models import ApprovalDecision, ApprovalRecord, ExecutionResult, Proposal
from ..redact import redact
from .registry import ToolSpec, get_tool

DEFAULT_TIMEOUT_SECONDS = 300


class NotApproved(Exception):
    pass


def run_tool(
    proposal: Proposal,
    approval: ApprovalRecord,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> ExecutionResult:
    if approval.proposal_id != proposal.id:
        raise ValueError("approval record does not match this proposal")
    if approval.decision != ApprovalDecision.APPROVED:
        raise NotApproved(f"proposal {proposal.id} was not approved (decision={approval.decision.value})")

    spec: ToolSpec = get_tool(proposal.tool)

    if spec.manual_only:
        drafted = f"{spec.binary} {proposal.args}"
        return ExecutionResult(
            proposal_id=proposal.id,
            approval_id=approval.id,
            raw_output_redacted=f"MANUAL EXECUTION REQUIRED — not auto-run: {drafted}",
            interpretation=(
                f"'{spec.name}' is manual_only ({spec.description}). "
                f"The exact command was drafted for you to run yourself in "
                f"Burp/msfconsole/etc. and paste results back for interpretation."
            ),
            exit_code=None,
        )

    if not shutil.which(spec.binary):
        return ExecutionResult(
            proposal_id=proposal.id,
            approval_id=approval.id,
            raw_output_redacted=f"'{spec.binary}' not found on PATH.",
            interpretation=f"Install it first: {spec.install_hint}",
            exit_code=None,
        )

    cmd = [spec.binary, *shlex.split(proposal.args)]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = redact(proc.stdout)
        stderr = redact(proc.stderr)
        raw = f"$ {' '.join(cmd)}\n[exit={proc.returncode}]\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        return ExecutionResult(
            proposal_id=proposal.id,
            approval_id=approval.id,
            raw_output_redacted=raw,
            interpretation="",  # left for the caller/human to fill in after review
            exit_code=proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            proposal_id=proposal.id,
            approval_id=approval.id,
            raw_output_redacted=f"$ {' '.join(cmd)}\nTIMED OUT after {timeout}s",
            interpretation="Execution exceeded timeout and was terminated.",
            exit_code=None,
        )
    except OSError as e:
        return ExecutionResult(
            proposal_id=proposal.id,
            approval_id=approval.id,
            raw_output_redacted=f"$ {' '.join(cmd)}\nFAILED TO START: {e}",
            interpretation="Command could not be executed.",
            exit_code=None,
        )
