"""Sentinel — an approval-gated bug bounty / pentest AI agent.

Every action that touches a live target is proposed, then gated through
sentinel.approval.gate() for a fresh human decision, then executed by
sentinel.tools.runner.run_tool() and logged by sentinel.logging_utils.
The LLM (sentinel.llm) is only ever used for reasoning tasks that do not
touch a target: threat-intel synthesis, novel hypothesis generation, SAST
triage narration, and report/disclosure drafting.
"""

__version__ = "0.1.0"
