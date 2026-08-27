"""Thin Anthropic API wrapper for the reasoning-only tasks.

Deliberately narrow: this client has no tool-use / function-calling wired
to it, so the model it talks to has no path to execute anything. It only
ever returns text for a human (or the phase modules) to read and act on.
Degrades gracefully with a clear error if no API key is configured, rather
than silently skipping steps.
"""
from __future__ import annotations

import os

from .prompts import SENTINEL_SYSTEM_PROMPT

DEFAULT_MODEL = "claude-sonnet-4-5"


class LLMUnavailable(Exception):
    pass


class SentinelLLM:
    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return self._client
        if not self.api_key:
            raise LLMUnavailable(
                "ANTHROPIC_API_KEY is not set. LLM-assisted steps (threat-intel "
                "synthesis, hypothesis generation, report/disclosure drafting) "
                "are unavailable until it is. Everything else in Sentinel — "
                "scope lock, approval gate, tool execution, logging — works "
                "without it."
            )
        try:
            import anthropic
        except ImportError as e:
            raise LLMUnavailable(
                "The 'anthropic' package is not installed. Run: pip install anthropic"
            ) from e
        self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def ask(self, task_prompt: str, max_tokens: int = 2000) -> str:
        client = self._ensure_client()
        response = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=SENTINEL_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": task_prompt}],
        )
        parts = [block.text for block in response.content if getattr(block, "type", None) == "text"]
        return "\n".join(parts).strip()
