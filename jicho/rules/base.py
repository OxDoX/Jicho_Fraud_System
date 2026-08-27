"""
Rule base class and registry.

Rationale (industrial practice): the earlier version was one large class
with one method per rule — functional, but every new rule (including
AI-drafted ones) required editing a shared file and remembering to wire
it into run_all(). This registry pattern means:
  1. Each rule is an independent, independently testable class in its own
     module (see jicho/rules/known_patterns.py).
  2. Adding a rule (hand-written or AI-drafted) means adding one file and
     one @register_rule decorator — no shared-state editing.
  3. A rule that raises an exception is caught and logged as a
     RuleExecutionError without crashing the batch run for every other
     rule — one bad rule can't take down detection entirely.
"""

from abc import ABC, abstractmethod

import pandas as pd

from jicho.config import EngineConfig
from jicho.models import Alert


class Rule(ABC):
    """Base class every detection rule must implement."""

    rule_id: str
    rule_name: str

    @abstractmethod
    def evaluate(self, df: pd.DataFrame, config: EngineConfig) -> list[Alert]:
        """Runs this rule against the transaction data and returns any alerts."""
        raise NotImplementedError


_REGISTRY: dict[str, type[Rule]] = {}


def register_rule(cls: type[Rule]) -> type[Rule]:
    """Class decorator that registers a Rule subclass for engine discovery."""
    if not getattr(cls, "rule_id", None):
        raise ValueError(f"{cls.__name__} must define a class-level rule_id")
    if cls.rule_id in _REGISTRY:
        raise ValueError(f"Duplicate rule_id '{cls.rule_id}' — already registered by {_REGISTRY[cls.rule_id].__name__}")
    _REGISTRY[cls.rule_id] = cls
    return cls


def get_registered_rules() -> dict[str, type[Rule]]:
    return dict(_REGISTRY)
