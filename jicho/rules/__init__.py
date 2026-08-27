"""
Importing this subpackage registers all built-in rules via their
@register_rule decorators. New rules (hand-written or AI-drafted) should
be added as new modules here and imported below.
"""

from jicho.rules import known_patterns  # noqa: F401  (import triggers registration)
from jicho.rules.base import Rule, get_registered_rules, register_rule

__all__ = ["Rule", "get_registered_rules", "register_rule"]
