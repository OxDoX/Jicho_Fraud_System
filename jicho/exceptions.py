"""
Custom exception hierarchy.

Rationale (industrial practice): a fraud engine that fails silently or
raises bare Exception/ValueError makes incident review and audit trails
much harder. Every failure mode here is a distinct, catchable type so
calling code (API layer, batch job, monitoring) can react appropriately
and log the exact failure category.
"""


class JichoError(Exception):
    """Base class for all Jicho fraud-engine errors."""


class ConfigValidationError(JichoError):
    """Raised when engine configuration fails schema validation."""


class TransactionSchemaError(JichoError):
    """Raised when input transaction data does not match the required schema."""


class RuleExecutionError(JichoError):
    """Raised when an individual rule fails during execution.

    Wraps the original exception so the failing rule can be identified and
    disabled/reviewed without crashing the whole batch run.
    """

    def __init__(self, rule_id: str, original_exception: Exception):
        self.rule_id = rule_id
        self.original_exception = original_exception
        super().__init__(f"Rule {rule_id} failed: {original_exception}")
