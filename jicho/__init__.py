"""Jicho — explainable fraud detection for East/Central/Southern African financial institutions."""

from jicho.config import EngineConfig, load_config
from jicho.engine import FraudEngine
from jicho.exceptions import ConfigValidationError, JichoError, RuleExecutionError, TransactionSchemaError
from jicho.models import Alert, validate_transactions

__version__ = "0.4.0"

__all__ = [
    "FraudEngine", "EngineConfig", "load_config", "Alert", "validate_transactions",
    "JichoError", "ConfigValidationError", "TransactionSchemaError", "RuleExecutionError",
]
