"""
Engine orchestrator.

Runs every registered rule against validated transaction data. A rule
that raises is caught, logged with full context, and skipped — it does
not abort the run for every other rule (industrial practice: one bad
rule is a bug ticket, not an outage).
"""

import pandas as pd

from jicho.config import EngineConfig, load_config
from jicho.exceptions import RuleExecutionError
from jicho.logging_config import get_logger, mask_account_id
from jicho.models import Alert, validate_transactions
from jicho.rules import get_registered_rules

logger = get_logger(__name__)


class FraudEngine:
    def __init__(self, config: EngineConfig | None = None, config_path: str | None = None):
        if config is not None and config_path is not None:
            raise ValueError("Pass either config or config_path, not both")
        self.config = config or load_config(config_path)
        self.rules = get_registered_rules()
        logger.info(f"Fraud engine initialized with {len(self.rules)} registered rules: {sorted(self.rules)}")

    def run(self, df: pd.DataFrame) -> list[Alert]:
        """Validates input and runs all registered rules, returning combined alerts."""
        df = validate_transactions(df)
        logger.info(f"Running {len(self.rules)} rules against {len(df)} transactions")

        all_alerts: list[Alert] = []
        for rule_id, rule_cls in sorted(self.rules.items()):
            rule = rule_cls()
            try:
                alerts = rule.evaluate(df, self.config)
                all_alerts.extend(alerts)
                logger.info(f"{rule_id} ({rule.rule_name}): {len(alerts)} alert(s)")
            except Exception as e:
                # A single failing rule must not take down the whole run.
                wrapped = RuleExecutionError(rule_id, e)
                logger.error(str(wrapped), exc_info=True)
                continue

        for alert in all_alerts:
            logger.info(
                f"ALERT {alert.rule_id} severity={alert.severity} score={alert.score} "
                f"account={mask_account_id(alert.account_id)}"
            )

        return sorted(all_alerts, key=lambda a: -a.score)
