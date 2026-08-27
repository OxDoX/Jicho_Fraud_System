"""
Structured (JSON) logging with PII masking.

Standards alignment:
- Tanzania Personal Data Protection Act (2022) and Kenya Data Protection
  Act (2019) both require minimizing exposure of personal data in
  processing systems, including logs. Account IDs are masked by default
  in all log output — full IDs stay in the alert records passed to the
  authenticated dashboard/API layer, never in plaintext logs.
- ISO/IEC 27001 Annex A.12.4 (Logging and monitoring) expects log
  integrity and controlled content — structured JSON logs are easier to
  ship to a SIEM and to redact/rotate/retain per policy than free-text
  print() output.
"""

import json
import logging
import re
from datetime import datetime, timezone


def mask_account_id(account_id: str) -> str:
    """Masks an account identifier for safe logging, e.g. ACC2001 -> ACC***01."""
    if not account_id or len(account_id) < 4:
        return "***"
    return account_id[:3] + "***" + account_id[-2:]


class PIIMaskingFilter(logging.Filter):
    """Masks account-ID-like tokens in log messages before they're emitted."""

    _ACCOUNT_PATTERN = re.compile(r"\b([A-Z]{2,10}\d{3,10})\b")

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self._ACCOUNT_PATTERN.sub(
                lambda m: mask_account_id(m.group(1)), record.msg
            )
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def get_logger(name: str = "jicho") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        handler.addFilter(PIIMaskingFilter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
