"""
Configuration schema and loader.

Rationale (industrial practice): thresholds should never be hardcoded in
rule logic. Externalizing to a validated YAML file means:
  1. A compliance/risk officer can review and sign off on threshold values
     without reading Python code.
  2. Different institutions (or the same institution over time) can retune
     without a code change or redeploy.
  3. Pydantic validation catches misconfiguration (negative thresholds,
     wrong types) at load time with a clear error, not a silent bad alert
     three steps into a batch run.
"""

import yaml
from pydantic import BaseModel, Field, field_validator

from jicho.exceptions import ConfigValidationError


class EngineConfig(BaseModel):
    sim_swap_window_hours: float = Field(gt=0, default=12)
    sim_swap_amount_threshold: float = Field(gt=0, default=500_000)

    velocity_window_minutes: float = Field(gt=0, default=30)
    velocity_txn_count: int = Field(gt=1, default=4)

    structuring_threshold: float = Field(gt=0, default=10_000_000)
    structuring_window_hours: float = Field(gt=0, default=24)
    structuring_min_txns: int = Field(gt=1, default=3)

    mule_fanin_window_hours: float = Field(gt=0, default=6)
    mule_fanin_sender_count: int = Field(gt=1, default=5)
    mule_outflow_ratio: float = Field(gt=0, le=1, default=0.8)

    agent_cashout_ratio_threshold: float = Field(gt=0, default=3.0)

    offhours_start: int = Field(ge=0, le=23, default=7)
    offhours_end: int = Field(ge=0, le=23, default=20)
    offhours_amount_threshold: float = Field(gt=0, default=2_000_000)

    layering_window_minutes: float = Field(gt=0, default=45)
    layering_hop_count: int = Field(gt=1, default=3)

    dormant_sweep_window_hours: float = Field(gt=0, default=6)
    dormant_sweep_amount_threshold: float = Field(gt=0, default=1_000_000)
    dormant_sweep_ratio: float = Field(gt=0, le=1, default=0.85)

    sync_spike_window_minutes: float = Field(gt=0, default=30)
    sync_spike_account_count: int = Field(gt=1, default=8)

    loan_cashout_window_hours: float = Field(gt=0, default=2)
    loan_cashout_ratio: float = Field(gt=0, le=1, default=0.9)

    fallback_ratio_threshold: float = Field(gt=0, le=1, default=0.015)  # Visa VAMP 2026: 1.5%
    fallback_min_sample_size: int = Field(gt=0, default=5)

    card_testing_window_minutes: float = Field(gt=0, default=20)
    card_testing_amount_threshold: float = Field(gt=0, default=20_000)
    card_testing_min_txns: int = Field(gt=1, default=3)

    impossible_travel_window_hours: float = Field(gt=0, default=3)

    refund_ratio_threshold: float = Field(gt=0, le=1, default=0.3)

    offline_auth_window_hours: float = Field(gt=0, default=4)
    offline_auth_count_threshold: int = Field(gt=1, default=3)

    bec_window_hours: float = Field(gt=0, default=6)
    bec_amount_threshold: float = Field(gt=0, default=1_000_000)

    ato_window_minutes: float = Field(gt=0, default=30)
    ato_amount_threshold: float = Field(gt=0, default=500_000)

    atm_multi_terminal_window_minutes: float = Field(gt=0, default=20)

    # --- Prevention policy (real-time block/hold decisions) ---
    # Deliberately conservative and OFF by default. Blocking a transaction is
    # a fundamentally bigger decision than raising an alert — it can deny a
    # legitimate customer access to their own funds, with real regulatory
    # and reputational consequences if wrong. This must be explicitly
    # enabled and configured by an institution's risk/compliance function,
    # the same CAB-style sign-off already required for any other change to
    # production detection behavior (see the Deployment Architecture
    # document, Section 6) — never enabled unilaterally by an engineer.
    prevention_enabled: bool = Field(default=False)
    # Only rules where the flagged transaction IS the harm-causing outbound
    # movement itself (not a precursor step) belong here — blocking stops
    # the fraud from completing, rather than blocking an innocent earlier
    # transaction based on a pattern that hasn't caused harm yet. Empty by
    # default: an institution must deliberately whitelist rules for this,
    # rule by rule, after reviewing that rule's real-world false-positive
    # rate via jicho.calibration — not on day one of deployment.
    block_eligible_rule_ids: list[str] = Field(default_factory=list)
    block_min_score: int = Field(ge=0, le=100, default=90)
    hold_min_score: int = Field(ge=0, le=100, default=75)
    # "open": if the prevention decision logic itself fails (bug, timeout,
    # scorer unavailable), the transaction proceeds and the failure is
    # logged/alerted for ops follow-up — availability wins over blocking.
    # "closed": the transaction is held pending manual review on any
    # decision-logic failure — safety wins over availability. This is a
    # genuine risk-appetite trade-off for the institution to set, not a
    # technical default to accept blindly; "open" is the conventional
    # choice for customer-facing payment rails, but some institutions or
    # channels may require "closed".
    prevention_fail_mode: str = Field(default="open", pattern="^(open|closed)$")

    # --- Unsupervised anomaly detection (jicho/anomaly.py) ---
    # The one honest gap flagged in the project brief's "adapts to emerging
    # threats" story (Section 7): a layer that flags statistically unusual
    # account behavior even when no named rule matches it. On by default —
    # unlike prevention, a wrong flag here costs an investigator a few
    # minutes of review, not a blocked transaction, so the asymmetry that
    # justifies prevention's off-by-default stance doesn't apply here.
    anomaly_detection_enabled: bool = Field(default=True)
    # Iglewicz & Hoaglin (1993) recommended cutoff for their modified
    # z-score outlier test — a standard, citable statistical reference,
    # not a value tuned against any institution's data.
    anomaly_zscore_threshold: float = Field(gt=0, default=3.5)
    # Below this many distinct accounts in a batch, there isn't a
    # meaningful portfolio baseline to compare any one account against —
    # detect_anomalies() skips rather than flagging on a near-empty sample.
    anomaly_min_accounts_for_baseline: int = Field(gt=1, default=10)

    @field_validator("offhours_end")
    @classmethod
    def _end_after_start(cls, v, info):
        start = info.data.get("offhours_start")
        if start is not None and v <= start:
            raise ValueError("offhours_end must be after offhours_start")
        return v

    model_config = {"extra": "forbid"}  # reject unknown keys instead of silently ignoring typos


def load_config(path: str | None = None) -> EngineConfig:
    """Loads and validates engine config from a YAML file, or defaults if none given.

    Raises:
        ConfigValidationError: if the file is malformed or fails schema validation.
    """
    if path is None:
        return EngineConfig()
    try:
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        return EngineConfig(**raw)
    except FileNotFoundError as e:
        raise ConfigValidationError(f"Config file not found: {path}") from e
    except yaml.YAMLError as e:
        raise ConfigValidationError(f"Malformed YAML in {path}: {e}") from e
    except Exception as e:  # pydantic ValidationError and friends
        raise ConfigValidationError(f"Invalid configuration in {path}: {e}") from e
