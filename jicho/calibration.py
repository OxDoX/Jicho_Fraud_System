"""
Threshold calibration: turns "illustrative" config defaults into
institution-specific, data-driven starting points.

This does NOT auto-apply anything — consistent with every other part of
this codebase, a human (compliance/risk officer, per the CAB workflow in
the deployment architecture doc) reviews the calibration report and
decides what to adopt. What it DOES do is replace guesswork with actual
percentile analysis of the institution's own transaction volumes, and lets
that person see, concretely, how many alerts each candidate threshold
would have produced against real historical data before it goes live.
"""

from dataclasses import dataclass, field

import pandas as pd

from jicho.config import EngineConfig
from jicho.engine import FraudEngine
from jicho.exceptions import ConfigValidationError
from jicho.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ThresholdSuggestion:
    field_name: str
    current_value: float
    suggested_value: float
    basis: str  # human-readable explanation of how the suggestion was derived

    def to_dict(self) -> dict:
        return {
            "field": self.field_name,
            "current": self.current_value,
            "suggested": (
                round(self.suggested_value, 2) if isinstance(self.suggested_value, float) else self.suggested_value
            ),
            "basis": self.basis,
        }


@dataclass
class CalibrationReport:
    suggestions: list[ThresholdSuggestion] = field(default_factory=list)
    alert_count_current: int = 0
    alert_count_suggested: int = 0

    def to_dict(self) -> dict:
        return {
            "suggestions": [s.to_dict() for s in self.suggestions],
            "alert_count_with_current_thresholds": self.alert_count_current,
            "alert_count_with_suggested_thresholds": self.alert_count_suggested,
        }


def _percentile(series: pd.Series, pct: float) -> float:
    return float(series.quantile(pct)) if len(series) else 0.0


def calibrate_amount_thresholds(df: pd.DataFrame, config: EngineConfig) -> list[ThresholdSuggestion]:
    """Suggests amount-based thresholds from the institution's own transaction
    value distribution, rather than the illustrative defaults shipped with
    the engine. Each suggestion uses the percentile that best matches what
    the threshold is meant to represent (e.g. an "unusually large" cash-out
    should sit above the typical range for that transaction type, not be a
    round number picked in the abstract).
    """
    suggestions = []

    withdrawals = df.loc[df["transaction_type"] == "withdrawal", "amount"]
    if len(withdrawals) >= 20:
        p99 = _percentile(withdrawals, 0.99)
        # sim_swap_amount_threshold has Field(gt=0) — a dataset dominated by
        # zero-amount withdrawal rows (e.g. balance checks, or a sim_swap
        # marker event itself logged as a zero-amount withdrawal, as several
        # of this codebase's own test fixtures do) can genuinely pull even a
        # 99th-percentile threshold down to 0. Skip rather than suggest a
        # value the config schema would itself reject — see apply_suggestions()
        # for why this can't be caught silently downstream instead.
        if p99 > 0:
            suggestions.append(ThresholdSuggestion(
                "sim_swap_amount_threshold", config.sim_swap_amount_threshold, p99,
                f"99th percentile of {len(withdrawals)} observed withdrawal amounts — a SIM-swap cash-out "
                "threshold should sit above typical withdrawal size, not an arbitrary round number."
            ))
        else:
            logger.warning(
                "Skipping sim_swap_amount_threshold calibration: 99th percentile of observed withdrawals "
                "is 0, which would violate the field's gt=0 constraint."
            )

    deposits = df.loc[df["transaction_type"].isin(["deposit", "cash_in"]), "amount"]
    if len(deposits) >= 20:
        # NOTE: structuring_threshold is deliberately NOT calibrated from this
        # institution's own deposit distribution. It represents an external
        # regulatory reporting cutoff (e.g. the jurisdiction's AML/CTR
        # threshold), not a statistical property of "typical" deposits here —
        # calibrating it from percentiles conflates two different things and
        # can silently break detection. An earlier version of this function
        # did exactly that: it suggested lowering the threshold to the 90th
        # percentile of observed deposits, which broke the structuring rule
        # entirely in backtesting (confirmed via calibrate()'s alert-count
        # comparison — the exact mechanism this module exists to catch).
        # This threshold must come from the institution's compliance team
        # citing the actual reporting cutoff for their jurisdiction, not from
        # this function.
        pass

    pos_txns = df.loc[df["transaction_type"] == "pos_purchase", "amount"]
    if len(pos_txns) >= 20:
        p25 = _percentile(pos_txns, 0.25)
        # Same reasoning as sim_swap_amount_threshold above: card_testing_amount_threshold
        # also has Field(gt=0), and a lower percentile (25th) is even more likely to land
        # on 0 if the institution logs any zero-amount POS events (e.g. authorization-only
        # or balance-check transactions) — skip rather than suggest an invalid value.
        if p25 > 0:
            suggestions.append(ThresholdSuggestion(
                "card_testing_amount_threshold", config.card_testing_amount_threshold, p25,
                f"25th percentile of {len(pos_txns)} observed POS amounts — card-testing transactions are "
                "characteristically small relative to this institution's typical purchase size, not a fixed value."
            ))
        else:
            logger.warning(
                "Skipping card_testing_amount_threshold calibration: 25th percentile of observed POS "
                "amounts is 0, which would violate the field's gt=0 constraint."
            )

    return suggestions


def calibrate_velocity_thresholds(df: pd.DataFrame, config: EngineConfig) -> list[ThresholdSuggestion]:
    """Suggests count-based thresholds (velocity, structuring frequency) from
    the actual distribution of per-account transaction bursts, so the
    threshold reflects what's actually unusual for this institution's
    customer base rather than a generic guess.
    """
    suggestions = []
    outbound = df[df["transaction_type"].isin(["withdrawal", "transfer_out", "cash_out"])]
    if len(outbound) < 20:
        return suggestions

    window = pd.Timedelta(minutes=config.velocity_window_minutes)
    counts = []
    for _, group in outbound.groupby("account_id"):
        times = sorted(group["timestamp"].tolist())
        for t in times:
            counts.append(sum(1 for other in times if t <= other <= t + window))

    if counts:
        p99 = pd.Series(counts).quantile(0.99)
        suggested = max(int(round(p99)) + 1, config.velocity_txn_count)  # never suggest loosening below a sane floor
        suggestions.append(ThresholdSuggestion(
            "velocity_txn_count", config.velocity_txn_count, suggested,
            f"99th percentile of observed per-account transaction bursts within the "
            f"{config.velocity_window_minutes}-minute window across {len(counts)} observations, "
            "plus one — set just above what this institution's real customers actually do."
        ))

    return suggestions


def apply_suggestions(config: EngineConfig, suggestions: list[ThresholdSuggestion]) -> EngineConfig:
    """Returns a NEW config with suggestions applied — does not mutate the
    original, and does not touch anything the caller didn't explicitly pass.

    Deliberately reconstructs via EngineConfig(...) rather than
    config.model_copy(update=...): Pydantic v2's model_copy applies `update`
    WITHOUT re-validating it, so a suggestion violating its own field's
    constraints (e.g. a Field(gt=0) threshold) would silently produce a
    config instance that fails its own schema — exactly the "bad config
    fails loudly, not silently downstream" guarantee config.py's docstring
    promises, broken by the one function whose entire job is to hand back a
    config a reviewer trusts. The individual calibrate_*_thresholds()
    functions above already avoid generating such a suggestion in the first
    place; this is the defense-in-depth backstop, not the primary fix.
    """
    updates = {s.field_name: s.suggested_value for s in suggestions}
    try:
        return EngineConfig(**{**config.model_dump(), **updates})
    except Exception as e:  # pydantic ValidationError and friends — same wrapping load_config() uses
        raise ConfigValidationError(f"A calibration suggestion produced an invalid config: {e}") from e


def calibrate(df: pd.DataFrame, config: EngineConfig) -> CalibrationReport:
    """Runs full calibration and backtests the suggested thresholds against
    the same historical data, so the report shows concretely how alert
    volume would change — the number a compliance officer actually needs
    to approve a threshold change.
    """
    suggestions = calibrate_amount_thresholds(df, config) + calibrate_velocity_thresholds(df, config)

    current_engine = FraudEngine(config=config)
    current_alerts = current_engine.run(df)

    suggested_config = apply_suggestions(config, suggestions)
    suggested_engine = FraudEngine(config=suggested_config)
    suggested_alerts = suggested_engine.run(df)

    logger.info(
        f"Calibration: {len(suggestions)} threshold(s) suggested; "
        f"alert count {len(current_alerts)} -> {len(suggested_alerts)}"
    )

    return CalibrationReport(
        suggestions=suggestions,
        alert_count_current=len(current_alerts),
        alert_count_suggested=len(suggested_alerts),
    )
