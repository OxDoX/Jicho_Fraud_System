"""
Unsupervised behavioral anomaly detection.

This is the third and last piece of "adapts to emerging threats" described
in the project brief (CLAUDE.md, Section 7). The 18 rules in
jicho/rules/known_patterns.py only catch patterns someone already named and
wrote logic for. This module is different in kind, not degree — it flags
accounts whose behavior is a statistical outlier against the rest of the
portfolio, with no named typology behind it, so a genuinely novel fraud
pattern that doesn't yet match any rule still has a route into the
investigator queue instead of sailing through undetected.

Deliberately NOT a Rule:
    This does not use @register_rule / the Rule ABC in jicho/rules/base.py,
    and FraudEngine.run() does not call it automatically — use
    FraudEngine.detect_anomalies() or detect_anomalies() directly, as an
    explicit separate step. Section 8 of the project brief draws a sharp
    line between reactive detection (rules) and proactive/exploratory
    capability (hunting); this module sits on the hunting side of that
    line — it doesn't know what it's looking for the way a named rule
    does, it just flags "this is unusual" as a hunting lead, and a human
    decides what to do with that. Mixing its output silently into
    engine.run()'s rule alerts would blur that line and make an "N rules
    fired" summary misleading.

Method — explainable, not a black-box model:
    jicho.hunting.FraudHunter.build_profile() already computes named
    behavioral features per account (transaction_count, total_inflow,
    total_outflow, distinct_counterparties) — the same features
    find_similar_accounts() uses. This module computes each feature's
    *modified z-score* (median- and MAD-based, not mean/stdev, because
    transaction volumes are heavily right-skewed and a few genuine
    high-volume accounts would otherwise blow out a mean-based baseline)
    for every account against the rest of the portfolio, using the
    outlier cutoff of 3.5 recommended by Iglewicz, B. and Hoaglin, D.C.
    (1993), "How to Detect and Handle Outliers," ASQC Basic References in
    Quality Control: Statistical Techniques, Vol. 16 — a standard,
    citable statistical reference, not a value tuned against any
    institution's data. An account is flagged if any feature's modified
    z-score exceeds the threshold, and the alert names exactly which
    feature and by how much (e.g. "total_outflow is a statistical outlier
    versus the portfolio median — modified z-score 6.2"), so an
    investigator or auditor can verify the number directly, unlike a
    model's opaque confidence score.

Structural limitation, stated plainly:
    This needs a reasonably sized, reasonably homogeneous portfolio to
    build a meaningful baseline against — it returns no alerts (and logs
    why) below anomaly_min_accounts_for_baseline accounts, and it has no
    concept of *why* a value is unusual beyond "unlike its peers this
    batch." It complements the 18 named rules; it does not replace them,
    and a flagged account is a hunting lead for a human, not a confirmed
    fraud finding. Concretely: sample_data_generator.py's demo data is
    built to plant one clear, extreme example per rule against a thin
    "normal" filler population, not to resemble a real institution's
    smoothly-varying transaction volumes — running this module against
    that demo dataset will flag many more accounts than it would against
    real production traffic, for exactly that reason. That's an honest
    property of the demo data, not a bug to quietly tune away.
"""

from dataclasses import dataclass

import pandas as pd

from jicho.config import EngineConfig
from jicho.hunting import FraudHunter
from jicho.logging_config import get_logger, mask_account_id
from jicho.models import Alert

logger = get_logger(__name__)

# The modified z-score's 0.6745 constant makes it comparable to a standard
# z-score under normality (Iglewicz & Hoaglin, 1993 — see module docstring).
MODIFIED_ZSCORE_CONSTANT = 0.6745

FEATURE_NAMES = ("transaction_count", "total_inflow", "total_outflow", "distinct_counterparties")

ANOMALY_RULE_ID = "ANOMALY"
ANOMALY_RULE_NAME = "Unsupervised Behavioral Anomaly"


@dataclass
class FeatureOutlier:
    feature: str
    value: float
    portfolio_median: float
    modified_z_score: float


def _median(values: list[float]) -> float:
    n = len(values)
    s = sorted(values)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def _modified_z_scores(values: list[float]) -> list[float | None]:
    """Median/MAD-based robust z-scores. Returns None per-value where the
    feature has zero MAD across the portfolio — a constant feature carries
    no information to judge an outlier against, so it's skipped rather than
    dividing by zero.
    """
    median = _median(values)
    mad = _median([abs(v - median) for v in values])
    if mad == 0:
        return [None] * len(values)
    return [MODIFIED_ZSCORE_CONSTANT * (v - median) / mad for v in values]


def _severity_for_score(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    if score >= 75:
        return "HIGH"
    if score >= 60:
        return "MEDIUM"
    return "LOW"


def detect_anomalies(
    df: pd.DataFrame, config: EngineConfig, exclude_accounts: frozenset[str] | set[str] = frozenset()
) -> list[Alert]:
    """Flags accounts whose behavior is a statistical outlier against the
    rest of the portfolio on at least one named feature. See the module
    docstring for method, scope, and why this is deliberately separate
    from the 18 named rules.

    `exclude_accounts` should be the set of account IDs that already have
    a rule-based alert (R1-R18) this run — FraudEngine.detect_anomalies()
    populates this automatically. An account already explained by a named
    rule stays part of the portfolio baseline (its behavior is still real
    data), but is not re-flagged here: doing so would duplicate a finding
    the investigator already has under a misleading "no rule matched"
    framing.
    """
    if not config.anomaly_detection_enabled:
        return []

    hunter = FraudHunter(df)
    account_ids = sorted(df["account_id"].dropna().unique().tolist())
    if len(account_ids) < config.anomaly_min_accounts_for_baseline:
        logger.info(
            f"Anomaly detection skipped: {len(account_ids)} account(s) in this batch, below the "
            f"{config.anomaly_min_accounts_for_baseline}-account minimum needed for a portfolio baseline."
        )
        return []

    profiles = {acct: hunter.build_profile(acct) for acct in account_ids}
    feature_values = {feat: [getattr(profiles[acct], feat) for acct in account_ids] for feat in FEATURE_NAMES}
    feature_medians = {feat: _median(vals) for feat, vals in feature_values.items()}
    feature_zscores = {feat: _modified_z_scores(vals) for feat, vals in feature_values.items()}

    alerts = []
    for idx, acct in enumerate(account_ids):
        if acct in exclude_accounts:
            continue
        outliers: list[FeatureOutlier] = []
        for feat in FEATURE_NAMES:
            z = feature_zscores[feat][idx]
            if z is not None and abs(z) >= config.anomaly_zscore_threshold:
                outliers.append(FeatureOutlier(
                    feature=feat,
                    value=feature_values[feat][idx],
                    portfolio_median=feature_medians[feat],
                    modified_z_score=z,
                ))
        if not outliers:
            continue

        driver = max(outliers, key=lambda o: abs(o.modified_z_score))
        last_txn = df[df["account_id"] == acct].sort_values("timestamp").iloc[-1]
        score = min(100, round(50 + (abs(driver.modified_z_score) - config.anomaly_zscore_threshold) * 10))

        alerts.append(Alert(
            rule_id=ANOMALY_RULE_ID,
            rule_name=ANOMALY_RULE_NAME,
            account_id=acct,
            transaction_id=last_txn["transaction_id"],
            timestamp=str(last_txn["timestamp"]),
            severity=_severity_for_score(score),
            score=score,
            description=(
                f"This account's {driver.feature.replace('_', ' ')} ({driver.value:,.0f}) is a statistical "
                f"outlier against the portfolio median ({driver.portfolio_median:,.0f}) — modified z-score "
                f"{driver.modified_z_score:.1f}. Flagged independently of the 18 named detection rules; this "
                "is a hunting lead for investigator review, not a confirmed finding."
            ),
            evidence={
                "driving_feature": driver.feature,
                "value": driver.value,
                "portfolio_median": driver.portfolio_median,
                "modified_z_score": round(driver.modified_z_score, 2),
                "all_outlier_features": [
                    {"feature": o.feature, "modified_z_score": round(o.modified_z_score, 2)} for o in outliers
                ],
            },
        ))
        logger.info(
            f"ANOMALY: {mask_account_id(acct)} flagged on {driver.feature} "
            f"(modified z-score {driver.modified_z_score:.1f})"
        )

    return sorted(alerts, key=lambda a: -a.score)
