"""
HTTP transport for the real-time scorer, plus webhook dispatch on alert.

This is one concrete transport. The scoring logic in jicho/realtime.py is
transport-agnostic by design — swapping this Flask app for a Kafka consumer
loop in production means writing a consumer that calls
`scorer.score_transaction(message)` per message instead of per HTTP request;
the detection logic itself does not change. That's the point of the
separation: this file is the "v2" delivery mechanism made concrete and
runnable, not just described in a roadmap bullet.
"""

import requests
from flask import Flask, jsonify, request

from jicho.config import load_config
from jicho.logging_config import get_logger
from jicho.prevention import decide_safely
from jicho.realtime import RealtimeScorer

logger = get_logger(__name__)

app = Flask(__name__)
_scorer = RealtimeScorer(load_config())
_webhook_url: str | None = None  # set via configure_webhook() or the /configure endpoint


def configure_webhook(url: str | None) -> None:
    global _webhook_url
    _webhook_url = url


def _dispatch_webhook(alerts: list) -> None:
    if not _webhook_url or not alerts:
        return
    payload = {"alerts": [a.__dict__ for a in alerts]}
    try:
        requests.post(_webhook_url, json=payload, timeout=5)
    except requests.RequestException as e:
        # A webhook delivery failure must never affect the scoring response
        # already returned to the caller — it's logged for ops follow-up,
        # not raised, since the transaction has already been scored correctly
        # regardless of whether the downstream notification succeeded.
        logger.error(f"Webhook dispatch failed: {e}")


@app.route("/score/transaction", methods=["POST"])
def score_transaction():
    """Scores one transaction in real time and returns a prevention decision
    (ALLOW/HOLD/BLOCK) alongside any alerts. Expects a JSON body matching
    the standard transaction schema (see jicho.models.REQUIRED_COLUMNS).

    IMPORTANT for integrators: prevention is only meaningful if the calling
    payment/core-banking system actually waits for this response and acts on
    `decision` BEFORE completing the transaction — this is a synchronous
    authorization-path integration, not a fire-and-forget notification. A
    caller that logs `decision` without acting on it gets alerting only,
    with no prevention benefit, regardless of what this endpoint returns.
    """
    txn = request.get_json(force=True)
    if not txn or "account_id" not in txn:
        return jsonify({"error": "request body must be a transaction object with at least account_id"}), 400

    try:
        alerts = _scorer.score_transaction(txn)
    except Exception as e:
        logger.error(f"Scoring failed: {e}")
        return jsonify({"error": str(e)}), 422

    decision = decide_safely(alerts, _scorer.config)
    _dispatch_webhook(alerts)

    return jsonify({
        "alerts": [a.__dict__ for a in alerts],
        "alert_count": len(alerts),
        "decision": decision.decision.value,
        "decision_reason": decision.reason,
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/configure/webhook", methods=["POST"])
def configure_webhook_endpoint():
    body = request.get_json(force=True) or {}
    configure_webhook(body.get("url"))
    return jsonify({"webhook_url": _webhook_url})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
