"""
Backend proxy for dashboard.html's AI-agent calls (investigation briefs,
"Ask Jicho", and the emerging-threat rule drafter).

Why this exists: `dashboard.html` calls the Anthropic Messages API directly
from the browser with no API key baked in. That only works inside the
Claude.ai artifact sandbox, which proxies the call for you — a standalone
deployment (see README.md's "Important deployment note" and CLAUDE.md
Section 5) must never ship a real API key in client-side HTML. This module
is that backend: it holds the key server-side and forwards the exact same
request shape the dashboard already sends ({system, messages, max_tokens,
model}), so pointing a standalone deployment at it is a one-constant
change in dashboard.html (see AI_PROXY_URL there), not a rewrite of the
AI-agent code.

This is a thin, transparent proxy, not a redesign: it injects the
server-held API key as a header and returns Anthropic's response verbatim.
It enforces one safety bound (a hard cap on max_tokens) since that's the
only protection this reference implementation adds against a misbehaving
or compromised client running up API spend. Everything else — who is
allowed to reach this endpoint at all — is the institution's own
network/auth perimeter, per the deployment architecture document's
on-premises model. This proxy is NOT itself an authentication layer and
must not be exposed outside that perimeter.

Also serves dashboard.html at `/` — deliberately, not incidentally: a
dashboard opened as a `file://` page (or from any other origin) making a
cross-origin fetch() to this proxy gets silently blocked by the browser's
CORS policy, since this app sends no `Access-Control-Allow-Origin` header
(adding one would mean any site reachable from an institution's internal
network could call an endpoint that spends real API credits — worse than
the problem being solved). Serving both from the same origin sidesteps
CORS entirely: run this file, open http://localhost:5001/, and set
dashboard.html's `AI_PROXY_URL` to the relative path `/api/claude`.
"""

import os

import requests
from flask import Flask, jsonify, request, send_from_directory

from jicho.logging_config import get_logger

logger = get_logger(__name__)

ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-4-6"
MAX_TOKENS_CAP = 4000
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)


@app.route("/", methods=["GET"])
def serve_dashboard():
    return send_from_directory(REPO_ROOT, "dashboard.html")


def _get_api_key() -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. This proxy holds the Anthropic API key "
            "server-side on behalf of dashboard.html's AI agents — set it in the "
            "environment before starting this process; never hardcode it here."
        )
    return api_key


@app.route("/api/claude", methods=["POST"])
def proxy_claude():
    """Forwards a Messages API request to Anthropic, injecting the
    server-held API key. Body shape matches what dashboard.html's
    callClaude() already sends: {system, messages, max_tokens, model}.
    """
    body = request.get_json(force=True, silent=True)
    if not body or "messages" not in body:
        return jsonify({"error": "request body must include a 'messages' array"}), 400

    payload = {
        "model": body.get("model", DEFAULT_MODEL),
        "max_tokens": min(int(body.get("max_tokens", 1000)), MAX_TOKENS_CAP),
        "messages": body["messages"],
    }
    if "system" in body:
        payload["system"] = body["system"]

    try:
        api_key = _get_api_key()
    except RuntimeError as e:
        logger.error(str(e))
        return jsonify({"error": "AI proxy is not configured on the server"}), 500

    try:
        upstream = requests.post(
            ANTHROPIC_MESSAGES_URL,
            json=payload,
            headers={
                "x-api-key": api_key,
                "anthropic-version": ANTHROPIC_API_VERSION,
                "content-type": "application/json",
            },
            timeout=30,
        )
    except requests.RequestException as e:
        logger.error(f"Upstream request to Anthropic failed: {e}")
        return jsonify({"error": "Could not reach the Anthropic API"}), 502

    return jsonify(upstream.json()), upstream.status_code


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "anthropic_key_configured": bool(os.environ.get("ANTHROPIC_API_KEY"))})


if __name__ == "__main__":
    _get_api_key()  # fail fast and loudly if misconfigured, before serving any request
    app.run(host="127.0.0.1", port=5001)
