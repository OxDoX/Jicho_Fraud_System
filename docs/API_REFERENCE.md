# JFS Real-Time Scoring API Reference

Covers `jicho/realtime_api.py` — the HTTP transport for
`jicho/realtime.py`'s incremental scorer. This is one concrete transport;
the scoring logic itself is transport-agnostic (see
`JFS_CLAUDE_CODE_BUILD_PROMPT.md` Section 8). A production Kafka consumer
would call the same `RealtimeScorer.score_transaction()` method per
message instead of per HTTP request.

**Scope reminder:** this API scores only the 13 account-local rules (see
`RULE_CATALOG.md`, RT column). Rules needing cross-account visibility
(R5, R7, R9, R11, R14) are not evaluated here — those require the periodic
batch run (`run.py`) against the full dataset.

**Deployment note:** the bundled Flask dev server (`app.run(...)`) is for
local development and demos only. Production deployment should run this
behind a WSGI server (gunicorn/uWSGI) and, per the deployment architecture
document, entirely within the institution's own network perimeter — this
API is not intended to be internet-facing.

---

## `GET /health`

Liveness check.

**Response 200:**
```json
{"status": "ok"}
```

---

## `POST /score/transaction`

Scores one transaction against the calling account's rolling window and
returns any alerts fired by account-local rules, plus a **prevention
decision** the calling system can act on before completing the transaction.

**⚠ Prevention is opt-in and off by default.** See "Prevention decisions"
below before integrating against the `decision` field — acting on it
incorrectly (or not acting on it at all, while assuming you are) has real
customer-impact consequences.

**Request body** — a JSON object matching the standard transaction schema
(`jicho/models.py: REQUIRED_COLUMNS`, plus any optional fields the specific
rule needs — see `RULE_CATALOG.md` for which rules need `event_type`,
`card_id`, `merchant_id`, `terminal_id`, `terminal_country`, `auth_mode`,
`entry_mode`, `agent_id`, `initiated_by_staff`):

```json
{
  "transaction_id": "TXN00123",
  "account_id": "ACC2001",
  "transaction_type": "withdrawal",
  "amount": 700000,
  "timestamp": "2026-08-26T09:30:00",
  "channel": "mobile_money",
  "event_type": "transaction"
}
```

Required fields: `transaction_id`, `account_id`, `transaction_type`,
`amount`, `timestamp`, `channel`. Missing `account_id` is rejected at the
API layer before scoring is attempted.

**Response 200** — scoring succeeded (with or without alerts):
```json
{
  "alert_count": 1,
  "alerts": [
    {
      "rule_id": "R1",
      "rule_name": "SIM-Swap Cash-Out",
      "account_id": "ACC2001",
      "transaction_id": "TXN00123",
      "timestamp": "2026-08-26 09:30:00",
      "severity": "CRITICAL",
      "score": 95,
      "description": "Withdrawal of 700,000 occurred 0:30:00 after a SIM/device change on this account.",
      "evidence": {"sim_swap_time": "2026-08-26 09:00:00", "withdrawal_amount": 700000.0}
    }
  ],
  "decision": "BLOCK",
  "decision_reason": "R1 (SIM-Swap Cash-Out) fired at score 95, at or above the institution-approved block threshold (90) for a rule explicitly whitelisted for blocking."
}
```

`decision` is always one of `ALLOW`, `HOLD`, `BLOCK`. Under the untouched
default configuration (`prevention_enabled: false`), `decision` is always
`ALLOW` regardless of what alerts fire — verified directly by scoring the
identical fraud sequence under both an opted-in and a default config and
confirming the decision differs only when prevention is explicitly enabled.

**Response 400** — malformed request (missing `account_id` or not a JSON object):
```json
{"error": "request body must be a transaction object with at least account_id"}
```

**Response 422** — the transaction failed schema validation once combined
with the account's buffered history (e.g. duplicate `transaction_id`,
unknown `transaction_type`, negative `amount`):
```json
{"error": "<TransactionSchemaError message>"}
```

**Side effect:** if a webhook URL has been configured (see below) and any
alerts fired, the alerts are POSTed to that URL asynchronously to the
response. A webhook delivery failure is logged but never affects this
endpoint's response — the transaction has already been scored correctly
regardless of downstream notification success.

**Verified behavior (tested end-to-end during development, not just unit
tested):** a `sim_swap` event scored first correctly returns zero alerts;
a subsequent withdrawal on the same account within the SIM-swap window
correctly returns the R1 alert — proving the incremental/stateful scoring
actually works across separate HTTP calls, not just within one function
call.

---

## `POST /configure/webhook`

Sets (or clears) the URL that fired alerts are POSTed to.

**Request body:**
```json
{"url": "https://fraud-ops.example-bank.co.tz/webhooks/jicho-alerts"}
```

Pass `{"url": null}` to disable webhook dispatch.

**Response 200:**
```json
{"webhook_url": "https://fraud-ops.example-bank.co.tz/webhooks/jicho-alerts"}
```

**Webhook payload delivered to the configured URL** (POST, JSON body):
```json
{"alerts": [ /* same alert object shape as /score/transaction */ ]}
```

---

## Prevention decisions — read this before integrating

`decision` is only meaningful if your integration is **synchronous and
authorization-blocking**: your payment/core-banking system must call
`/score/transaction`, wait for the response, and only complete the
transaction if `decision` permits it. If you call this endpoint
fire-and-forget (e.g. after already committing the transaction, or without
checking the response), you get alerting only — zero prevention benefit —
regardless of what `decision` says.

| Decision | Meaning | Expected caller action |
|---|---|---|
| `ALLOW` | No block-eligible alert fired, or prevention is disabled | Complete the transaction normally |
| `HOLD` | A high-confidence alert fired, but on a rule not whitelisted for blocking | Trigger step-up authentication (OTP/biometric) or route to expedited manual review — do not complete automatically, but do not treat as a confirmed decline either |
| `BLOCK` | An alert fired on a rule explicitly whitelisted by the institution, at or above the block threshold | Decline the transaction and route to fraud ops for immediate review |

**This is opt-in, off by default.** `EngineConfig.prevention_enabled` is
`False` and `block_eligible_rule_ids` is empty until an institution's risk
and compliance function explicitly configures otherwise — see
`JFS_Product_Requirements.docx` Section 9 and the Deployment Architecture
document's change-governance workflow (Section 6) for the expected approval
process. Do not enable blocking for a rule without first measuring that
rule's real-world false-positive rate via `jicho.calibration` against the
institution's own data.

**Fail-safe behavior:** if the decision logic itself errors, the outcome
follows `EngineConfig.prevention_fail_mode` (`"open"` by default —
transaction proceeds, failure logged; or `"closed"` — held pending review).
This is a deliberate, institution-set risk-appetite choice, tested in both
directions, not an incidental default.



| Status | Meaning | Caller action |
|---|---|---|
| 200 | Scored successfully (alerts array may be empty) | Proceed normally |
| 400 | Malformed request | Fix the request body — this is a caller bug |
| 422 | Valid JSON but fails transaction schema validation | Check the specific field named in the error message |
| 5xx | Unhandled server error | Retry with backoff; alert on repeated failure |

## Operational notes

- State is in-memory and per-process. Restarting the service clears all
  account buffers and the deduplication set — any account mid-window at
  restart time will need its window re-established from subsequent
  transactions. A production deployment handling this properly needs a
  shared state store (Redis or similar) instead of the in-memory dict this
  reference implementation uses; that's a scaling change to
  `RealtimeScorer`'s storage, not to the scoring logic itself.
- `RealtimeScorer` retention window is computed automatically from the
  longest lookback any account-local rule needs (with margin) — see
  `RealtimeScorer._compute_retention()`. It updates automatically if
  thresholds are retuned via `jicho/calibration.py`.
