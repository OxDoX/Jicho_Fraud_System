# Jicho — Fraud Detection & Alerting System
### Rules-based fraud detection tuned to East & Central African financial fraud typologies

"Jicho" = "the eye" (Swahili). Built as an explainable, auditable rules engine —
compliance teams and bank examiners in this region want to see *why* an alert
fired, not a black-box ML score. This is deliberately rules-first for that reason,
with a clear upgrade path to statistical/ML scoring layered on top later.

## Why these specific rules

Grounded in documented regional fraud patterns (Interpol Africa Cyberthreat
Assessment, GSMA mobile money fraud research, and East African bank fraud
reporting, 2024–2026):

| Rule | Typology | Why it matters here |
|---|---|---|
| R1 | SIM-swap cash-out | Interpol: mobile money fraud is the #1 reported cyber scam across ~97% of surveyed African countries; SIM-swap is the primary enabler in Tanzania/Uganda/Kenya |
| R2 | Velocity spike | Rapid drain of a compromised account before the victim notices |
| R3 | Structuring / smurfing | Splitting deposits to dodge reporting/AML thresholds |
| R4 | Money-mule fan-in / sweep-out | "Money mulling" via fake job ads is flagged by Interpol as a growing regional trend, laundering BEC and scam proceeds |
| R5 | Agent/OTC till anomaly | Agents conducting off-book cash transactions instead of loading customer wallets — a known East African MFS-specific fraud vector |
| R6 | Off-hours insider transaction | Insider collusion is a repeatedly cited driver of large-scale bank fraud in the region (e.g. Equity Bank Kenya case) |
| R7 | Rapid cross-account layering | Funds hopped across accounts fast enough to stay under each institution's individual monitoring threshold |
| R8 | Dormant account sudden inflow + sweep | Southern Africa signature: EFT rails clear on account number alone with no payee-name verification, making single-use mule accounts the dominant fraud pattern (one SA bank alone flagged 64,000+ mule accounts in 14 months) |
| R9 | Synchronized multi-account withdrawal spike | Portfolio-level signal for investment/forex scheme collapse — this typology is consistently the #2 fraud category (after mobile money) across multiple African markets |
| R10 | Loan-app disbursement rapid cash-out | Interpol's Operation Red Card 2.0 named fraudulent mobile loan apps explicitly as a targeted pan-African typology |
| R11 | EMV fallback abuse | Chip cards deliberately damaged to force magstripe fallback, enabling cloned-card use — Visa's VAMP program (April 2026) set 1.5% as the "excessive fallback" merchant threshold, used directly as this rule's default |
| R12 | Card testing pattern | Fraudsters run several small POS transactions on a stolen card to confirm it's live before a larger purchase — a well-documented pre-fraud signature globally, including on cards stolen or cloned in the region |
| R13 | Cross-border card velocity | Same card used at POS terminals in two countries within a window too short for real travel — a cloned-card signature, especially relevant across CEMAC/EAC borders with uneven card-network fraud coordination |
| R14 | Merchant refund anomaly | Abnormally high refund-to-sales ratio at one merchant — return fraud or merchant collusion, a named POS fraud typology distinct from card-present cloning |
| R15 | Offline authorization abuse | Offline/store-and-forward terminal mode skips real-time balance and velocity checks — a widely documented POS/ATM fraud vector once a terminal or network segment goes offline |
| R16 | BEC-pattern payment redirection | The detectable transaction signature of Business Email Compromise: a beneficiary detail change followed by an urgent high-value payment to the new beneficiary — independent of any specific incident, this is the standard BEC fraud pattern documented industry-wide |
| R17 | Credential-phishing account takeover | A flagged suspicious login (new device, new location, impossible-travel login) followed by a large transfer — the generic ATO signature regardless of how credentials were obtained (phishing, malware, or otherwise) |
| R18 | Rapid multi-terminal ATM withdrawal | Domestic analogue of R13 — withdrawals at physically distinct ATMs too fast for real travel, consistent with a cloned card or payment-switch routing abuse |

**Not covered, and deliberately so:** deepfake/AI-driven social engineering (synthetic voices/identities used to bypass verification) is a real and growing threat, but it is **not a transaction-pattern problem** — by the time a deepfake-driven instruction reaches the transaction log, it looks identical to a legitimate one. The actual control for this is procedural: mandatory out-of-band callback verification for beneficiary changes and high-value payment instructions, not a rule in this engine. Saying this plainly to a prospect is more credible than forcing a rule that can't actually catch the thing it claims to.

## Regional coverage — honest map, not a claim of completeness

| Region | Rules that apply well | Known gaps |
|---|---|---|
| East Africa (TZ, KE, UG, RW) | R1–R7, R9, R10 | Deep in mobile money/agent typologies; less tested against bank-only or card-heavy markets |
| Southern Africa (ZA, ZM, ZW) | R8, R9, R2, R6, R7, R11, R12, R13, R14 | Does **not** cover ATM jackpotting (a device/malware attack, not a transaction pattern — needs ATM telemetry monitoring, a different system entirely) |
| Central Africa (CM, CD, CEMAC) | R9, R10, R4, R7, R13 | Cross-border corridor layering across CEMAC's GIMACPAY rail is only partially covered by R7/R13 — true cross-institution, cross-country layering needs a data-sharing agreement or regulator-run shared utility, not something one bank's transaction log alone can see |

This table is the honest pitch: not "we cover all fraud in three regions," but "here's exactly what's covered, why, and what still needs region-specific data or infrastructure we don't have yet." That's also the table to walk through in a client meeting to figure out which rules matter most for their specific market and rails.

## Architecture

```
jicho/                          → installable package
  __init__.py                   → public API
  config.py                     → Pydantic-validated configuration
  exceptions.py                 → typed exception hierarchy
  logging_config.py             → structured JSON logging + PII masking
  models.py                     → Alert model + transaction schema validation
  engine.py                     → orchestrator: runs all registered rules
  hunting.py                    → proactive fraud hunting: search, link analysis, similarity
  hunt_suggestions.py           → bridges detection to hunting: auto-generates leads per alert
  calibration.py                 → data-driven threshold tuning against an institution's own data
  realtime.py                    → incremental real-time scorer (13 account-local rules)
  realtime_api.py                → HTTP transport + webhook dispatch for real-time scoring
  federated_layering.py          → privacy-preserving cross-institution matching primitive
  prevention.py                  → real-time block/hold/allow decisions, off by default, opt-in per rule
  rules/
    base.py                     → Rule ABC + plugin registry
    known_patterns.py           → all 18 detection rules
tests/                          → 23 unit tests (pytest)
config/default_config.yaml      → reviewable, tunable thresholds
run.py                          → CLI entry point
sample_data_generator.py        → synthetic demo data w/ planted patterns
dashboard.html                  → case-management console + AI agents
pyproject.toml                  → packaging + ruff/mypy/pytest config
```

## Running it

```bash
pip install -e .                                    # installs jicho + dependencies
python3 sample_data_generator.py                     # generates data/sample_transactions.csv
python3 run.py --data data/sample_transactions.csv --config config/default_config.yaml
pytest tests/ -v                                      # run the test suite
ruff check jicho/ tests/                              # lint
```

Open `output/dashboard.html` in a browser to triage alerts visually.

## AI agent layer (v0.3)

The rules engine still does all the *detection* — that stays deterministic and
auditable, which is what regulators and bank examiners actually want to see.
Two AI agents sit on top of it, for the parts that genuinely benefit from
language reasoning rather than fixed logic:

- **Per-alert investigation briefs** — click "Generate AI investigation brief"
  on any alert; it produces a short, structured writeup (what happened / why
  it's suspicious / recommended action / what data to pull next), grounded
  strictly in that alert's evidence — it's told explicitly not to invent
  details like names or phone numbers that aren't in the data.
- **"Ask Jicho"** — a natural-language box so a compliance officer can ask
  things like *"which alerts should we investigate first today?"* across the
  whole current alert queue, answered only from that data.
- **Emerging Threat → Draft Detection Rule** — this is the "adapts to new
  fraud scenarios" capability, and it's worth being precise about what it
  actually is: **not** self-learning ML that retrains on live data (that
  needs labeled real fraud cases, which you don't have yet, and shouldn't
  fake). It's an AI-assisted rule-authoring workflow: an analyst describes an
  emerging scenario in plain English (e.g. a new scam-call pattern), and the
  agent drafts a candidate rule — typology summary, plain-language logic,
  a working Python method in the exact style of the existing rules, suggested
  config thresholds, and honest caveats about false-positive risk and what
  real data would be needed to validate it. A human then reviews it, pastes
  it into `rules_engine.py` in the marked spot near `run_all()`, and tests it
  before it ever touches real alerts. This is genuinely valuable — it turns
  "we heard about a new fraud pattern at the last industry working group"
  into a testable rule in minutes instead of a ticket that sits for weeks —
  but it is a drafting assistant, not an autonomous system, and should be
  pitched to clients that way. Overclaiming "self-learning AI" to a bank's
  risk committee is the kind of thing that gets a vendor disqualified once
  someone technical asks a follow-up question.

**Important deployment note:** `dashboard.html` calls the Anthropic API
directly from the browser with no API key — that only works because it's
running inside Claude.ai's artifact sandbox, which proxies the call for you.
To deploy this standalone (e.g. hosted for a real client), route those `fetch`
calls through your own backend that holds the API key server-side — never
ship an API key in client-side HTML. This is a one-function change
(`callClaude()` in `dashboard.html`) once you have that backend.

## Engineering standards this codebase follows

This section exists because "explainable rules" only means something if the
code itself would survive a real due-diligence review. Concretely:

**Architecture**
- Plugin-registry pattern (`jicho/rules/base.py`) — each rule is an independent,
  independently testable class; adding a rule means adding one file, not
  editing shared state.
- Pydantic-validated configuration (`jicho/config.py`) — thresholds live in
  reviewable YAML, never hardcoded, and bad config fails loudly at load time
  with a specific error, not silently downstream.
- Per-rule error isolation (`jicho/engine.py`) — a rule that throws is caught,
  logged with full context, and skipped; it cannot take down detection for
  every other rule in the same run.
- Input schema validation (`jicho/models.py`) — malformed upstream data
  (missing columns, duplicate transaction IDs, unknown types, negative
  amounts) is rejected with a specific `TransactionSchemaError` before it
  ever reaches a rule.

**Testing**
- 79 unit tests (`tests/`) covering every rule's positive case (fires on the
  planted pattern) and negative case (silent on normal activity), config
  validation, schema validation, engine-level fault isolation, the hunting
  module (network traversal, similarity ranking, shared-attribute detection),
  the detection-to-hunting bridge, threshold calibration (including a
  regression test pinning a real bug found during development), the
  real-time incremental scorer (including a regression test on rule
  classification), and the privacy-preserving cross-institution matching
  primitive (including a proof that raw account IDs never appear in an
  exported fingerprint). Run with `pytest tests/ -v`.

**New dependencies for the additions above**
- `flask` and `requests` — the real-time HTTP API and its webhook dispatch.
  Both are used only by `realtime_api.py`; the core batch pipeline has no
  new runtime dependencies.

**Code quality**
- Linted clean with `ruff` (import order, unused imports, line length) —
  `ruff check jicho/ tests/`.
- Type-hinted throughout; `mypy` config included in `pyproject.toml`.
- Packaged as an installable module (`pyproject.toml`, PEP 621) rather than
  loose scripts.

**Security & data protection alignment**
- Structured JSON logging (`jicho/logging_config.py`) with automatic PII
  masking — account IDs are masked in every log line (`ACC2001` → `ACC***01`),
  aligned with data-minimization requirements under Tanzania's Personal Data
  Protection Act (2022) and Kenya's Data Protection Act (2019).
- No secrets or API keys in code — the dashboard's AI-agent calls rely on the
  Claude.ai artifact sandbox's proxy specifically so no key is ever embedded;
  a standalone deployment must hold keys server-side (see AI agent section).
- Relevant control frameworks to map this against during a real vendor
  security review: **ISO/IEC 27001** Annex A.12 (logging/monitoring) and A.14
  (secure development), **NIST Cybersecurity Framework** (Detect function),
  **OWASP ASVS** for the dashboard's web surface, and **FATF Recommendation
  20** (suspicious transaction reporting) for the alerting workflow itself.
  This codebase is aligned with the spirit of these, not formally certified
  against them — that certification is an institution-level process, not a
  codebase property, and should be named accurately in any pitch.

**What's still missing for production (say this upfront to prospects)**
- No CI pipeline configured yet (tests/lint run locally; wiring to GitHub
  Actions or similar is straightforward once this lives in a real repo).
- No encryption-at-rest or access-control layer — this engine assumes it's
  running inside an institution's already-secured environment; it is not
  itself a secured data store.
- No real-time/streaming ingestion — still batch, as noted below.

## Fraud hunting — proactive investigation, not just reactive alerts

Everything above is *reactive*: a rule fires, or it doesn't. Fraud hunting is
the other half — an investigator starting from a lead (a suspicious account,
a tip, a hunch) and actively searching, the way a SOC analyst threat-hunts
rather than just watching a SIEM dashboard. `jicho/hunting.py` provides:

- **`search()`** — ad-hoc filtered queries across any combination of account,
  counterparty, channel, transaction type, agent, device, amount range, and
  time range. The equivalent of a SIEM query for transaction data.
- **`account_network()`** — breadth-first link analysis from a seed account
  outward through the counterparty graph. Tested against the sample data,
  starting from `ACC2006` alone reconstructs the entire 4-account layering
  chain (R7) with zero prior knowledge of the pattern — this is what lets an
  investigator pull a thread from one suspicious account and see the whole
  ring, not just the one transaction a rule happened to flag.
- **`shared_attribute_accounts()`** — finds other accounts sharing a device ID
  or agent ID with a given account. Device/agent reuse across supposedly
  unrelated accounts is one of the strongest fraud-ring indicators there is;
  legitimate customers don't normally share a phone or an agent till with
  strangers.
- **`find_similar_accounts()`** — given a confirmed fraud case, ranks other
  accounts by behavioral similarity (transaction count, inflow/outflow
  volume, counterparty spread). Deliberately **not** a black-box embedding —
  it's explainable distance over named features, so a finding can be
  justified to an investigator or auditor in plain terms: "flagged because
  it has almost identical deposit/withdrawal volume and counterparty count
  to the confirmed case," not "the model said so."

This is the piece that lets the system catch things the rules engine's fixed
typologies were never written for — an investigator with a lead can find a
whole network the same afternoon, instead of waiting for enough of that
network's individual transactions to separately trip a rule.

### Auto-suggested hunts — bridging detection and investigation

The rules engine and the hunting module used to be separate: a rule fires,
and the investigator has to think of what to hunt next themselves. 
`jicho/hunt_suggestions.py` closes that gap — **every fired alert
automatically comes with hunting leads attached**, tailored to that alert's
typology rather than a generic checklist:

- **R7 (layering)** hunts the account network out to 5 hops — deliberately
  further than the 3-hop threshold that triggered detection, on the logic
  that a ring rarely stops exactly where the rule's threshold does. Tested
  against the sample data: the alert fires on a 3-hop chain, but the attached
  hunt lead correctly surfaces the 4th account one hop further out.
- **R5 (agent till anomaly)** hunts the *agent's* full till activity, not
  just the one flagged transaction — the fraud may well be the agent, not
  the customer.
- **R8 (dormant sweep)** hunts where the swept funds went next, plus shared
  device/agent — is this a one-off, or part of a wider mule network?
- Any rule not explicitly listed (including a brand-new rule drafted through
  the AI rule-authoring workflow) automatically gets a sensible default
  strategy — network, shared device, shared agent, similar accounts — so
  hunting support isn't something you have to remember to wire up for every
  new rule.

This shows up in `dashboard.html` as a "Suggested hunts" section on every
alert card, and in the CLI/JSON output as a `suggested_hunts` field on each
alert. The point isn't to replace an investigator's judgment — it's to make
sure the first five minutes of every investigation start from "here's what's
connected" instead of a blank search box.

## Turning this into income — realistic next steps

1. **Portfolio/demo asset first.** This synthetic-data version is safe to show
   prospects (banks, MFIs, SACCOs, PSPs) without touching real customer data —
   use it as a live demo in sales conversations.
2. **Pilot with one institution.** Approach a mid-size bank, MFI, or PSP (not
   a tier-1 bank first — faster procurement cycles) to run this against a
   read-only copy of historical transactions and show real detections.
3. **Package as either:**
   - a one-time build + customization engagement ($3–15k depending on
     institution size and integration complexity), or
   - a monthly-retainer managed alerting service you run for smaller MFIs/SACCOs
     that can't afford an in-house fraud team.
4. **Add real data connectors** as pilots progress: core banking system exports,
   mobile money CDR/API feeds, or a simple file-drop ingestion for institutions
   without APIs.
5. **Layer in ML scoring later** (e.g. isolation forest / gradient boosting on
   engineered features) once you have enough labeled real alerts to train on —
   keep the rules layer as the explainable backbone regulators will want to see.
6. **Compliance angle:** position this explicitly as supporting Bank of
   Tanzania / BOU / CBK AML/CFT reporting obligations — that's the budget line
   this actually gets purchased from.

## Prevention — blocking fraud in progress, not just alerting on it

Detection and alerting tell an investigator what happened. Prevention
(`jicho/prevention.py`) is different in kind, not just degree: it returns a
decision the calling payment/core-banking system can act on **before** a
transaction completes, so a fraudulent withdrawal or transfer can be
stopped rather than just logged.

This is worth being careful about, because the risk profile is genuinely
different. An alert that turns out to be a false positive costs an
investigator a few minutes. A block decision that turns out to be wrong
denies a real customer access to their own money — a direct harm, a likely
complaint, and potentially a regulatory issue, since timely availability of
funds is often a legal obligation rather than a service-quality nicety.
Everything about how this module is built follows from that asymmetry:

- **Off by default.** `EngineConfig.prevention_enabled` is `False` out of
  the box. Verified directly: the exact same SIM-swap-then-withdrawal fraud
  pattern that produces a `BLOCK` decision under an opted-in config produces
  `ALLOW` under the untouched default config — prevention cannot
  accidentally activate.
- **Rule-by-rule opt-in, not a global switch.** `block_eligible_rule_ids`
  starts empty. An institution's risk/compliance function must explicitly
  whitelist a rule for blocking — the intended workflow is: enable
  alerting only first, measure that rule's real-world false-positive rate
  via `jicho.calibration`, and only then approve it for blocking. This
  mirrors the same CAB-style human-sign-off principle already required for
  AI-drafted rules and cloud-distributed updates elsewhere in this project.
- **Three outcomes, not two.** `BLOCK` is deliberately the narrow, hard-to-
  reach outcome. A high-confidence alert on a rule NOT whitelisted for
  blocking returns `HOLD` — step-up authentication or expedited manual
  review, not an outright decline. Only a whitelisted rule at or above
  `block_min_score` (default 90) returns `BLOCK`. Multiple alerts on one
  transaction take the most severe outcome (`BLOCK` > `HOLD` > `ALLOW`).
- **Only rules where the flagged transaction IS the harm** are sensible
  block candidates — e.g. R1's cash-out withdrawal, R16's redirected
  transfer, R17's post-takeover transfer. Blocking these specific
  transactions stops the fraud from completing. A rule that fires on an
  earlier, non-harmful precursor step would be the wrong thing to block on.
- **Fails safe, deliberately configurably so.** `decide_safely()` wraps the
  decision logic; if it errors, the transaction's fate follows
  `prevention_fail_mode` — `"open"` (default, availability wins, the
  transaction proceeds and the failure is logged for ops follow-up) or
  `"closed"` (safety wins, held pending review). This is a genuine
  risk-appetite choice for the institution, not a default to accept
  blindly — tested explicitly in both directions.
- **Integration is synchronous, and that's on the caller.** The
  `/score/transaction` endpoint (`jicho/realtime_api.py`) returns `decision`
  alongside alerts, but prevention only works if the calling payment system
  actually waits for and acts on that field before completing the
  transaction. A caller that logs the decision without acting on it gets
  alerting only, with zero prevention benefit, no matter what this endpoint
  returns — this is stated plainly in the endpoint's docstring, not left to
  be discovered by an integrator the hard way.

Verified end-to-end over real HTTP requests (not just unit-tested in
isolation): a SIM-swap event followed by a large withdrawal correctly
returns `BLOCK` under an opted-in policy with R1 whitelisted, and correctly
returns `ALLOW` for the identical sequence under the untouched default
config.



The three limitations below were originally flagged as open gaps. Each now
has real, tested code addressing it — but it's worth being precise about
what each addition actually closes versus what remains a genuine boundary,
rather than declaring "fixed" and moving on.

**Threshold calibration (`jicho/calibration.py`)** — thresholds are no
longer just illustrative defaults with no path forward. `calibrate()` takes
an institution's own historical transaction data and suggests data-driven
thresholds from actual percentile analysis, then backtests the suggestions
against the same data so a reviewer sees the before/after alert count
before approving anything (consistent with the CAB regression-test step in
the deployment architecture doc). One real finding from building this: an
early version calibrated `structuring_threshold` from the institution's own
deposit percentiles and it *broke* detection in backtesting — that
threshold represents an external regulatory reporting cutoff, not a
statistical property of this institution's deposits, and conflating the two
silently dropped a real structuring alert. That's now a permanent
regression test (`test_calibration_never_suggests_structuring_threshold_from_deposit_percentiles`)
so it can't quietly come back. Calibration still requires human review
before any suggested threshold goes to production — it removes the
guesswork, not the sign-off step.

**Real-time scoring (`jicho/realtime.py`, `jicho/realtime_api.py`)** — a
working incremental scorer and HTTP API now exist, tested end-to-end
(SIM-swap event over HTTP → correctly silent → large withdrawal 30 minutes
later over HTTP → R1 fires, matching the batch engine exactly). Be precise
about scope: this covers the 13 rules that only need one account's own
recent history (verified against each rule's actual grouping key, not
assumed — this exercise caught two more real bugs: R4 and R18 were
wrongly excluded as "not account-local" when they're actually fine, and R11
was wrongly included when it's merchant-level and needs cross-account
visibility). Rules keyed by agent_id, merchant_id, a cross-account chain, or
a portfolio-wide window (R5, R7, R9, R11, R14) still need the periodic batch
run — an in-memory per-account buffer structurally cannot see across
accounts. The HTTP API is a concrete, runnable v2 delivery mechanism; the
scoring logic itself is transport-agnostic, so swapping in a real Kafka
consumer loop for production is a delivery-mechanism change, not a rewrite.

**Cross-institution layering (`jicho/federated_layering.py`)** — this is
the one where the honest answer is that the core limitation is NOT solved,
and can't be solved by code alone, because it's a legal/regulatory
constraint (institutions comparing notes on shared customers requires a
data-sharing agreement or a regulator-run utility) rather than a technical
one. What's built instead is the privacy-preserving matching primitive that
makes the system technically ready the moment such an agreement exists: a
salted-hash scheme where two institutions' layering fingerprints can be
matched to reveal a shared cross-institution chain WITHOUT either side's
raw account numbers ever appearing in the comparison. This is proven to
work in tests (a chain hopping from a Bank A fingerprint set to a Bank B
fingerprint set is correctly matched using only hashes), and proven to
preserve privacy (raw account IDs are asserted absent from every exported
fingerprint). It is explicitly not a live integration with any regulator
system and should never be pointed at another institution's real data
without that institution's contractual agreement — doing so wouldn't
solve the privacy problem, just relocate it.

