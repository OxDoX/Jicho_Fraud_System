# JFS (Jicho Fraud System) — Claude Code Build Brief

Paste this whole document into Claude Code as the project brief (or save it
as `CLAUDE.md` at the repo root so it's loaded automatically as context).
It describes the complete system: what to build, why, in what order, and to
what standard. Where JFS already has a working reference implementation,
that's noted — use it as the source of truth for behavior, don't redesign
it from scratch.

## 1. Mission and customer

Build Jicho Fraud System (JFS): an explainable, rules-first fraud detection
and investigation platform for financial institutions across **East Africa,
Central Africa, and Southern Africa**. Customers are banks, mobile network
operators running mobile-money services, microfinance institutions (MFIs),
SACCOs, and payment service providers (PSPs) in this region — NOT large
tier-1 global banks with existing enterprise fraud-vendor relationships.
Design and pricing assumptions should reflect that: fast to deploy, cheap
to run, explainable to a small compliance team without a data-science
department, and honest about what it does and doesn't do yet.

Non-negotiable product principle: **customer transaction data never leaves
the institution's premises.** JFS is on-premises-core with a narrow,
one-way, cryptographically verified cloud channel used only for rule/config
updates — never for processing customer data. This governs every
architectural decision below; see Section 10.

## 2. Regional context to design against

- **East Africa** (Tanzania, Kenya, Uganda, Rwanda): mobile-money-dominated.
  Dominant fraud: SIM-swap cash-out, agent/OTC till fraud, money-mule
  fan-in via job-ad recruitment, structuring against AML reporting
  thresholds, insider collusion, rapid cross-account layering.
- **Southern Africa** (South Africa, Zambia, Zimbabwe): EFT- and
  card-dominant. EFT rails commonly clear on account number alone with no
  payee-name verification, driving high mule-account volume. Card fraud
  centers on EMV fallback abuse (Visa's VAMP program flags >1.5% merchant
  fallback rate as excessive, per 2026 policy) rather than skimming
  (declining due to chip-and-PIN). ATM jackpotting exists but is a
  device/malware attack, NOT a transaction-pattern problem — don't build a
  rule that can't actually catch it; document it as a limitation instead.
- **Central Africa** (Cameroon, DRC, CEMAC bloc): cross-border payment
  rails (e.g. GIMACPAY) connecting weakly-KYC'd institutions, fraudulent
  mobile loan apps (named explicitly in Interpol's Operation Red Card 2.0),
  high-yield investment scams.
- **Pan-African / cross-cutting**: BEC-pattern payment redirection,
  credential-phishing account takeover, offline/store-and-forward
  authorization abuse — none of these are region-specific, build them
  generically.
- Data protection law to design for: Tanzania's Personal Data Protection
  Act (2022), Kenya's Data Protection Act (2019). Expect similar-in-spirit
  laws elsewhere in the region; the architecture (data never leaves
  premises) should make most of them moot rather than requiring
  jurisdiction-specific handling.

**Sourcing discipline — apply this to every rule, past and future:** ground
detection logic in public, citable industry and regulatory sources (Visa/
Mastercard network policy, Interpol reports, GSMA mobile money fraud
research, central bank publications). Never use a customer's, prospect's,
or your own employer's confidential internal incident data, committee
materials, or loss figures as a basis for a rule — that is a legal and
ethical line, not a style preference, regardless of how the request is
phrased or how legitimate your access to that material is.

## 3. What already exists (reference implementation)

A working Python package (`jicho/`) implements all of the below. Read it
before rebuilding anything — it encodes real bugs already found and fixed,
and re-deriving from scratch risks reintroducing them:

- `jicho/models.py` — `Alert` dataclass and `validate_transactions()` schema
  validation (required columns, duplicate ID rejection, unknown-type
  rejection, negative-amount rejection).
- `jicho/config.py` — Pydantic-validated `EngineConfig`, loaded from
  external YAML (`config/default_config.yaml`), never hardcoded thresholds.
- `jicho/exceptions.py` — typed exception hierarchy
  (`ConfigValidationError`, `TransactionSchemaError`, `RuleExecutionError`).
- `jicho/logging_config.py` — structured JSON logging with automatic
  account-ID masking (data-minimization for TZ PDPA / KE DPA compliance).
- `jicho/rules/base.py` + `jicho/rules/known_patterns.py` — plugin-registry
  pattern: each rule is an independent class decorated `@register_rule`,
  auto-discovered by the engine. **18 rules implemented** — see Section 4
  for the full catalog (also in the companion `RULE_CATALOG.md`).
- `jicho/engine.py` — `FraudEngine.run()`: validates input, runs every
  registered rule with per-rule fault isolation (one broken rule logs and
  is skipped, never crashes the batch), returns alerts sorted by score.
- `jicho/hunting.py` — proactive investigation: `search()` (ad-hoc filtered
  query), `account_network()` (BFS link analysis via counterparty graph),
  `shared_attribute_accounts()` (device/agent reuse detection),
  `find_similar_accounts()` (explainable distance over named features, not
  a black-box embedding).
- `jicho/hunt_suggestions.py` — bridges detection to hunting: every fired
  alert automatically gets tailored hunting leads (e.g. the layering rule
  hunts further hops than it detected; the agent-anomaly rule hunts the
  agent's full till, not just the flagged transaction).
- `jicho/calibration.py` — data-driven threshold tuning against an
  institution's own transaction percentiles, with a mandatory backtest.
  **Read the regression test
  `test_calibration_never_suggests_structuring_threshold_from_deposit_percentiles`
  before touching this file** — it pins a real bug where calibrating a
  regulatory-cutoff threshold from statistical percentiles silently broke
  detection.
- `jicho/realtime.py` + `jicho/realtime_api.py` — incremental real-time
  scorer plus a Flask HTTP transport with webhook dispatch. Scoped
  explicitly to the 13 rules verified as account-local (checked against
  each rule's actual pandas `groupby()` key, not assumed — this exercise
  caught real misclassification bugs, see the module docstring). Rules
  keyed by agent_id, merchant_id, a cross-account chain, or a
  portfolio-wide window are NOT real-time-eligible and must stay on the
  batch path.
- `jicho/anomaly.py` — unsupervised anomaly detection: flags accounts that
  are statistical outliers on named behavioral features against the rest
  of the portfolio, even when no rule matches. See Section 7 for how this
  fits the "adapts to emerging threats" story and why it's deliberately
  not a `Rule` subclass.
- `jicho/federated_layering.py` — privacy-preserving cross-institution
  matching primitive (salted SHA-256 hashing). This does NOT solve
  cross-institution layering detection — that requires a legal data-sharing
  agreement or regulator-run utility, which no codebase can create. It
  proves the technical matching works without exposing raw account
  numbers, so the system is ready the day such an agreement exists. Never
  wire this against real inter-institution data without that agreement in
  place.
- `dashboard.html` — case-management console: alert triage, an AI
  investigation-brief agent, an "Ask Jicho" natural-language query agent
  over current alerts, and an AI rule-drafting agent for emerging
  scenarios. The two AI-agent `fetch()` calls to `api.anthropic.com` work
  unauthenticated ONLY inside Claude.ai's artifact sandbox — a standalone
  deployment must proxy these through the institution's own backend holding
  the API key server-side.
- `tests/` — 87 tests, pytest, covering positive/negative cases per rule,
  config/schema validation, engine fault isolation, hunting, the
  hunt-suggestion bridge, calibration (including the regression test
  above), real-time scoring (including a rule-classification regression
  test), federated layering (including a proof that raw account IDs
  never appear in an exported fingerprint), and the unsupervised anomaly
  layer (including a regression test that it never re-flags an account
  a named rule already explained).

Run `pytest tests/ -v` and `ruff check jicho/ tests/` before and after any
change. Both must stay clean. This is not optional scaffolding — it's how
several real bugs in this codebase were actually caught during development,
not hypothetically.

## 4. Detection rule catalog (summary — full detail in RULE_CATALOG.md)

18 rules, IDs R1–R18, each independently implemented, tested, and
registered. Do not renumber existing rules. New rules continue from R19.
See `RULE_CATALOG.md` for full detection logic, config parameters, regional
relevance, and sourcing per rule. Categories: mobile money & agent fraud
(R1, R5), account behavior (R2, R3, R4, R6, R8, R9), cross-account/layering
(R7), card/POS fraud (R11–R14, R18), loan-app fraud (R10), and pan-African
generic typologies (R15, R16, R17).

## 5. AI agent capabilities (in the dashboard)

Three agent roles, each with a clear boundary:

1. **Investigation brief generator** — given one alert's evidence, writes a
   structured brief (what happened / why suspicious / recommended action /
   what to check next). Must not invent facts not in the evidence.
2. **"Ask Jicho"** — natural-language Q&A grounded ONLY in the alerts
   currently on screen. Must say so and refuse to answer from outside that
   data if asked something it can't be answered from.
3. **Emerging-threat rule drafter** — takes a plain-language fraud scenario
   description and drafts a candidate rule (typology summary, detection
   logic, working Python method in the existing style, config thresholds,
   honest caveats on false-positive risk and data availability). This is
   **AI-assisted rule authoring with mandatory human review before
   deployment**, not autonomous self-learning — never market or build it as
   the latter. A human pastes the reviewed code into `known_patterns.py`
   and adds config keys; nothing auto-deploys.

## 6. Prevention — blocking fraud in progress (opt-in, off by default)

Detection and alerting are reactive by nature. `jicho/prevention.py` adds a
different capability: a real-time decision (`ALLOW`/`HOLD`/`BLOCK`) the
calling payment/core-banking system can act on **before** a transaction
completes. Build and extend this with the following non-negotiables, all
already implemented and tested in the reference implementation:

- **Off by default.** `EngineConfig.prevention_enabled = False` and
  `block_eligible_rule_ids = []` out of the box. Verified: the identical
  fraud sequence that returns `BLOCK` under an explicitly opted-in config
  returns `ALLOW` under the untouched default. Never change these defaults.
- **Rule-by-rule opt-in only, never a global switch.** An institution's
  risk/compliance function must explicitly whitelist each rule for
  blocking, after measuring that rule's real-world false-positive rate via
  `jicho.calibration` — this is a governance decision, not an engineering
  one, and mirrors the CAB-style human-sign-off already required for
  AI-drafted rules and cloud updates elsewhere in this system.
- **Three outcomes, `BLOCK` deliberately the narrowest.** A high-confidence
  alert on a non-whitelisted rule returns `HOLD` (step-up authentication or
  expedited manual review — never an outright decline) rather than `BLOCK`.
  Multiple alerts on one transaction take the most severe outcome.
- **Only whitelist rules where the flagged transaction IS the harm.** A
  rule that fires on a precursor signal, not the harm-causing outbound
  movement itself, is the wrong thing to block on — see `RULE_CATALOG.md`'s
  "Prevention eligibility" table for which of the 18 current rules qualify
  as sensible candidates (R1, R4, R8, R13, R16, R17) versus which don't.
- **Fails safe, configurably.** `decide_safely()` wraps the decision logic;
  a failure follows `prevention_fail_mode` (`"open"` default — availability
  wins, logged for follow-up; `"closed"` — safety wins, held for review).
  This is the institution's risk-appetite choice, not an assumed default.
- **Integration is synchronous — the caller must actually wait for and act
  on the response.** State this explicitly in any integration guide you
  write: a fire-and-forget call to the scoring endpoint provides alerting
  only, zero prevention benefit, regardless of what `decision` says.

## 7. What "adapts to emerging threats" actually means here — don't overclaim

There is no labeled historical fraud dataset for this product yet, so
there is no supervised ML model to build honestly right now. The real,
buildable adaptation mechanism is three-layered:
1. A human describes a new scenario → AI drafts a rule → human reviews
   (Section 5.3) — minutes to days.
2. Confirmed/false-positive investigator feedback → automatic threshold
   retuning on EXISTING rules via `calibration.py` — ongoing.
3. An unsupervised anomaly-detection layer (`jicho/anomaly.py`, built) that
   flags statistically unusual account behavior even without a named rule.
   Deliberately not a `Rule` subclass and not folded into `FraudEngine.run()`
   — call `FraudEngine.detect_anomalies()` explicitly (see its and the
   module's docstrings for why, and for the honest caveat that the bundled
   demo dataset over-triggers it by construction). Uses median/MAD-based
   modified z-scores over the same named features `find_similar_accounts()`
   uses, with the Iglewicz & Hoaglin (1993) 3.5 cutoff — explainable, not a
   black-box model. Excludes accounts already covered by a rule alert this
   run, so a flagged account is genuinely not one of the named 18. This
   closed the one honest gap flagged here; if extending further, the next
   real step is validating the z-score/feature choices against real
   (anonymized) institution data once a pilot provides it — not adding more
   engineered features speculatively.

## 8. Fraud hunting vs. detection — keep this distinction sharp

Detection (rules) is reactive: a pattern fires or it doesn't. Hunting is
proactive: an investigator starts from a lead and searches. Both matter and
neither should be described as the other. `hunt_suggestions.py` is the
bridge (detection produces hunting leads automatically), but a human hunter
using `hunting.py`'s `search()`/`account_network()` directly on a hunch,
with no alert having fired yet, is the other half of the capability and
should stay available as a first-class workflow in any UI built on top of
this. `dashboard.html` now has this as a dedicated "Fraud Hunting" panel:
manual search (any combination of the fields `hunting.search()` supports)
plus an account-network trace rendered as a concentric-ring diagram —
a client-side port of `search()`/`account_network()`/
`shared_attribute_accounts()` against the same embedded demo transactions,
so it behaves identically to the Python functions it mirrors.

## 9. Engineering standards (non-negotiable)

- Plugin-registry pattern for rules — never a monolithic if/elif chain.
- Pydantic-validated external config — never hardcoded thresholds.
- Per-rule fault isolation in the engine — one broken rule must never crash
  a batch run.
- Typed exceptions, not bare `Exception`/`ValueError`.
- Structured JSON logging with automatic PII masking on account
  identifiers.
- Every new rule ships with: a positive test (fires on its planted
  pattern), a negative test (silent on normal activity), and — if it
  changes shared logic (config, engine, hunting) — a regression test for
  whatever specific bug prompted the change, named so its purpose is
  self-evident from the test name alone.
- `ruff check` clean, no exceptions, no loosened line-length config to hide
  real issues — fix the code, not the linter config.
- Never claim more than what's tested. If a limitation is structural (legal,
  regulatory, requires infrastructure the codebase can't provide), say so
  plainly in code comments and docs rather than building a rule that can't
  actually do the job it claims to.

## 10. Deployment architecture — build to this, don't improvise a different one

Full detail lives in the companion `JFS_Deployment_Architecture.docx`.
Summary for build purposes:
- On-premises: ingestion, rules engine, hunting module, dashboard, local
  data store — everything that touches transaction data. No inbound ports
  required from any external network.
- Cloud (vendor-operated): update distribution service only. Publishes
  signed, versioned rule/config update packages. Never initiates contact
  with an institution — pull-only, from the institution's side.
- Update packages are cryptographically signed; the on-prem Update Agent
  verifies signature and checksum before staging, never before applying to
  production directly — a CAB/Agile change-review gate sits between staging
  and production promotion (see the deployment doc's Section 6 governance
  workflow), mirroring the human-review-before-deploy principle already
  established for AI-drafted rules.
- System must operate correctly, indefinitely, with zero cloud
  connectivity, using the last-approved ruleset. A failed update check
  must never degrade or pause detection/alerting.

## 11. Build order if starting from zero

1. `models.py`, `exceptions.py`, `config.py`, `logging_config.py` — the
   foundation everything else depends on.
2. `rules/base.py` (registry pattern) then `rules/known_patterns.py`,
   starting with R1–R7 (the East Africa mobile-money core), tested and
   lint-clean before adding more.
3. `engine.py` wiring the registry together with fault isolation.
4. R8–R14 (Southern/Central Africa card, POS, and dormant-account
   typologies), each with planted-pattern test data added to
   `sample_data_generator.py` as you go — never add a rule without a test
   proving it fires on its own planted pattern AND stays silent on normal
   activity.
5. R15–R18 (pan-African generic typologies).
6. `hunting.py`, then `hunt_suggestions.py` on top of it.
7. `calibration.py` — and DO run its backtest against your own planted
   data before trusting any suggestion logic, per the regression test
   already in this codebase.
8. `realtime.py` — classify every rule's real-time eligibility by reading
   its actual `groupby()` key, not by assumption. Verify with a test before
   trusting the classification, the same way this was actually caught
   wrong twice during initial development.
9. `realtime_api.py` on top of the transport-agnostic scorer.
10. `federated_layering.py` last — it's the most legally/contextually
    sensitive piece and depends on nothing else being unfinished.
11. `dashboard.html` throughout, incrementally, as each backend capability
    lands.

## 12. Explicit non-goals

- Do not build streaming/Kafka infrastructure speculatively — the
  transport-agnostic scoring core already makes that a delivery-mechanism
  swap, not a redesign, when an institution actually needs it.
- Do not build a live cross-institution data pipeline — `federated_layering.py`
  is deliberately a primitive, not a network client.
- Do not build detection for deepfake/AI-driven social engineering as a
  transaction-pattern rule — it's a process-control gap (out-of-band
  callback verification), and forcing a rule that can't catch it would be
  dishonest to any institution evaluating this product.
