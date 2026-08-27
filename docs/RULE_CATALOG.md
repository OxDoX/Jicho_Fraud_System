# JFS Rule Catalog — Complete Reference

18 detection rules, each an independently registered class in
`jicho/rules/known_patterns.py`. All thresholds below are the illustrative
defaults in `config/default_config.yaml` — see `jicho/calibration.py` for
tuning them against a real institution's own data before production use.

Legend: **RT** = real-time eligible (account-local, per `jicho/realtime.py`).
**Region** = where the underlying research grounding this rule is strongest,
not an exclusivity claim — most rules generalize.

---

## R1 — SIM-Swap Cash-Out
**Region:** East Africa | **Severity:** CRITICAL (score 95) | **RT:** Yes

**Typology:** Fraudster fraudulently ports/replaces a victim's SIM, receives
their mobile-money OTPs, and drains the account before the victim notices.
Interpol reports mobile money fraud as the #1 reported cyber scam across
~97% of surveyed African countries, with SIM-swap as the primary enabler in
Tanzania/Uganda/Kenya.

**Logic:** A `sim_swap` event on an account, followed within
`sim_swap_window_hours` (12h) by a withdrawal ≥ `sim_swap_amount_threshold`
(500,000).

**Config:** `sim_swap_window_hours`, `sim_swap_amount_threshold`

---

## R2 — Velocity Spike
**Region:** Generic | **Severity:** HIGH (75) | **RT:** Yes

**Typology:** Rapid-fire outbound transactions draining a compromised
account before the victim or bank can react.

**Logic:** ≥ `velocity_txn_count` (4) outbound transactions (withdrawal/
transfer_out/cash_out) on one account within `velocity_window_minutes` (30).

**Config:** `velocity_window_minutes`, `velocity_txn_count`

---

## R3 — Structuring / Smurfing
**Region:** Generic / AML | **Severity:** MEDIUM (60) | **RT:** Yes

**Typology:** Splitting deposits into amounts just under a regulatory
reporting threshold to avoid AML/CTR filing.

**Logic:** ≥ `structuring_min_txns` (3) deposits between 60–100% of
`structuring_threshold` (10,000,000) within `structuring_window_hours` (24).

**Config:** `structuring_threshold`, `structuring_window_hours`,
`structuring_min_txns`

**⚠ Calibration warning:** `structuring_threshold` represents an EXTERNAL
regulatory reporting cutoff, not a statistical property of this
institution's deposits. `jicho/calibration.py` deliberately never suggests
a value for this field — an earlier version did, calibrated it from deposit
percentiles, and it silently broke detection in backtesting. This must be
set from the institution's actual jurisdiction-specific AML/CTR threshold,
supplied by compliance, not derived from data.

---

## R4 — Money-Mule Fan-In / Sweep-Out
**Region:** East Africa | **Severity:** CRITICAL (90) | **RT:** Yes

**Typology:** An account receives funds from many distinct senders (often
recruited via fake job ads — an Interpol-flagged regional trend) then
rapidly sweeps most of it out, laundering scam/BEC proceeds.

**Logic:** ≥ `mule_fanin_sender_count` (5) distinct senders within
`mule_fanin_window_hours` (6h), followed by outflow ≥ `mule_outflow_ratio`
(80%) of the inflow total within the same window.

**Config:** `mule_fanin_window_hours`, `mule_fanin_sender_count`,
`mule_outflow_ratio`

---

## R5 — Agent Till Cash-Out Anomaly
**Region:** East Africa | **Severity:** HIGH (70) | **RT:** No (agent_id-keyed, needs cross-account visibility)

**Typology:** A mobile-money agent conducts off-book cash transactions
instead of loading customer wallets — an MFS-specific fraud vector.

**Logic:** An agent's cash-out volume ≥ `agent_cashout_ratio_threshold`
(3.0×) its cash-in volume.

**Config:** `agent_cashout_ratio_threshold`

---

## R6 — Off-Hours Staff-Initiated Transaction
**Region:** Generic | **Severity:** HIGH (80) | **RT:** Yes

**Typology:** Insider collusion — staff-initiated transactions outside
business hours are a repeatedly cited driver of large-scale bank fraud
regionally.

**Logic:** A staff-initiated transaction ≥ `offhours_amount_threshold`
(2,000,000) outside the `offhours_start`–`offhours_end` window (07:00–20:00).

**Config:** `offhours_start`, `offhours_end`, `offhours_amount_threshold`

---

## R7 — Rapid Cross-Account Layering
**Region:** Generic / cross-border | **Severity:** CRITICAL (92) | **RT:** No (cross-account chain by design)

**Typology:** Funds hopped across ≥3 accounts fast enough to stay under any
single institution's monitoring threshold.

**Logic:** ≥ `layering_hop_count` (3) sequential transfer hops within
`layering_window_minutes` (45) of each other.

**Config:** `layering_window_minutes`, `layering_hop_count`

**Known limitation:** only sees transfers within one institution's own
data. Cross-institution layering needs `jicho/federated_layering.py` PLUS a
legal data-sharing agreement or regulator-run utility — the module proves
the technical matching works, it does not create the agreement.

---

## R8 — Dormant Account Sudden Inflow + Sweep
**Region:** Southern Africa | **Severity:** CRITICAL (93) | **RT:** Yes

**Typology:** Southern Africa's EFT rails commonly clear on account number
alone with no payee-name verification, making "victim sends to mule
account, mule immediately drains it once" the dominant fraud pattern there.
Differs from R4: a SINGLE large inflow to a previously inactive account,
not a fan-in from many senders.

**Logic:** An account's first-ever recorded activity is an inflow ≥
`dormant_sweep_amount_threshold` (1,000,000), followed by outflow ≥
`dormant_sweep_ratio` (85%) within `dormant_sweep_window_hours` (6h).

**Config:** `dormant_sweep_window_hours`, `dormant_sweep_amount_threshold`,
`dormant_sweep_ratio`

---

## R9 — Synchronized Multi-Account Withdrawal Spike
**Region:** Pan-African | **Severity:** HIGH (78) | **RT:** No (portfolio-wide)

**Typology:** Portfolio-level, not account-level: investment/forex scams
are consistently the #2 fraud category (after mobile money) across African
markets. When a scheme collapses, many unrelated accounts try to withdraw
in the same short window.

**Logic:** ≥ `sync_spike_account_count` (8) distinct accounts attempting
withdrawals within `sync_spike_window_minutes` (30).

**Config:** `sync_spike_window_minutes`, `sync_spike_account_count`

**Note:** alerts with `account_id == "PORTFOLIO"` — there is no single
account to attach a hunting lead to; a human must identify which specific
accounts to investigate first.

---

## R10 — Loan-App Disbursement Rapid Cash-Out
**Region:** Central Africa / Pan-African | **Severity:** HIGH (82) | **RT:** Yes

**Typology:** Interpol's Operation Red Card 2.0 named fraudulent mobile
loan apps explicitly as a targeted pan-African typology.

**Logic:** A `loan_disbursement` transaction, ≥ `loan_cashout_ratio` (90%)
of which is cashed out within `loan_cashout_window_hours` (2h).

**Config:** `loan_cashout_window_hours`, `loan_cashout_ratio`

---

## R11 — EMV Fallback Abuse
**Region:** Southern Africa | **Severity:** HIGH (76) | **RT:** No (merchant_id-keyed, needs cross-account visibility)

**Typology:** Chip cards deliberately damaged to force magstripe fallback,
enabling cloned-card use even at chip-capable terminals. Visa's VAMP
program (April 2026) set 1.5% as the "excessive fallback" merchant
threshold — used directly as this rule's default.

**Logic:** A merchant's magstripe-fallback rate ≥ `fallback_ratio_threshold`
(1.5%) across ≥ `fallback_min_sample_size` (5) card-present transactions.

**Config:** `fallback_ratio_threshold`, `fallback_min_sample_size`

---

## R12 — Card Testing Pattern
**Region:** Generic | **Severity:** HIGH (79) | **RT:** Yes (with caveat)

**Typology:** Fraudsters run several small POS transactions on a stolen
card to confirm it's live before a larger purchase.

**Logic:** ≥ `card_testing_min_txns` (3) POS transactions ≤
`card_testing_amount_threshold` (20,000) on one card within
`card_testing_window_minutes` (20).

**Config:** `card_testing_window_minutes`, `card_testing_amount_threshold`,
`card_testing_min_txns`

**RT caveat:** correct for the common case where a card belongs to one
account; would miss the rare case where the same card_id appears under a
different account_id record.

---

## R13 — Cross-Border Card Velocity
**Region:** Central Africa (CEMAC/EAC border seams) | **Severity:** CRITICAL (91) | **RT:** Yes (with caveat)

**Typology:** Same card used at POS terminals in two countries within a
window too short for real travel — a cloned-card signature, especially
relevant across borders with uneven card-network fraud coordination.

**Logic:** Same card, two different `terminal_country` values, within
`impossible_travel_window_hours` (3h).

**Config:** `impossible_travel_window_hours`

**RT caveat:** correct for the common case where a card belongs to one
account; would miss the rare case where the same card_id appears under a
different account_id record — same caveat as R12, since both group by
`card_id` rather than `account_id`.

---

## R14 — Merchant Refund Anomaly
**Region:** Generic POS | **Severity:** MEDIUM (64) | **RT:** No (merchant_id-keyed, needs cross-account visibility)

**Typology:** Abnormally high refund-to-sales ratio at one merchant —
return fraud or merchant collusion.

**Logic:** A merchant's refund total ≥ `refund_ratio_threshold` (30%) of
its sales total.

**Config:** `refund_ratio_threshold`

---

## R15 — Offline Authorization Abuse
**Region:** Generic POS/ATM | **Severity:** HIGH (81) | **RT:** Yes

**Typology:** Offline/store-and-forward terminal mode skips real-time
balance and velocity checks — a documented fraud vector once a terminal or
network segment goes offline.

**Logic:** ≥ `offline_auth_count_threshold` (3) offline-authorized
transactions on one account within `offline_auth_window_hours` (4h).

**Config:** `offline_auth_window_hours`, `offline_auth_count_threshold`

---

## R16 — BEC-Pattern Payment Redirection
**Region:** Generic | **Severity:** CRITICAL (89) | **RT:** Yes

**Typology:** The detectable transaction signature of Business Email
Compromise: a beneficiary detail change followed by an urgent high-value
payment to the new beneficiary. Built from the standard, publicly
documented BEC pattern — independent of any specific incident.

**Logic:** A `beneficiary_change` event followed within `bec_window_hours`
(6h) by a transfer_out ≥ `bec_amount_threshold` (1,000,000).

**Config:** `bec_window_hours`, `bec_amount_threshold`

---

## R17 — Credential-Phishing Account Takeover
**Region:** Generic | **Severity:** CRITICAL (88) | **RT:** Yes

**Typology:** A flagged suspicious login (new device, new location,
impossible-travel login) followed by a large transfer — the generic ATO
signature regardless of how credentials were obtained.

**Logic:** A `suspicious_login` event followed within `ato_window_minutes`
(30) by a transfer/withdrawal ≥ `ato_amount_threshold` (500,000).

**Config:** `ato_window_minutes`, `ato_amount_threshold`

---

## R18 — Rapid Multi-Terminal ATM Withdrawal
**Region:** Generic / payment-switch | **Severity:** HIGH (84) | **RT:** Yes

**Typology:** Domestic analogue of R13 — withdrawals at physically distinct
ATMs too fast for real travel, consistent with a cloned card or
payment-switch routing abuse.

**Logic:** Same account, two different `terminal_id` values, within
`atm_multi_terminal_window_minutes` (20).

**Config:** `atm_multi_terminal_window_minutes`

---

## Explicitly not covered — and why

**Deepfake / AI-driven social engineering:** a real and growing threat, but
NOT a transaction-pattern problem. By the time a deepfake-driven payment
instruction reaches the transaction log, it is indistinguishable from a
legitimate one. The actual control is procedural — mandatory out-of-band
callback verification for beneficiary changes and high-value instructions —
not a rule in this engine. Say this plainly to any institution evaluating
JFS rather than forcing a rule that can't do the job.

**ATM jackpotting:** a device/malware attack on the ATM itself, not a
transaction-pattern fraud. Needs ATM telemetry/device monitoring, a
different system category entirely.

## Prevention eligibility (real-time block/hold, opt-in only)

`jicho/prevention.py` turns a real-time alert into a decision (`ALLOW`/
`HOLD`/`BLOCK`) the calling payment system can act on before a transaction
completes. This is off by default and requires an institution to explicitly
whitelist specific rules for `BLOCK` after measuring their real-world
false-positive rate — see `API_REFERENCE.md`'s "Prevention decisions"
section and `JFS_Product_Requirements.docx` Section 9 for the required
governance process. Only rules where the flagged transaction IS the
harm-causing outbound movement itself are sensible block candidates:

| Rule | Sensible block candidate? | Why |
|---|---|---|
| R1 | Yes | Flags the actual cash-out withdrawal completing the fraud |
| R4 | Yes | Flags the actual sweep-out transaction completing the laundering |
| R8 | Yes | Flags the actual sweep transaction draining the dormant-account inflow |
| R13 | Yes | Flags the actual fraudulent cross-border purchase itself |
| R16 | Yes | Flags the actual redirected payment to the changed beneficiary |
| R17 | Yes | Flags the actual post-takeover transfer |
| All others | No — alert/hunt only | Either not real-time eligible (needs cross-account view), or the flagged event is a precursor signal rather than the harm-causing transaction itself, or has a false-positive profile not yet appropriate for blocking |

This table is a starting point for an institution's risk committee to
review, not a pre-approved default — `block_eligible_rule_ids` ships empty
regardless of what's listed here as "sensible."

## Regional coverage matrix

| Region | Strong coverage | Gaps |
|---|---|---|
| East Africa | R1–R7, R9, R10 | Less tested against bank-only/card-heavy markets |
| Southern Africa | R2, R6, R7, R8, R9, R11, R12, R13, R14 | ATM jackpotting (device problem, out of scope) |
| Central Africa | R4, R7, R9, R10, R13 | True cross-institution corridor layering needs `federated_layering.py` PLUS a data-sharing agreement — not solvable by rules alone |
