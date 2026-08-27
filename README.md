# Sentinel

Sentinel is an approval-gated AI agent for **authorized** bug bounty hunting
and penetration testing. It implements the Sentinel workflow (scope intake →
threat intel → novel hypothesis generation → SAST → DAST → verification →
cleanup → reporting → disclosure → retest) as real, enforced Python code —
not just an LLM prompt asking nicely.

**The safety model is code, not instructions.** Scope lock, per-action human
approval, the destructive-action blocklist, redaction, and audit logging are
implemented in plain Python in `sentinel/approval.py`, `sentinel/scope.py`,
and `sentinel/redact.py`. The LLM (`sentinel/llm/`) is only ever used for
reasoning tasks that never touch a live target — threat-intel synthesis,
novel hypothesis generation, SAST triage narration, and report/disclosure
drafting. It has no tool-execution capability of its own; every action that
touches a target goes through `sentinel/tools/runner.py`, which only runs
after `sentinel/approval.py` has recorded a fresh, explicit, human "yes" for
that exact proposal.

> This tool assumes you are already authorized to test the target(s) you
> configure in scope — an active bug bounty program, a signed pentest SOW, or
> equivalent. It does not grant authorization; it only helps you work within
> it safely and keep a clean audit trail.

## Why this architecture

- **The agent recognizes the tech stack itself**
  (`sentinel fingerprint-code` / `sentinel fingerprint-target`,
  `sentinel/phases/phase1_fingerprint.py`) — local codebase fingerprinting
  parses manifest files (package.json, requirements.txt/pyproject.toml,
  go.mod, Gemfile, composer.json, pom.xml/build.gradle, Dockerfile) with no
  approval gate (it never touches a target); live-target fingerprinting
  (whatweb/httpx/wappalyzer) goes through the normal Phase 3 approval gate,
  since passive recon still touches a target (Hard Constraint 1). Either
  way, the result feeds `threat-intel`, `hypotheses`, and `suggest`
  automatically — `--stack`/`--architecture` are optional now, not required
  hand-typed input.
- **The agent tracks whether its own knowledge is stale**
  (`sentinel refresh-check`, `sentinel/phases/phase1_5_threat_intel.py::
  staleness_warning`) — "the technique landscape shifts within weeks"
  (Hard Constraint 5 / Phase 1.5) is enforced as a real age check: a
  missing or >14-day-old threat-intel brief prints a non-blocking warning
  on `status`, `hypotheses`, and `suggest`, telling you to re-run
  `threat-intel` before trusting technique currency. It also reports
  whether a local `nuclei-templates` checkout looks stale. This is
  entirely local/informational — the agent never rewrites its own code or
  tool registry on its own; "keeping current" means re-querying its
  sources, not self-modifying.
- **The agent proposes, it doesn't just execute what you type**
  (`sentinel suggest` / `sentinel/phases/phase3_dast.py::suggest_proposals`)
  — the LLM drafts concrete tool+args+target Phase 3 proposals from the
  scope, the Phase 1.5 threat-intel brief, and Phase 1.75 hypotheses,
  saved to `suggested_proposals.json`. Drafting is not approval or
  execution: a suggestion only becomes a real action via
  `propose-suggested`, which runs it through the exact same approval gate
  as a hand-typed `propose` call — same scope lock, same destructive/
  escalation checks, same fresh human "yes" required.
- **Approval gate, every time** (`sentinel/approval.py::gate`) — no tool call
  reaches a live target without a fresh, single-use, interactive confirmation.
  There is no "approve all" flag anywhere in the CLI, on purpose.
- **Scope lock** (`sentinel/scope.py::is_in_scope`) — re-checked inside the
  gate itself, not trusted from the caller. Ambiguous or unparseable targets
  are always treated as out of scope.
- **Destructive actions are blocked before a human is even asked**
  (`sentinel/approval.py::check_destructive`) — `sqlmap --dump`,
  `DROP TABLE`, `rm -rf`, etc. are refused outright, approval or not.
- **Escalation is blocked by default** (`sentinel/approval.py::check_escalation`)
  — anything reading as lateral movement, exfil, persistence, a reverse shell,
  privesc, etc. is refused unless the proposal is explicitly marked
  `--escalation-requested`, standing in for "the human explicitly asked for
  this specific next step" (Hard Constraint 4).
- **Emergency stop** (`sentinel stop` / `sentinel resume`) — halts every
  target-touching action, cleanup, disclosure step, and retest on an
  engagement immediately. Nothing proceeds again until `sentinel resume` is
  run with an explicit reason; silence or a topic change is never treated as
  resumption (Hard Constraint 17).
- **Duplicate/exclusion check runs automatically** before every DAST
  proposal (`sentinel/phases/phase1_25_dedup.py`, wired into
  `phase3_dast.propose_and_run`) — a proposal matching a standing program
  exclusion gets flagged with an extra confirmation before it can spend an
  approval cycle (Hard Constraint 13).
- **Tool integrity** (`sentinel/tools/registry.py`) — only tools in the
  registry can run at all. GUI/interactive/high-risk tools (Burp, Metasploit,
  Frida, Responder, CrackMapExec, ...) are `manual_only`: the runner drafts
  the exact command for you to run yourself and paste results back in.
  Internal-network tools are `pentest_only` and refused on `bug_bounty`
  engagements.
- **Redaction** (`sentinel/redact.py`) — every piece of tool output is
  scrubbed for JWTs, AWS keys, bearer tokens, API keys/passwords (value
  masked, label kept legible), emails, and private key blocks before it is
  logged or shown.
- **Audit logging** (`sentinel/logging_utils.py`) — every proposal, approval
  or denial, execution, and finding is appended to
  `engagements/<id>/action_log.jsonl`; the Phase 6 disclosure clearance
  chain gets its own separate `disclosure_log.jsonl`.
- **SAST LLM triage is opt-in, not default** (`sentinel sast --llm-triage`)
  — Semgrep/gitleaks/etc. output can include source code context lines, so
  sending it to the LLM API for triage synthesis requires an explicit flag
  each run (Hard Constraint 10). Without it you still get findings, just
  with raw (redacted) tool output as the evidence instead of an LLM summary.
- **Finding correlation is a suggestion, merging is explicit**
  (`sentinel correlate` / `sentinel merge-findings`) — findings sharing an
  asset and overlapping title language get grouped as a suggestion; nothing
  is combined into one root-cause finding until you name exactly which ids
  to merge, matching "never combine unrelated findings into one entry."
- **Report templates match the platform** (`sentinel report --platform
  hackerone|bugcrowd|intigriti|jira|generic`) — field layout follows each
  platform's own submission format.

## Install

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements.txt
```

LLM-assisted steps (threat-intel synthesis, hypothesis generation, report and
disclosure drafting) need an API key:

```bash
cp .env.example .env   # then fill in ANTHROPIC_API_KEY
export $(grep -v '^#' .env | xargs)
```

Everything else — scope lock, the approval gate, tool execution, and audit
logging — works without a key. Pass `--no-llm` to skip LLM synthesis on
`threat-intel`, `report`, and `disclose-draft`. `sast` is the other way
round: LLM triage is off by default, and you opt in with `--llm-triage`
(see Hard Constraint 10 note below).

The security tools themselves (`nuclei`, `subfinder`, `semgrep`, ...) are
**not** bundled — install only what you need from `sentinel list-tools`,
verifying provenance (official repo, checksums) before first use in an
engagement, per Hard Constraint 8.

Once installed, check what's actually ready on this machine rather than
assuming:

```bash
sentinel doctor --scope my-program-scope.yaml
```

This reports, concretely: whether `ANTHROPIC_API_KEY` is set and the
`anthropic` package is importable, which of the approved tools are on
`PATH` (grouped by category, with the install hint for anything missing),
and whether the scope doc you gave it loads cleanly. Run it before pointing
the agent at a real engagement — none of the core safety mechanics (scope
lock, approval gate, redaction, audit logging) need any of this, but the
LLM-assisted commands and DAST tool execution do.

## Quickstart

```bash
# 1. Write a scope doc (see examples/scope.example.yaml)
cp examples/scope.example.yaml my-program-scope.yaml
$EDITOR my-program-scope.yaml

# 2. Create the engagement
sentinel init "My Program" --scope my-program-scope.yaml --id my-program

# 3. Phase 1 — confirm scope & authorization (interactive)
sentinel intake --id my-program

# Resuming a session later? Restate scope, phase, findings, and disclosure
# state before proposing anything new (Hard Constraint 15):
sentinel status --id my-program

# Emergency stop, any time, from any phase (Hard Constraint 17):
#   sentinel stop --id my-program --reason "..."
#   sentinel resume --id my-program --reason "..."   # explicit, logged, required to continue

# 3.5. Phase 1 — fingerprint the tech stack instead of typing it by hand.
#      Local codebase: no approval gate (never touches a target).
sentinel fingerprint-code --id my-program --path ./path/to/repo
#      Live target: goes through the normal approval gate, same as any Phase 3 action.
sentinel fingerprint-target --id my-program --target https://app.example.com --tool whatweb

# 4. Phase 1.5 — threat intel (real NVD data + optional LLM synthesis).
#    --stack/--keywords are optional now — they auto-fill from whatever
#    fingerprint-code/fingerprint-target detected above.
sentinel threat-intel --id my-program
#    ...or override manually:
#    sentinel threat-intel --id my-program --stack "nginx, Django 5.x, GraphQL API" --keywords "django,graphql,nginx"

# Is the agent's picture of the threat landscape still current? (Hard
# Constraint 5 — "the technique landscape shifts within weeks")
sentinel refresh-check --id my-program

# 5. Phase 1.75 — novel attack-chain hypotheses (LLM required).
#    --architecture is optional too — auto-fills from scope + detected stack.
sentinel hypotheses --id my-program

# 6. Phase 2 — SAST (no approval gate; local code only)
#    Findings use raw redacted tool output by default. Add --llm-triage only
#    if you want the LLM to synthesize it (sends that redacted output to the
#    API — explicit opt-in per Hard Constraint 10):
sentinel sast --id my-program --run "semgrep=--config auto ./path/to/repo"

# 7. Phase 3 — DAST, one proposal at a time, fresh approval every time.
#    A proposal matching a standing program exclusion gets flagged first;
#    anything reading as escalation (lateral movement, exfil, a shell,
#    persistence, ...) is refused unless you pass --escalation-requested,
#    which should only ever be true because the human explicitly asked for
#    that specific next step.
sentinel checklist   # see the baseline technique list

# Either propose by hand:
sentinel propose --id my-program \
  --tool nuclei --args "-t cves/2025/ -rate-limit 5" \
  --target "https://app.example.com" \
  --expected "identify known CVEs" \
  --rationale "baseline recon" --source baseline

# ...or have the agent draft candidates from scope + threat-intel + hypotheses,
# review them, then run one through the same approval gate:
sentinel suggest --id my-program
sentinel list-suggestions --id my-program
sentinel propose-suggested --id my-program --index 0

# 8. Review findings, correlate likely duplicates, confirm, generate the report
sentinel findings --id my-program
sentinel correlate --id my-program
sentinel merge-findings --id my-program --keep <id> --absorb <id2>,<id3>
sentinel confirm --id my-program --finding-id <id>
sentinel report --id my-program --platform hackerone

# 9. Cleanup anything testing created
sentinel scan-leftover-state --id my-program
sentinel cleanup --id my-program --description "delete test account foo@bar" --target app.example.com

# 10. Disclosure — only once you actually have clearance (see Phase 6 below)
sentinel disclose-gate --id my-program --finding-id <id> --approved-by "you@example.com"
sentinel disclose-draft --id my-program --finding-id <id> --disclosure-id <disc-id> \
  --discovery-date 2026-01-01 --report-date 2026-01-02
sentinel publish --id my-program --disclosure-id <disc-id>

# 11. Retest after the program reports a fix
sentinel retest --id my-program --finding-id <id> --scope my-program-scope.yaml
sentinel retest-outcome --id my-program --finding-id <id> --fix-holds --notes "confirmed patched"
```

## Phase 6 — disclosure is intentionally hard to reach

`disclose-gate` asks the four Hard-Constraint-7 conditions **one at a time**
and refuses if any is unmet:

1. Program closed it / disclosure timeline elapsed / vendor already published
2. A written clearance reference (email, platform message, cited policy)
3. The draft will contain no weaponized PoC
4. No real user/customer data appears anywhere in the draft

`disclose-draft` refuses to run if the gate didn't fully clear. `publish` is
a second, final, one-shot confirmation — and even then it only flips a local
record and logs the decision; actually posting anywhere is left to you.

## Engagement isolation

Each `sentinel init` creates its own `engagements/<id>/` directory with its
own scope snapshot, action log, disclosure log, findings, and reports.
Nothing is ever shared across engagement IDs (Hard Constraint 16) — that
directory is `.gitignore`d because it contains real target/finding data.

## Tests

```bash
pip install -e . -r requirements.txt
pytest
```

Tests cover the safety-critical paths specifically: scope matching
(wildcards, CIDRs, out-of-scope precedence), the approval gate (scope block,
destructive block, escalation block, pentest-only block, denial handling,
logging), emergency stop/resume state transitions, the dedup/exclusion
prompt, redaction (JWTs, AWS keys, emails, label-preserving value masking),
finding correlation/merge, LLM proposal-suggestion parsing, manifest-based
tech-stack detection, threat-intel staleness calculation, and — critically —
that findings/hypotheses/disclosures actually survive a save/reload cycle as
typed objects (every `sentinel` command is a fresh process, so this one
matters more than it sounds).

## Project layout

```
sentinel/
  models.py          dataclasses: ScopeDoc, Proposal, ApprovalRecord, Finding, ...
  scope.py            scope loading + is_in_scope()
  approval.py         the approval gate — scope/destructive/pentest-only checks + human confirm
  redact.py           PII/credential redaction
  logging_utils.py    append-only JSONL audit logs
  engagement.py       per-engagement state container
  tools/
    registry.py        approved open-source tool list
    runner.py           safe subprocess execution (or manual-draft) of an approved tool
    freshness.py         local nuclei-templates staleness check (informational only)
  llm/
    client.py           thin Anthropic API wrapper, no tool-use wired to it
    prompts.py           Sentinel system prompt + phase task prompts
  phases/
    phase1_scope.py, phase1_fingerprint.py, phase1_25_dedup.py,
    phase1_5_threat_intel.py, phase1_75_hypotheses.py, phase2_sast.py,
    phase3_dast.py, phase4_verification.py, phase4_5_cleanup.py,
    phase5_reporting.py, phase6_disclosure.py, phase7_retest.py
  cli.py              Typer CLI wiring every phase together
tests/                 pytest coverage for scope/approval/redact/fingerprint/staleness
examples/scope.example.yaml
```
