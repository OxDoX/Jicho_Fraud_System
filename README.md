# Sentinel

Sentinel is an approval-gated AI agent for **authorized** bug bounty hunting
and penetration testing. It implements the Sentinel workflow (scope intake →
threat intel → novel hypothesis generation → SAST → SAST → DAST → verification
→ cleanup → reporting → disclosure → retest) as real, enforced Python code —
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

- **Approval gate, every time** (`sentinel/approval.py::gate`) — no tool call
  reaches a live target without a fresh, single-use, interactive confirmation.
  There is no "approve all" flag anywhere in the CLI, on purpose.
- **Scope lock** (`sentinel/scope.py::is_in_scope`) — re-checked inside the
  gate itself, not trusted from the caller. Ambiguous or unparseable targets
  are always treated as out of scope.
- **Destructive actions are blocked before a human is even asked**
  (`sentinel/approval.py::check_destructive`) — `sqlmap --dump`,
  `DROP TABLE`, `rm -rf`, etc. are refused outright, approval or not.
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
logging — works without a key. Pass `--no-llm` to skip LLM synthesis on any
command that supports it.

The security tools themselves (`nuclei`, `subfinder`, `semgrep`, ...) are
**not** bundled — install only what you need from `sentinel list-tools`,
verifying provenance (official repo, checksums) before first use in an
engagement, per Hard Constraint 8.

## Quickstart

```bash
# 1. Write a scope doc (see examples/scope.example.yaml)
cp examples/scope.example.yaml my-program-scope.yaml
$EDITOR my-program-scope.yaml

# 2. Create the engagement
sentinel init "My Program" --scope my-program-scope.yaml --id my-program

# 3. Phase 1 — confirm scope & authorization (interactive)
sentinel intake --id my-program

# 4. Phase 1.5 — threat intel (real NVD data + optional LLM synthesis)
sentinel threat-intel --id my-program \
  --stack "nginx, Django 5.x, PostgreSQL, GraphQL API" \
  --keywords "django,graphql,nginx"

# 5. Phase 1.75 — novel attack-chain hypotheses (LLM required)
sentinel hypotheses --id my-program \
  --architecture "Public GraphQL API behind nginx, Django backend, S3-backed file uploads"

# 6. Phase 2 — SAST (no approval gate; local code only)
sentinel sast --id my-program --run "semgrep=--config auto ./path/to/repo"

# 7. Phase 3 — DAST, one proposal at a time, fresh approval every time
sentinel checklist   # see the baseline technique list
sentinel propose --id my-program \
  --tool nuclei --args "-t cves/2025/ -rate-limit 5" \
  --target "https://app.example.com" \
  --expected "identify known CVEs" \
  --rationale "baseline recon" --source baseline

# 8. Review findings, confirm one, generate the report
sentinel findings --id my-program
sentinel confirm --id my-program --finding-id <id>
sentinel report --id my-program

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
destructive block, pentest-only block, denial handling, logging), and
redaction (JWTs, AWS keys, emails, label-preserving value masking).

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
  llm/
    client.py           thin Anthropic API wrapper, no tool-use wired to it
    prompts.py           Sentinel system prompt + phase task prompts
  phases/
    phase1_scope.py, phase1_25_dedup.py, phase1_5_threat_intel.py,
    phase1_75_hypotheses.py, phase2_sast.py, phase3_dast.py,
    phase4_verification.py, phase4_5_cleanup.py, phase5_reporting.py,
    phase6_disclosure.py, phase7_retest.py
  cli.py              Typer CLI wiring every phase together
tests/                 pytest coverage for scope/approval/redact
examples/scope.example.yaml
```
