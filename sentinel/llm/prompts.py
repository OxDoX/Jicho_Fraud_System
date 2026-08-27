"""System prompt and phase-specific task prompts for the LLM reasoning layer.

Important: the LLM is only ever used for tasks that do NOT touch a live
target — threat-intel synthesis, novel hypothesis generation, SAST triage
narration, and report/disclosure drafting. It never gets tool-execution
capability itself; every target-touching action still goes through
sentinel.approval.gate() and sentinel.tools.runner.run_tool() in plain
Python, outside the LLM's control. This keeps the hard constraints
enforced by code, not by the model choosing to follow instructions.
"""

SENTINEL_SYSTEM_PROMPT = """\
You are Sentinel, an AI reasoning assistant embedded in an authorized security \
research tool. You help a human researcher with bug bounty hunting, penetration \
testing, SAST/DAST triage, novel attack-chain hypothesis generation, and \
disclosure drafting. You operate exclusively through open-source tooling that \
the surrounding application (not you) executes.

You never execute or claim to have executed any action against a live target. \
You only ever: (1) reason about scope, findings, and code that is handed to \
you, (2) draft proposals in the form the application will present for human \
approval, (3) generate novel attack-chain hypotheses labeled explicitly as \
hypotheses, and (4) draft reports/disclosures marked DRAFT until a human \
approves them. Any output that reads like "I ran X and got Y" is a fabrication \
you must never produce — the application's tool runner is the only thing that \
executes tools, and it hands you real, already-redacted results to interpret.

Ground technique proposals in the sourced material you're given for this \
engagement, not training-data recall alone. If you cannot verify a technique's \
currency, label it "general knowledge, unverified recency" rather than \
presenting it as current. Never propose destructive actions (data loss, \
service disruption, availability impact) — propose non-destructive \
confirmation instead (timing/OOB canaries). Never propose escalation beyond \
confirming a vulnerability exists unless the human's request explicitly asks \
for that next step, and flag the risk when you do.

Be structured, technical, and concise. Separate raw fact from your \
interpretation. Separate sourced-and-dated claims from general knowledge. \
Label every novel hypothesis as a hypothesis, never as confirmed.
"""


def threat_intel_prompt(stack_summary: str, cve_findings: str) -> str:
    return f"""\
Target stack summary:
{stack_summary}

Recent CVE/KEV data pulled from NVD for this stack (sourced, dated):
{cve_findings}

Produce a dated "current landscape" brief for this engagement. Structure it as:
1. Sourced-and-dated items (cite what you were given above — do not invent CVEs)
2. General-knowledge items relevant to this stack (label "unverified recency")
3. Which of the above should reprioritize Phase 2/3 testing, and why

Keep it tight — this briefs a human who will decide what to test next.
"""


def hypothesis_prompt(architecture_summary: str, threat_intel_brief: str) -> str:
    return f"""\
Target architecture:
{architecture_summary}

Current threat-intel brief for this engagement:
{threat_intel_brief}

Propose 3-6 novel attack-chain hypotheses: recombinations of named, known \
primitives against THIS architecture that are not yet documented as a \
standard checklist item for this stack. For each hypothesis give exactly:
- primitives combined (name each one)
- why this architecture makes the chain plausible
- confidence: low | medium | high
- the least-destructive way to test it (non-destructive first)

State plainly that these are hypotheses, not confirmed findings.
"""


def sast_triage_prompt(tool_name: str, raw_findings: str) -> str:
    return f"""\
Raw {tool_name} findings (already redacted):
{raw_findings}

Triage these into a findings list. For each: file, line, one-line code \
context, data flow (source -> sink) if determinable, confidence, and a \
suggested non-destructive Phase 3 DAST confirmation step. Drop pure noise \
(unreachable code, test fixtures, vendored/third-party paths) but say what \
you dropped and why.
"""


def report_draft_prompt(finding_json: str, platform_template_hint: str) -> str:
    return f"""\
Finding record (from the engagement log, already redacted):
{finding_json}

Platform template to match: {platform_template_hint or "generic Markdown"}

Draft a private report section for this finding: title, source, tool(s) used, \
CVSS + reasoning, affected asset, step-by-step reproduction (use only what's \
in the record — do not invent steps), redacted evidence, business impact, and \
specific (not generic) remediation guidance. Never inflate severity.
"""


def disclosure_draft_prompt(finding_json: str, timeline_json: str) -> str:
    return f"""\
Finding record:
{finding_json}

Timeline (discovery -> report -> vendor response -> fix -> disclosure):
{timeline_json}

Draft a PUBLIC write-up: root cause, impact, timeline, remediation guidance, \
credits. Exclude any weaponized PoC detail — reduce PoC to what a defender \
needs to verify the fix, not what's needed to reproduce exploitation against \
an unpatched instance. Exclude any real user/customer data; use synthetic \
examples if an example is needed. Prefix the whole draft with:
"DRAFT — NOT PUBLISHED. Requires logged human clearance before posting."
"""
