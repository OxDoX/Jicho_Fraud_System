# JFS Documentation Set — Index

Six documents, each with a distinct audience and purpose. Read in this
order for a first pass; use as standalone references after that.

| Document | Audience | Purpose |
|---|---|---|
| `JFS_Product_Requirements.docx` | Stakeholders, investors, pilot institutions | What JFS must do, for whom, and why — functional/non-functional requirements, personas, success metrics, and explicit limitations |
| `JFS_Deployment_Architecture.docx` | IT security/audit, procurement, CAB reviewers | On-premises core + cloud-update-channel architecture, data flow, security controls, and the change-governance workflow for updates |
| `JFS_Technical_README.md` | Engineers, technical reviewers | Full codebase structure, engineering standards, testing approach, and all capabilities as actually implemented (18 rules, hunting, AI agents, calibration, real-time scoring, federated layering) |
| `RULE_CATALOG.md` | Engineers, fraud analysts, compliance officers | Every detection rule: typology, logic, config parameters, regional relevance, sourcing, and real-time eligibility |
| `API_REFERENCE.md` | Engineers integrating the real-time scoring service | Endpoint reference for the HTTP scoring API, including honest scope limits |
| `JFS_CLAUDE_CODE_BUILD_PROMPT.md` | Whoever builds or extends JFS next (human or AI-assisted) | A complete build brief — mission, regional context, what already exists, standards, build order, and explicit non-goals. Meant to be pasted into Claude Code (or saved as `CLAUDE.md`) as project context |

## How these fit together

The **PRD** and **Deployment Architecture** documents are the two
formal, stakeholder-facing artifacts — use these in procurement and pilot
conversations. The **Technical README**, **Rule Catalog**, and **API
Reference** are the engineering-facing reference set. The **Build Prompt**
is the synthesis of all of the above into actionable instructions for
continuing development, written so that picking the project back up —
whether that's you, another engineer, or an AI coding assistant — doesn't
require re-deriving decisions and bugs that were already found and fixed
once.

## A note on honesty as a design constraint

Every document in this set was written to the same standard: state what's
built and tested plainly, state what's a genuine limitation plainly, and
never round a partial capability up to a complete one. This isn't a style
preference — for a fraud-detection product being evaluated by bank risk
committees and IT auditors, overclaiming is the fastest way to lose
credibility the moment a technical reviewer asks a follow-up question. The
Known Limitations sections in the PRD and the "explicitly not covered"
notes in the Rule Catalog are load-bearing parts of the pitch, not
disclaimers to minimize.
