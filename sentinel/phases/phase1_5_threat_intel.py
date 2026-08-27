"""Phase 1.5 — Threat Intelligence Refresh.

Pulls real, sourced, dated CVE data from the NVD public API (read-only,
not a target — no approval gate needed) for the engagement's stack, then
optionally asks the LLM to synthesize it into a brief. If the LLM is
unavailable, the raw sourced data is still saved and returned — synthesis
is a nice-to-have, sourcing is the requirement.
"""
from __future__ import annotations

from pathlib import Path

import requests

from ..engagement import Engagement
from ..llm.client import LLMUnavailable, SentinelLLM
from ..llm.prompts import threat_intel_prompt

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(keyword: str, results: int = 10, timeout: int = 20) -> list[dict]:
    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": results},
            timeout=timeout,
            headers={"User-Agent": "sentinel-agent/0.1 (authorized-research-tool)"},
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        return [{"error": f"NVD query failed for '{keyword}': {e}"}]

    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        out.append(
            {
                "cve_id": cve_id,
                "published": cve.get("published"),
                "cvss": cvss,
                "description": desc[:400],
                "source": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )
    return out


def format_cve_findings(keyword: str, cves: list[dict]) -> str:
    if not cves:
        return f"No NVD results for keyword '{keyword}'."
    if len(cves) == 1 and "error" in cves[0]:
        return cves[0]["error"]
    lines = [f"Keyword: {keyword}"]
    for c in cves:
        lines.append(f"  - {c['cve_id']} (CVSS {c['cvss']}, published {c['published']}): {c['description']}")
        lines.append(f"    source: {c['source']}")
    return "\n".join(lines)


def run(
    engagement: Engagement,
    stack_summary: str,
    keywords: list[str],
    llm: SentinelLLM | None = None,
) -> str:
    all_findings = []
    for kw in keywords:
        cves = fetch_recent_cves(kw)
        all_findings.append(format_cve_findings(kw, cves))
    cve_findings_text = "\n\n".join(all_findings)

    engagement.logger.log_action(
        "threat_intel_cve_query", {"keywords": keywords, "raw": cve_findings_text}
    )

    brief: str
    if llm is not None:
        try:
            brief = llm.ask(threat_intel_prompt(stack_summary, cve_findings_text))
        except LLMUnavailable as e:
            brief = (
                f"(LLM synthesis unavailable: {e})\n\n"
                f"=== Sourced-and-dated NVD data (raw) ===\n{cve_findings_text}"
            )
    else:
        brief = f"=== Sourced-and-dated NVD data (raw) ===\n{cve_findings_text}"

    out_path = engagement.root / "threat_intel_brief.md"
    out_path.write_text(brief, encoding="utf-8")
    engagement.logger.log_action("threat_intel_brief_saved", {"path": str(out_path)})
    engagement.set_phase("1.5_threat_intel_done")
    return brief
