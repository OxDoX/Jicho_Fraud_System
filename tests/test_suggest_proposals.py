import json

from sentinel.engagement import Engagement
from sentinel.models import EngagementType, ScopeAsset, ScopeDoc
from sentinel.phases import phase3_dast


def _scope():
    return ScopeDoc(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[ScopeAsset(pattern="*.example.com")],
    )


class _FakeLLM:
    def __init__(self, response: str):
        self.response = response
        self.last_prompt = None

    def ask(self, prompt, max_tokens=2000):
        self.last_prompt = prompt
        return self.response


def test_suggest_proposals_parses_clean_json(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    llm = _FakeLLM(json.dumps([
        {
            "tool": "nuclei", "args": "-t cves/2025/ -rate-limit 5",
            "target": "https://app.example.com", "expected_outcome": "identify known CVEs",
            "rationale": "baseline recon", "source": "baseline",
        }
    ]))

    suggestions = phase3_dast.suggest_proposals(eng, llm)

    assert len(suggestions) == 1
    assert suggestions[0]["tool"] == "nuclei"
    saved = json.loads((eng.root / "suggested_proposals.json").read_text())
    assert saved == suggestions


def test_suggest_proposals_strips_markdown_fence(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    fenced = "```json\n" + json.dumps([{"tool": "httpx", "args": "-silent", "target": "app.example.com"}]) + "\n```"
    llm = _FakeLLM(fenced)

    suggestions = phase3_dast.suggest_proposals(eng, llm)

    assert len(suggestions) == 1
    assert suggestions[0]["tool"] == "httpx"


def test_suggest_proposals_handles_unparseable_output(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    llm = _FakeLLM("Sure! Here are some ideas: nuclei scan, then ffuf fuzzing.")

    suggestions = phase3_dast.suggest_proposals(eng, llm)

    assert len(suggestions) == 1
    assert "_unparsed" in suggestions[0]


def test_suggest_proposals_includes_scope_and_checklist_in_prompt(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    llm = _FakeLLM("[]")

    phase3_dast.suggest_proposals(eng, llm)

    assert "*.example.com" in llm.last_prompt
    assert "HTTP request smuggling" in llm.last_prompt
    assert "nuclei" in llm.last_prompt  # approved tool names listed
