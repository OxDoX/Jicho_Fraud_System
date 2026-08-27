"""Regression test: every `sentinel` CLI command is a fresh process, so
findings/hypotheses/disclosures must survive a full save -> reload cycle as
real typed objects, not just sit in state.json as inert dicts."""
from sentinel.engagement import Engagement
from sentinel.models import (
    DisclosureGateAnswers,
    DisclosureRecord,
    EngagementType,
    Finding,
    Hypothesis,
    ProposalSource,
    ScopeAsset,
    ScopeDoc,
)


def _scope():
    return ScopeDoc(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[ScopeAsset(pattern="*.example.com")],
    )


def test_finding_survives_reload_as_typed_object(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(
        Finding(
            title="SQLi in /search",
            source=ProposalSource.BASELINE,
            tool="sqlmap",
            asset="app.example.com",
            cvss=7.5,
            cvss_reasoning="network, low complexity",
            reproduction_steps=["step 1"],
            evidence_redacted="evidence",
            impact="data exposure",
            remediation="parameterize queries",
        )
    )

    reloaded = Engagement("eng", _scope(), root=tmp_path)
    assert len(reloaded.findings) == 1
    f = reloaded.findings[0]
    assert isinstance(f, Finding)
    assert f.title == "SQLi in /search"
    assert f.source == ProposalSource.BASELINE
    assert f.cvss == 7.5


def test_hypothesis_survives_reload(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_hypothesis(
        Hypothesis(primitives=["SSRF", "IMDS"], rationale="chain", confidence="medium", test_plan="OOB canary")
    )
    reloaded = Engagement("eng", _scope(), root=tmp_path)
    assert len(reloaded.hypotheses) == 1
    assert isinstance(reloaded.hypotheses[0], Hypothesis)
    assert reloaded.hypotheses[0].confidence == "medium"


def test_disclosure_record_survives_reload(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    answers = DisclosureGateAnswers(
        program_closed_or_policy_elapsed=True,
        written_clearance_reference="email #123",
        poc_scrubbed_to_defender_only=True,
        no_real_user_data=True,
    )
    eng.add_disclosure(DisclosureRecord(finding_id="find_1", answers=answers, approved_by="researcher@example.com"))

    reloaded = Engagement("eng", _scope(), root=tmp_path)
    assert len(reloaded.disclosures) == 1
    record = reloaded.disclosures[0]
    assert isinstance(record.answers, DisclosureGateAnswers)
    assert record.answers.all_clear() is True


def test_findable_by_id_after_reload(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(
        Finding(
            title="X", source=ProposalSource.BASELINE, tool="nuclei", asset="a.example.com",
            cvss=None, cvss_reasoning="", reproduction_steps=["s"], evidence_redacted="e",
            impact="i", remediation="r",
        )
    )
    fid = eng.findings[0].id

    reloaded = Engagement("eng", _scope(), root=tmp_path)
    match = next((f for f in reloaded.findings if f.id == fid), None)
    assert match is not None
