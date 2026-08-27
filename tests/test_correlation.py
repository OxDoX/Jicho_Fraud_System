from sentinel.engagement import Engagement
from sentinel.models import EngagementType, Finding, ProposalSource, ScopeAsset, ScopeDoc
from sentinel.phases import phase4_verification as p4


def _scope():
    return ScopeDoc(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[ScopeAsset(pattern="*.example.com")],
    )


def _finding(**overrides):
    defaults = dict(
        title="SQL injection in search parameter",
        source=ProposalSource.BASELINE,
        tool="sqlmap",
        asset="app.example.com",
        cvss=None,
        cvss_reasoning="",
        reproduction_steps=["step 1"],
        evidence_redacted="evidence A",
        impact="data exposure",
        remediation="parameterize",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_same_asset_overlapping_title_grouped(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(_finding(title="SQL injection in search parameter", tool="semgrep"))
    eng.add_finding(_finding(title="Confirmed SQL injection via search endpoint", tool="sqlmap"))

    groups = p4.correlate_findings(eng)
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_different_asset_not_grouped(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(_finding(title="SQL injection in search parameter", asset="app.example.com"))
    eng.add_finding(_finding(title="SQL injection in search parameter", asset="api.example.com"))

    groups = p4.correlate_findings(eng)
    assert groups == []


def test_unrelated_titles_not_grouped(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(_finding(title="SQL injection in search parameter"))
    eng.add_finding(_finding(title="Missing rate limiting on login"))

    groups = p4.correlate_findings(eng)
    assert groups == []


def test_merge_combines_reproduction_steps_and_marks_duplicate(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(_finding(title="SQL injection A", reproduction_steps=["step 1", "step 2"]))
    eng.add_finding(_finding(title="SQL injection B", reproduction_steps=["step 2", "step 3"]))
    keep_id, absorb_id = eng.findings[0].id, eng.findings[1].id

    merged = p4.merge_findings(eng, keep_id, [absorb_id])

    assert merged.reproduction_steps == ["step 1", "step 2", "step 3"]
    absorbed = next(f for f in eng.findings if f.id == absorb_id)
    assert absorbed.status == "duplicate"


def test_merge_persists_across_reload(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(_finding(title="A"))
    eng.add_finding(_finding(title="B"))
    keep_id, absorb_id = eng.findings[0].id, eng.findings[1].id
    p4.merge_findings(eng, keep_id, [absorb_id])

    reloaded = Engagement("eng", _scope(), root=tmp_path)
    absorbed = next(f for f in reloaded.findings if f.id == absorb_id)
    assert absorbed.status == "duplicate"


def test_merge_unknown_id_raises(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    eng.add_finding(_finding())
    try:
        p4.merge_findings(eng, "nonexistent", [eng.findings[0].id])
        assert False, "expected ValueError"
    except ValueError:
        pass
