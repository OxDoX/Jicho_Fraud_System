from sentinel.models import EngagementType, ScopeAsset, ScopeDoc
from sentinel.scope import is_in_scope


def _scope(**overrides):
    defaults = dict(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[
            ScopeAsset(pattern="*.example.com"),
            ScopeAsset(pattern="10.0.0.0/24", asset_type="cidr"),
        ],
        out_of_scope=["internal.example.com"],
    )
    defaults.update(overrides)
    return ScopeDoc(**defaults)


def test_wildcard_subdomain_in_scope():
    scope = _scope()
    ok, _ = is_in_scope(scope, "https://app.example.com/login")
    assert ok


def test_apex_domain_not_matched_by_wildcard():
    scope = _scope()
    ok, _ = is_in_scope(scope, "https://example.com/")
    assert not ok


def test_out_of_scope_wins_even_if_pattern_would_match():
    scope = _scope(in_scope=[ScopeAsset(pattern="*.example.com")])
    ok, reason = is_in_scope(scope, "internal.example.com")
    assert not ok
    assert "out_of_scope" in reason


def test_cidr_match():
    scope = _scope()
    ok, _ = is_in_scope(scope, "10.0.0.42")
    assert ok


def test_cidr_no_match_outside_range():
    scope = _scope()
    ok, _ = is_in_scope(scope, "10.0.1.42")
    assert not ok


def test_unrelated_host_out_of_scope():
    scope = _scope()
    ok, _ = is_in_scope(scope, "https://evil.attacker.net")
    assert not ok


def test_empty_target_is_never_in_scope():
    scope = _scope()
    ok, reason = is_in_scope(scope, "")
    assert not ok
    assert "empty" in reason
