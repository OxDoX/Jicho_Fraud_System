import os

from sentinel.doctor import format_report, run_diagnostics


def test_reports_api_key_absent(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    report = run_diagnostics()
    assert report.api_key_set is False
    assert report.llm_ready is False


def test_reports_api_key_present(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake-not-real")
    report = run_diagnostics()
    assert report.api_key_set is True


def test_report_never_leaks_the_key_value(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-super-secret-value-12345")
    report = run_diagnostics()
    text = format_report(report)
    assert "sk-super-secret-value-12345" not in text


def test_tool_statuses_cover_full_registry():
    report = run_diagnostics()
    from sentinel.tools.registry import list_tools
    assert report.total_count == len(list_tools())


def test_manual_only_tools_count_as_installed():
    report = run_diagnostics()
    manual = [t for t in report.tool_statuses if t.manual_only]
    assert manual  # registry has manual_only entries (Burp, Metasploit, ...)
    assert all(t.installed for t in manual)


def test_scope_validation_reports_success(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "program_name: Test\nengagement_type: bug_bounty\nin_scope:\n  - pattern: '*.example.com'\n"
    )
    report = run_diagnostics(scope_path=scope_file)
    assert report.scope_valid is True
    assert report.scope_program_name == "Test"


def test_scope_validation_reports_failure(tmp_path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text("program_name: Empty\nengagement_type: bug_bounty\nin_scope: []\n")
    report = run_diagnostics(scope_path=scope_file)
    assert report.scope_valid is False
    assert report.scope_error is not None


def test_no_scope_path_leaves_scope_fields_none():
    report = run_diagnostics()
    assert report.scope_path is None
    assert report.scope_valid is None


def test_format_report_is_readable_text():
    report = run_diagnostics()
    text = format_report(report)
    assert "Sentinel readiness check" in text
    assert "Next steps" in text
