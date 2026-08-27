from sentinel.redact import redact


def test_redacts_jwt():
    text = "Authorization set to eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert "eyJ" not in redact(text)
    assert "[REDACTED]" in redact(text)


def test_redacts_aws_key():
    text = "found key AKIAABCDEFGHIJKLMNOP in repo"
    assert "AKIAABCDEFGHIJKLMNOP" not in redact(text)


def test_redacts_email():
    text = "contact user at jane.doe@example.com for access"
    assert "jane.doe@example.com" not in redact(text)


def test_keep_edges_mode_shows_first_last_four():
    text = "api_key=abcdefghijklmnop"
    out = redact(text, keep_edges=True)
    assert "abcd" in out
    assert "mnop" in out
    assert "efghijkl" not in out


def test_non_secret_text_untouched():
    text = "nuclei scan completed, 0 findings"
    assert redact(text) == text
