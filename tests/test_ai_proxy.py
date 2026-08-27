import pytest

from jicho.ai_proxy import DEFAULT_MODEL, MAX_TOKENS_CAP, app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


class _FakeUpstreamResponse:
    def __init__(self, json_body, status_code=200):
        self._json_body = json_body
        self.status_code = status_code

    def json(self):
        return self._json_body


def test_proxy_forwards_request_and_injects_api_key(client, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-secret")
    captured = {}

    def fake_post(url, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _FakeUpstreamResponse({"content": [{"type": "text", "text": "hello"}]})

    monkeypatch.setattr("jicho.ai_proxy.requests.post", fake_post)

    resp = client.post("/api/claude", json={"system": "be helpful", "messages": [{"role": "user", "content": "hi"}]})

    assert resp.status_code == 200
    assert resp.get_json() == {"content": [{"type": "text", "text": "hello"}]}
    assert captured["headers"]["x-api-key"] == "sk-test-secret"
    assert captured["json"]["messages"] == [{"role": "user", "content": "hi"}]
    assert captured["json"]["system"] == "be helpful"
    assert captured["json"]["model"] == DEFAULT_MODEL


def test_proxy_never_leaks_api_key_into_the_response_body(client, monkeypatch):
    """The one thing this proxy exists to prevent: the key must never appear
    anywhere in what's sent back to the browser, success or failure.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-never-appear-in-response")

    def fake_post(url, json, headers, timeout):
        return _FakeUpstreamResponse({"content": [{"type": "text", "text": "ok"}]})

    monkeypatch.setattr("jicho.ai_proxy.requests.post", fake_post)

    resp = client.post("/api/claude", json={"messages": [{"role": "user", "content": "hi"}]})
    assert "sk-should-never-appear-in-response" not in resp.get_data(as_text=True)


def test_proxy_rejects_body_without_messages(client, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    resp = client.post("/api/claude", json={"system": "no messages here"})
    assert resp.status_code == 400


def test_proxy_returns_500_without_crashing_when_api_key_missing(client, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    resp = client.post("/api/claude", json={"messages": [{"role": "user", "content": "hi"}]})
    assert resp.status_code == 500


def test_proxy_caps_client_supplied_max_tokens(client, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    captured = {}

    def fake_post(url, json, headers, timeout):
        captured["json"] = json
        return _FakeUpstreamResponse({"content": []})

    monkeypatch.setattr("jicho.ai_proxy.requests.post", fake_post)

    client.post("/api/claude", json={"messages": [{"role": "user", "content": "hi"}], "max_tokens": 999_999})
    assert captured["json"]["max_tokens"] == MAX_TOKENS_CAP


def test_proxy_returns_502_on_upstream_network_failure(client, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    import requests

    def fake_post(url, json, headers, timeout):
        raise requests.RequestException("connection reset")

    monkeypatch.setattr("jicho.ai_proxy.requests.post", fake_post)

    resp = client.post("/api/claude", json={"messages": [{"role": "user", "content": "hi"}]})
    assert resp.status_code == 502


def test_health_reports_whether_api_key_is_configured(client, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert client.get("/health").get_json() == {"status": "ok", "anthropic_key_configured": True}

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert client.get("/health").get_json() == {"status": "ok", "anthropic_key_configured": False}
