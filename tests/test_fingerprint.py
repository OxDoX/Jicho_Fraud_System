import json

from sentinel.engagement import Engagement
from sentinel.models import EngagementType, ScopeAsset, ScopeDoc
from sentinel.phases import phase1_fingerprint as fp


def _scope():
    return ScopeDoc(
        program_name="Test",
        engagement_type=EngagementType.BUG_BOUNTY,
        in_scope=[ScopeAsset(pattern="*.example.com")],
    )


def test_detects_node_project_and_framework(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"express": "^4.18.0", "next": "^14.0.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))

    detected = fp.detect_local_stack(tmp_path)

    assert "JavaScript/TypeScript" in detected["languages"]
    assert "Express" in detected["frameworks"]
    assert "Next.js" in detected["frameworks"]
    assert "package.json" in detected["manifests_found"]


def test_detects_python_django_project(tmp_path):
    (tmp_path / "requirements.txt").write_text("Django==5.0.1\npsycopg2-binary==2.9.9\n# a comment\n")

    detected = fp.detect_local_stack(tmp_path)

    assert "Python" in detected["languages"]
    assert "Django" in detected["frameworks"]
    assert "Django" in detected["dependencies"]


def test_detects_dockerfile_base_image(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nRUN pip install -r requirements.txt\n")

    detected = fp.detect_local_stack(tmp_path)

    assert "python:3.12-slim" in detected["base_images"]


def test_no_manifests_found_returns_empty_lists(tmp_path):
    (tmp_path / "README.md").write_text("hello")

    detected = fp.detect_local_stack(tmp_path)

    assert detected["languages"] == []
    assert detected["manifests_found"] == []


def test_scans_one_level_of_subdirectories(tmp_path):
    sub = tmp_path / "backend"
    sub.mkdir()
    (sub / "go.mod").write_text("module example.com/app\n\nrequire github.com/gin-gonic/gin v1.9.0\n")

    detected = fp.detect_local_stack(tmp_path)

    assert "Go" in detected["languages"]
    assert "Gin" in detected["frameworks"]


def test_save_and_load_local_stack_roundtrip(tmp_path):
    eng = Engagement("eng", _scope(), root=tmp_path)
    detected = {"languages": ["Python"], "frameworks": ["Django"], "dependencies": {}, "base_images": [], "manifests_found": []}

    merged = fp.save_local_stack(eng, detected)
    assert merged["local_codebase"]["languages"] == ["Python"]

    reloaded = fp.load_detected_stack(eng)
    assert reloaded["local_codebase"]["frameworks"] == ["Django"]


def test_summarize_stack_handles_empty():
    assert "no tech-stack fingerprint" in fp.summarize_stack({})


def test_summarize_stack_includes_local_and_live():
    detected = {
        "local_codebase": {"languages": ["Python"], "frameworks": ["Django"], "dependencies": {"a": ""}, "manifests_found": ["requirements.txt"]},
        "live_target": {"https://app.example.com": ["nginx", "HTTPServer:nginx/1.18.0"]},
    }
    summary = fp.summarize_stack(detected)
    assert "Python" in summary
    assert "Django" in summary
    assert "nginx" in summary


def test_extract_tech_hints_from_whatweb_style_output():
    raw = "https://example.com [200 OK] Country[UNITED STATES][US], HTTPServer[nginx/1.18.0], WordPress[6.4]"
    hints = fp.extract_tech_hints(raw)
    assert any("nginx" in h.lower() for h in hints)
    assert any(h.startswith("WordPress:") for h in hints)
    assert not any(h.startswith("Country:") for h in hints)


def test_derive_keywords_from_detected_stack():
    detected = {
        "local_codebase": {"languages": ["Python"], "frameworks": ["Django"]},
        "live_target": {"https://app.example.com": ["nginx", "HTTPServer:nginx/1.18.0"]},
    }
    keywords = fp.derive_keywords(detected)
    assert "Python" in keywords
    assert "Django" in keywords
    assert "nginx" in keywords


def test_derive_keywords_empty_when_nothing_detected():
    assert fp.derive_keywords({}) == []
