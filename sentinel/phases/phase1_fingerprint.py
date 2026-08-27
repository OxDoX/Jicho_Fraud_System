"""Phase 1 — Tech-stack fingerprinting.

"Fingerprint the target's tech stack (languages, frameworks, cloud
provider, CMS/platform, auth method) to drive tool selection and
threat-intel research" (system prompt, Phase 1).

Two halves, deliberately kept separate:

  - detect_local_stack(): reads manifest files in a local checkout. This
    is SAST-side — it never touches a live target, so it needs no
    approval gate (matches "SAST ... no approval gate, not live-target
    interaction").
  - Live-target fingerprinting (whatweb/httpx/wappalyzer against a real
    host) is NOT done here — it still touches a target, so it goes
    through the normal Phase 3 approval gate. See
    phase3_dast.propose_fingerprint_scan() and extract_tech_hints() below,
    which parse an already-executed, already-approved result.

Both halves write into the same engagements/<id>/detected_stack.json so
Phase 1.5/1.75/3 can use one merged picture of "what is this thing built
with" instead of requiring the human to retype a --stack description by
hand every time.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..engagement import Engagement

STACK_PATH_NAME = "detected_stack.json"

# manifest filename -> (language, parser function name below)
_MANIFEST_PARSERS: dict[str, str] = {
    "package.json": "_parse_package_json",
    "requirements.txt": "_parse_requirements_txt",
    "pyproject.toml": "_parse_pyproject_toml",
    "go.mod": "_parse_go_mod",
    "Gemfile": "_parse_gemfile",
    "composer.json": "_parse_composer_json",
    "pom.xml": "_parse_pom_xml",
    "build.gradle": "_parse_build_gradle",
    "Dockerfile": "_parse_dockerfile",
}

# dependency-name substring -> human framework name, per ecosystem
_FRAMEWORK_HINTS: dict[str, dict[str, str]] = {
    "node": {
        "next": "Next.js", "react": "React", "vue": "Vue", "express": "Express",
        "nestjs": "NestJS", "fastify": "Fastify", "@angular/core": "Angular",
        "svelte": "Svelte", "koa": "Koa",
    },
    "python": {
        "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
        "tornado": "Tornado", "pyramid": "Pyramid", "aiohttp": "aiohttp",
    },
    "ruby": {"rails": "Ruby on Rails", "sinatra": "Sinatra"},
    "php": {
        "laravel/framework": "Laravel", "symfony/symfony": "Symfony",
        "symfony/framework-bundle": "Symfony", "cakephp/cakephp": "CakePHP",
    },
    "java": {
        "spring-boot": "Spring Boot", "spring-core": "Spring",
        "org.springframework.boot": "Spring Boot",
    },
    "go": {"gin-gonic/gin": "Gin", "labstack/echo": "Echo", "gofiber/fiber": "Fiber"},
}


def _match_frameworks(ecosystem: str, dep_names: list[str]) -> list[str]:
    hints = _FRAMEWORK_HINTS.get(ecosystem, {})
    found = set()
    for dep in dep_names:
        dep_lower = dep.lower()
        for needle, framework in hints.items():
            if needle in dep_lower:
                found.add(framework)
    return sorted(found)


def _parse_package_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return {
        "language": "JavaScript/TypeScript",
        "dependencies": deps,
        "frameworks": _match_frameworks("node", list(deps.keys())),
    }


def _parse_requirements_txt(path: Path) -> dict:
    deps = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-\[\]]+)\s*([=<>!~]+.*)?$", line)
            if m:
                deps[m.group(1)] = (m.group(2) or "").strip()
    except OSError:
        return {}
    return {
        "language": "Python",
        "dependencies": deps,
        "frameworks": _match_frameworks("python", list(deps.keys())),
    }


def _parse_pyproject_toml(path: Path) -> dict:
    # Deliberately no TOML library dependency — a light regex pass is
    # enough to pull dependency names for framework detection.
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    deps = re.findall(r'^\s*"?([A-Za-z0-9_.\-]+)"?\s*=\s*["\{]', text, re.MULTILINE)
    return {
        "language": "Python",
        "dependencies": {d: "" for d in deps},
        "frameworks": _match_frameworks("python", deps),
    }


def _parse_go_mod(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    # covers both `require X vY` single-line and `require (\n  X vY\n)` block form
    deps = re.findall(r"^\s*(?:require\s+)?([\w.\-/]+)\s+v[\d.]+", text, re.MULTILINE)
    return {
        "language": "Go",
        "dependencies": {d: "" for d in deps},
        "frameworks": _match_frameworks("go", deps),
    }


def _parse_gemfile(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    deps = re.findall(r"gem\s+['\"]([\w\-]+)['\"]", text)
    return {
        "language": "Ruby",
        "dependencies": {d: "" for d in deps},
        "frameworks": _match_frameworks("ruby", deps),
    }


def _parse_composer_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    deps = {**data.get("require", {}), **data.get("require-dev", {})}
    return {
        "language": "PHP",
        "dependencies": deps,
        "frameworks": _match_frameworks("php", list(deps.keys())),
    }


def _parse_pom_xml(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    artifact_ids = re.findall(r"<artifactId>([\w\-.]+)</artifactId>", text)
    return {
        "language": "Java",
        "dependencies": {a: "" for a in artifact_ids},
        "frameworks": _match_frameworks("java", artifact_ids),
    }


def _parse_build_gradle(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    deps = re.findall(r"['\"]([\w.\-]+:[\w.\-]+):[\w.\-]+['\"]", text)
    return {
        "language": "Java/Kotlin",
        "dependencies": {d: "" for d in deps},
        "frameworks": _match_frameworks("java", deps),
    }


def _parse_dockerfile(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    images = re.findall(r"^\s*FROM\s+([^\s]+)", text, re.MULTILINE | re.IGNORECASE)
    return {"base_images": images}


_PARSER_FUNCS = {
    "_parse_package_json": _parse_package_json,
    "_parse_requirements_txt": _parse_requirements_txt,
    "_parse_pyproject_toml": _parse_pyproject_toml,
    "_parse_go_mod": _parse_go_mod,
    "_parse_gemfile": _parse_gemfile,
    "_parse_composer_json": _parse_composer_json,
    "_parse_pom_xml": _parse_pom_xml,
    "_parse_build_gradle": _parse_build_gradle,
    "_parse_dockerfile": _parse_dockerfile,
}


def detect_local_stack(repo_path: str | Path) -> dict:
    """Walk repo_path (top level + one level deep, to catch monorepo
    packages without an unbounded filesystem crawl) for known manifest
    files and return a merged {languages, frameworks, dependencies,
    base_images, manifests_found} picture."""
    root = Path(repo_path)
    languages: set[str] = set()
    frameworks: set[str] = set()
    dependencies: dict[str, str] = {}
    base_images: set[str] = set()
    manifests_found: list[str] = []

    candidates = list(root.glob("*")) + list(root.glob("*/*"))
    for entry in candidates:
        if entry.name in _MANIFEST_PARSERS and entry.is_file():
            parser = _PARSER_FUNCS[_MANIFEST_PARSERS[entry.name]]
            result = parser(entry)
            if not result:
                continue
            manifests_found.append(str(entry.relative_to(root)))
            if "language" in result:
                languages.add(result["language"])
            frameworks.update(result.get("frameworks", []))
            dependencies.update(result.get("dependencies", {}))
            base_images.update(result.get("base_images", []))

    return {
        "languages": sorted(languages),
        "frameworks": sorted(frameworks),
        "dependencies": dependencies,
        "base_images": sorted(base_images),
        "manifests_found": sorted(manifests_found),
    }


# Keyword net for parsing whatweb/httpx/wappalyzer output after an
# already-approved, already-executed Phase 3 fingerprint scan. Best-effort
# only — the raw (redacted) output is always kept in the action log too.
_LIVE_TECH_KEYWORDS = [
    "nginx", "apache", "iis", "cloudflare", "wordpress", "drupal", "joomla",
    "php", "asp.net", "express", "django", "laravel", "rails", "react",
    "vue", "angular", "next.js", "varnish", "tomcat", "jetty", "kubernetes",
    "cloudfront", "akamai", "fastly", "graphql", "shopify", "magento",
]
_NOISE_LABELS = {"country", "ip", "title", "redirectlocation", "uncommonheaders"}


def extract_tech_hints(raw_output: str) -> list[str]:
    """Best-effort tech-name extraction from whatweb/httpx-style output:
    known keyword hits plus whatweb's Label[value] tokens."""
    lowered = raw_output.lower()
    found = {kw for kw in _LIVE_TECH_KEYWORDS if kw in lowered}

    for m in re.finditer(r"([A-Za-z][\w.\-]*)\[([^\]]{1,60})\]", raw_output):
        label, value = m.group(1), m.group(2)
        if label.lower() not in _NOISE_LABELS:
            found.add(f"{label}:{value}")

    return sorted(found)


def load_detected_stack(engagement: Engagement) -> dict:
    path = engagement.root / STACK_PATH_NAME
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_local_stack(engagement: Engagement, detected: dict) -> dict:
    """Merge freshly detected local-codebase stack info into
    detected_stack.json under the 'local_codebase' key, preserving any
    'live_target' data already on file."""
    existing = load_detected_stack(engagement)
    existing["local_codebase"] = detected
    path = engagement.root / STACK_PATH_NAME
    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
    engagement.logger.log_action("stack_fingerprinted_local", detected)
    return existing


def summarize_stack(detected: dict) -> str:
    """Human/LLM-readable summary of whatever's on file — used to
    auto-populate --stack / --architecture when the human doesn't type one."""
    if not detected:
        return "(no tech-stack fingerprint on file — run `sentinel fingerprint-code` and/or `sentinel fingerprint-target`)"

    lines = []
    local = detected.get("local_codebase")
    if local:
        lines.append("Local codebase:")
        if local.get("languages"):
            lines.append(f"  Languages: {', '.join(local['languages'])}")
        if local.get("frameworks"):
            lines.append(f"  Frameworks: {', '.join(local['frameworks'])}")
        if local.get("base_images"):
            lines.append(f"  Container base images: {', '.join(local['base_images'])}")
        dep_count = len(local.get("dependencies", {}))
        if dep_count:
            lines.append(f"  Dependencies detected: {dep_count} (see detected_stack.json for full list)")
        if local.get("manifests_found"):
            lines.append(f"  From: {', '.join(local['manifests_found'])}")

    live = detected.get("live_target")
    if live:
        lines.append("Live target (from approved fingerprint scan):")
        for target, hints in live.items():
            lines.append(f"  {target}: {', '.join(hints) if hints else '(scan ran, no clear tech hints parsed)'}")

    return "\n".join(lines) if lines else "(fingerprint file present but empty)"


def derive_keywords(detected: dict) -> list[str]:
    """Pull short, NVD-friendly keywords (language/framework names) out of
    whatever's been fingerprinted, for auto-filling --keywords on
    `threat-intel` when the human doesn't type one."""
    keywords: set[str] = set()

    local = detected.get("local_codebase") or {}
    for lang in local.get("languages", []):
        keywords.add(lang.split("/")[0].strip())
    keywords.update(local.get("frameworks", []))

    live = detected.get("live_target") or {}
    for hints in live.values():
        for hint in hints:
            # "HTTPServer:nginx" -> "nginx"; plain keyword hits pass through
            keywords.add(hint.split(":", 1)[-1] if ":" in hint else hint)

    return sorted(k for k in keywords if k)
