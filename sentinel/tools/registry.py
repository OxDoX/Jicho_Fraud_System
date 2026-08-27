"""Approved open-source tool list (Hard Constraint 8).

Only tools in this registry can ever be run by `tools.runner.run_tool`.
Anything not here is refused outright — extending the list is a deliberate,
reviewable code change, not something the agent decides mid-session.

`sast` tools do not touch a live target and so are not subject to the
Phase 3 approval gate (they still get scope-appropriate handling in
phases/phase2_sast.py, which never proposes/approves them as DAST actions).

`manual_only` tools (GUI, interactive consoles, or too high-risk to
automate blindly — Burp, Metasploit, Frida, Responder, etc.) are never
executed by the runner. The runner drafts the exact command/config for a
human to run themselves, matching "drafts for human execution or approved
replay" in the system prompt.

`pentest_only` tools are refused entirely on bug_bounty engagements
(Hard Constraint 16 area — CrackMapExec/NetExec/Responder/Impacket internal
network scope).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: str
    binary: str
    description: str
    install_hint: str
    sast: bool = False
    manual_only: bool = False
    pentest_only: bool = False
    requires_credentials: bool = False


_REGISTRY: dict[str, ToolSpec] = {}


def _register(spec: ToolSpec) -> None:
    _REGISTRY[spec.name] = spec


for spec in [
    # --- Recon / Asset Discovery ---
    ToolSpec("subfinder", "recon", "subfinder", "Subdomain enumeration", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolSpec("amass", "recon", "amass", "Subdomain enumeration / attack surface mapping", "go install github.com/owasp-amass/amass/v4/...@master"),
    ToolSpec("httpx", "recon", "httpx", "Live host probing / fingerprinting", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolSpec("dnsx", "recon", "dnsx", "DNS resolution / bruteforce", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ToolSpec("naabu", "recon", "naabu", "Fast port scan", "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ToolSpec("nmap", "recon", "nmap", "Full port/service/version scan, NSE", "apt install nmap"),
    ToolSpec("masscan", "recon", "masscan", "Internet-scale port scan — explicit rate limits only", "apt install masscan"),
    ToolSpec("katana", "recon", "katana", "Crawling", "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ToolSpec("gospider", "recon", "gospider", "Crawling", "go install github.com/jaeles-project/gospider@latest"),
    ToolSpec("waybackurls", "recon", "waybackurls", "Historical URLs", "go install github.com/tomnomnom/waybackurls@latest"),
    ToolSpec("gau", "recon", "gau", "Historical URLs", "go install github.com/lc/gau/v2/cmd/gau@latest"),
    ToolSpec("whatweb", "recon", "whatweb", "Tech fingerprinting", "apt install whatweb"),

    # --- DAST ---
    ToolSpec("nuclei", "dast", "nuclei", "Template-based vulnerability scanning", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ToolSpec("zap", "dast", "zap-baseline.py", "OWASP ZAP full app scanning", "docker pull zaproxy/zap-stable", manual_only=True),
    ToolSpec("nikto", "dast", "nikto", "Web server misconfig", "apt install nikto"),
    ToolSpec("testssl", "dast", "testssl.sh", "TLS/SSL config", "git clone https://github.com/drwetter/testssl.sh"),
    ToolSpec("sslyze", "dast", "sslyze", "TLS/SSL config", "pip install sslyze"),
    ToolSpec("wpscan", "dast", "wpscan", "WordPress scanning — respect its own scope rules", "gem install wpscan"),
    ToolSpec("sqlmap", "dast", "sqlmap", "SQLi — non-destructive flags only unless explicitly escalated", "pip install sqlmap"),
    ToolSpec("commix", "dast", "commix", "Command injection", "pip install commix"),
    ToolSpec("ffuf", "dast", "ffuf", "Fuzzing", "go install github.com/ffuf/ffuf/v2@latest"),
    ToolSpec("wfuzz", "dast", "wfuzz", "Fuzzing", "pip install wfuzz"),
    ToolSpec("arjun", "dast", "arjun", "Hidden parameter discovery", "pip install arjun"),
    ToolSpec("graphql-cop", "dast", "graphql-cop", "GraphQL introspection/batching abuse", "pip install graphql-cop"),
    ToolSpec("inql", "dast", "inql", "GraphQL testing", "pip install inql", manual_only=True),
    ToolSpec("jwt_tool", "dast", "jwt_tool.py", "JWT flaws — alg confusion, weak secrets", "git clone https://github.com/ticarpi/jwt_tool"),
    ToolSpec("smuggler", "dast", "smuggler.py", "HTTP request smuggling variants", "git clone https://github.com/defparam/smuggler"),
    ToolSpec("h2csmuggler", "dast", "h2csmuggler.py", "H2C smuggling", "pip install h2csmuggler"),
    ToolSpec("corsy", "dast", "corsy.py", "CORS misconfig", "git clone https://github.com/s0md3v/Corsy"),

    # --- Network / Infrastructure ---
    ToolSpec("tshark", "network", "tshark", "Packet analysis", "apt install tshark", manual_only=True),
    ToolSpec("metasploit", "network", "msfconsole", "Exploitation — per-module, per-target approval", "apt install metasploit-framework", manual_only=True),
    ToolSpec("impacket", "network", "impacket-script", "Protocol-level testing — internal pentest scope", "pip install impacket", manual_only=True, pentest_only=True),
    ToolSpec("crackmapexec", "network", "cme", "Internal network/AD — pentest only, never bug bounty", "pip install crackmapexec", manual_only=True, pentest_only=True),
    ToolSpec("netexec", "network", "nxc", "Internal network/AD — pentest only, never bug bounty", "pip install netexec", manual_only=True, pentest_only=True),
    ToolSpec("responder", "network", "responder", "LLMNR/NBT-NS poisoning — internal pentest only", "apt install responder", manual_only=True, pentest_only=True),

    # --- Web Proxy / Manual Testing Support ---
    ToolSpec("burpsuite", "proxy", "burpsuite", "Proxy/repeater/intruder — draft for human execution", "https://portswigger.net/burp/communitydownload", manual_only=True),
    ToolSpec("mitmproxy", "proxy", "mitmdump", "Scriptable interception", "pip install mitmproxy", manual_only=True),

    # --- SAST / Code Analysis (no approval gate — not live-target interaction) ---
    ToolSpec("semgrep", "sast", "semgrep", "OSS rulesets, incl. custom rules", "pip install semgrep", sast=True),
    ToolSpec("codeql", "sast", "codeql", "Open query packs", "https://github.com/github/codeql-cli-binaries", sast=True),
    ToolSpec("bandit", "sast", "bandit", "Python SAST", "pip install bandit", sast=True),
    ToolSpec("gosec", "sast", "gosec", "Go SAST", "go install github.com/securego/gosec/v2/cmd/gosec@latest", sast=True),
    ToolSpec("eslint", "sast", "eslint", "JS/TS SAST with security plugins", "npm install -g eslint", sast=True),
    ToolSpec("brakeman", "sast", "brakeman", "Ruby on Rails SAST", "gem install brakeman", sast=True),
    ToolSpec("gitleaks", "sast", "gitleaks", "Secret scanning", "go install github.com/gitleaks/gitleaks/v8@latest", sast=True),
    ToolSpec("trufflehog", "sast", "trufflehog", "Secret scanning", "go install github.com/trufflesecurity/trufflehog/v3@latest", sast=True),
    ToolSpec("trivy", "sast", "trivy", "Dependency/container/IaC + SCA", "apt install trivy", sast=True),
    ToolSpec("grype", "sast", "grype", "Dependency/container SCA", "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh", sast=True),
    ToolSpec("checkov", "sast", "checkov", "IaC misconfig", "pip install checkov", sast=True),
    ToolSpec("tfsec", "sast", "tfsec", "Terraform misconfig", "go install github.com/aquasecurity/tfsec/cmd/tfsec@latest", sast=True),

    # --- Cloud-Specific (read-only, requires explicit scoped credentials from the human) ---
    ToolSpec("scoutsuite", "cloud", "scout", "Multi-cloud audit — read-only", "pip install scoutsuite", requires_credentials=True),
    ToolSpec("prowler", "cloud", "prowler", "AWS/Azure/GCP audit", "pip install prowler", requires_credentials=True),
    ToolSpec("cloudfox", "cloud", "cloudfox", "Cloud pentest enumeration", "go install github.com/BishopFox/cloudfox@latest", requires_credentials=True),

    # --- Mobile ---
    ToolSpec("mobsf", "mobile", "mobsf", "Static/dynamic analysis", "docker pull opensecurity/mobile-security-framework-mobsf", sast=True),
    ToolSpec("objection", "mobile", "objection", "Runtime instrumentation — explicit approval per session", "pip install objection", manual_only=True),
    ToolSpec("frida", "mobile", "frida", "Runtime instrumentation — high capability", "pip install frida-tools", manual_only=True),
    ToolSpec("apktool", "mobile", "apktool", "Android decompilation", "apt install apktool", sast=True),
    ToolSpec("jadx", "mobile", "jadx", "Android decompilation", "apt install jadx", sast=True),

    # --- Cleanup (Phase 4.5) ---
    ToolSpec(
        "manual-cleanup", "cleanup", "(manual)",
        "Arbitrary cleanup action performed by the human (delete test account, "
        "revoke API key, remove uploaded file, etc.) — always drafted, never auto-run.",
        "n/a", manual_only=True,
    ),
]:
    _register(spec)


def get_tool(name: str) -> ToolSpec:
    key = name.strip().lower()
    if key not in _REGISTRY:
        raise KeyError(
            f"'{name}' is not on the approved open-source tool list (Hard Constraint 8). "
            f"Add it to sentinel/tools/registry.py deliberately if it should be, "
            f"then verify provenance before first use in an engagement."
        )
    return _REGISTRY[key]


def list_tools(category: str | None = None) -> list[ToolSpec]:
    tools = list(_REGISTRY.values())
    if category:
        tools = [t for t in tools if t.category == category]
    return sorted(tools, key=lambda t: (t.category, t.name))
