#!/usr/bin/env bash
# Installs as much of sentinel/tools/registry.py's approved tool list as a
# Debian/Ubuntu-based box (incl. Kali/Parrot) can get via package managers +
# go install, using exactly the commands verified to work by hand during
# development. Run `sentinel doctor` before and after to see the delta.
#
# Idempotent-ish: safe to re-run. Network-dependent — some steps need
# unrestricted access to pypi.org, proxy.golang.org, and github.com (git
# protocol specifically; some sandboxed networks block plain HTTPS GETs to
# github.com's web/API/release-asset endpoints while still allowing git
# clone — if a `go install` step below fails with a github.com download
# error, that's usually why).
#
# What this deliberately skips: manual_only tools (Burp, Metasploit, Frida,
# Responder, CrackMapExec, NetExec, Impacket, ObJection, ZAP, tshark) — the
# runner never auto-executes these anyway, install them on your own
# schedule. Also skips codeql (license-gated manual download) and mobsf
# (large Docker image) — pull those yourself if you need them.
set -euo pipefail

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (or with sudo) — this installs system packages." >&2
    exit 1
  fi
}
require_root

export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
GOBIN="${GOBIN:-$HOME/go/bin}"
mkdir -p "$GOBIN" /opt/security-tools /usr/local/bin

echo "=== apt packages ==="
apt-get update -qq
apt-get install -y -qq nmap masscan whatweb nikto apktool tshark libcurl4-openssl-dev libssl-dev

echo "=== pip packages ==="
pip install -q \
  semgrep checkov sqlmap arjun sslyze commix mitmproxy scoutsuite prowler bandit eslint 2>&1 \
  | grep -v "^$" || true
# wfuzz needs pycurl to compile; skip it if the build environment can't —
# ffuf (installed below via go) covers the same fuzzing use case.
pip install -q wfuzz || echo "wfuzz failed to build (pycurl) — skipping; use ffuf instead"

echo "=== go install (this is the slow part — large dependency trees) ==="
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/zricethezav/gitleaks/v8@latest          # NOT github.com/gitleaks/gitleaks — that path 404s
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install github.com/aquasecurity/tfsec/cmd/tfsec@latest
go install github.com/anchore/grype/cmd/grype@latest           # NOT the bare module root — main is under cmd/grype
go install github.com/BishopFox/cloudfox@latest
go install github.com/aquasecurity/trivy/cmd/trivy@v0.56.2     # @latest can need a newer Go toolchain (json/v2 experiment) than yours

echo "=== trufflehog (go install refuses due to replace directives in its go.mod — build from source) ==="
if ! command -v trufflehog >/dev/null 2>&1; then
  tmpdir=$(mktemp -d)
  git clone --depth 1 https://github.com/trufflesecurity/trufflehog "$tmpdir"
  (cd "$tmpdir" && go build -o "$GOBIN/trufflehog" .)
  rm -rf "$tmpdir"
fi

echo "=== gem packages ==="
gem install wpscan brakeman
# gem installs sometimes land outside PATH depending on the ruby version
# manager in use — symlink explicitly if `command -v` doesn't find them.
for bin in wpscan brakeman; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    found=$(gem contents "$bin" 2>/dev/null | grep "bin/$bin$" | head -1 || true)
    [ -n "$found" ] && ln -sf "$found" "/usr/local/bin/$bin"
  fi
done

echo "=== git-clone-only tools (no package registry ships a working binary) ==="
clone_and_link() {
  local repo="$1" dir="$2" script="$3" link_name="$4"
  [ -d "/opt/security-tools/$dir" ] || git clone --depth 1 "$repo" "/opt/security-tools/$dir"
  chmod +x "/opt/security-tools/$dir/$script"
  ln -sf "/opt/security-tools/$dir/$script" "/usr/local/bin/$link_name"
}
clone_and_link https://github.com/drwetter/testssl.sh   testssl.sh    testssl.sh   testssl.sh
clone_and_link https://github.com/ticarpi/jwt_tool       jwt_tool      jwt_tool.py  jwt_tool.py
clone_and_link https://github.com/defparam/smuggler      smuggler      smuggler.py  smuggler.py
clone_and_link https://github.com/s0md3v/Corsy           Corsy         corsy.py     corsy.py
clone_and_link https://github.com/dolevf/graphql-cop     graphql-cop   graphql-cop.py graphql-cop
clone_and_link https://github.com/BishopFox/h2csmuggler  h2csmuggler   h2csmuggler.py h2csmuggler.py

pip install -q -r /opt/security-tools/jwt_tool/requirements.txt
[ -f /opt/security-tools/Corsy/requirements.txt ] && pip install -q -r /opt/security-tools/Corsy/requirements.txt
[ -f /opt/security-tools/graphql-cop/requirements.txt ] && pip install -q -r /opt/security-tools/graphql-cop/requirements.txt

echo
echo "Done. Run: sentinel doctor --scope <your-scope.yaml>"
echo "Not covered here (see sentinel/tools/registry.py install_hint for each):"
echo "  wappalyzer (dead upstream project, use whatweb), codeql (license-gated manual download),"
echo "  jadx (no apt package — grab a release zip), mobsf (docker pull, large image),"
echo "  and every manual_only tool (Burp, Metasploit, Frida, Responder, CrackMapExec, NetExec, Impacket, objection, ZAP)."
