"""S04 · Software Supply Chain.

Secret scanning, SBOM, dependency and IaC analysis, CI/CD audit, provenance
verification, and malicious-package behaviour heuristics (including the
invisible-unicode technique that powered the 2025–26 Shai-Hulud/GlassWorm waves).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from collections.abc import Iterable

from ..core.models import Evidence, Finding, RunContext, Severity

# ── secret patterns. Provider-aware so we know what a key actually IS.
SECRET_PATTERNS: list[tuple[str, str, Severity, str]] = [
    ("aws_access_key", r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b", Severity.CRITICAL, "AWS access key id"),
    ("aws_secret", r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", Severity.CRITICAL, "AWS secret access key"),
    ("gcp_api", r"\b(AIza[0-9A-Za-z\-_]{35})\b", Severity.CRITICAL, "Google API key"),
    ("gcp_service", r'"type"\s*:\s*"service_account"', Severity.HIGH, "GCP service account json"),
    ("azure_storage", r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/=]{60,})", Severity.CRITICAL, "Azure storage key"),
    ("slack", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", Severity.HIGH, "Slack token"),
    ("github_pat", r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b", Severity.CRITICAL, "GitHub token"),
    ("gitlab_pat", r"\b(glpat-[A-Za-z0-9\-_]{20,})\b", Severity.CRITICAL, "GitLab token"),
    ("openai", r"\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{20,})\b", Severity.CRITICAL, "OpenAI API key"),
    ("anthropic", r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b", Severity.CRITICAL, "Anthropic API key"),
    ("google_ai", r"\b(AIzaSy[A-Za-z0-9_\-]{33})\b", Severity.CRITICAL, "Google AI / Gemini key"),
    ("stripe", r"\b(sk_live_[0-9a-zA-Z]{20,})\b", Severity.CRITICAL, "Stripe live key"),
    ("sendgrid", r"\b(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})\b", Severity.CRITICAL, "SendGrid key"),
    ("npm_token", r"\b(npm_[A-Za-z0-9]{36})\b", Severity.CRITICAL, "npm token"),
    ("pypi_token", r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b", Severity.CRITICAL, "PyPI token"),
    ("dockerhub", r"(?i)dockerhub[_a-z]*\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{40,})", Severity.CRITICAL, "Docker Hub PAT"),
    ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", Severity.CRITICAL, "Private key material"),
    ("jwt", r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b", Severity.MEDIUM, "JWT"),
    ("bearer", r"(?i)authorization\s*:\s*bearer\s+([A-Za-z0-9\-._~+/]{20,})", Severity.MEDIUM, "Bearer token in source"),
    ("db_password", r"(?i)(?:db|database|sql)_(?:pass|password|user)\w*\s*[=:]\s*['\"]([^'\"]{8,})['\"]", Severity.HIGH, "Database credential in config"),
    ("basic_auth", r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}", Severity.MEDIUM, "Basic-auth credential in source"),
    ("ssh_key_line", r"(?m)^\s*(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+AAAA", Severity.MEDIUM, "Embedded public SSH key"),
    ("ai_model_key", r"(?i)\b(?:openai|anthropic|cohere|mistral|groq|perplexity)[_\-]?(?:api)?[_\-]?key\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", Severity.CRITICAL, "LLM provider API key"),
    ("hf_token", r"\b(hf_[A-Za-z0-9]{30,})\b", Severity.HIGH, "HuggingFace token"),
]

# ── invisible / homoglyph unicode used to smuggle payloads
INVISIBLE_RE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad]"
)
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")

# ── install-script behaviour markers seen in real supply-chain worms
INSTALL_MARKERS = [
    ("postinstall payload", re.compile(r"(?:pre|post)?install\s*[\"']?\s*:", re.I), Severity.MEDIUM),
    ("remote script fetch", re.compile(r"(?:curl|wget|Invoke-WebRequest|iwr)\s+[^\n|]{0,80}(?:https?://|\$\{)", re.I), Severity.HIGH),
    ("base64 decode to exec", re.compile(r"(?:base64|atob|from_?base64)[^\n]{0,60}(?:exec|eval|Invoke-|child_process|spawn)", re.I), Severity.CRITICAL),
    ("env exfiltration", re.compile(r"(?:process\.env|os\.environ|printenv)[^\n]{0,80}(?:fetch|requests\.|curl|http|axios)", re.I), Severity.CRITICAL),
    ("credential file read", re.compile(r"(?:\.npmrc|\.aws/credentials|\.netrc|\.git-credentials|Login Data|cookies\.sqlite|key4\.db|logins\.json)", re.I), Severity.CRITICAL),
    ("git credential push", re.compile(r"git\s+(?:credential|config)[^\n]{0,60}(?:push|url|helper)", re.I), Severity.HIGH),
    ("registry publish", re.compile(r"npm\s+publish|yarn\s+publish|pypi\s+upload|twine\s+upload", re.I), Severity.CRITICAL),
    ("process injection", re.compile(r"(?:eval|new\s+Function|child_process\.exec|os\.system|execSync)\s*\(", re.I), Severity.HIGH),
    ("obfuscated literal array", re.compile(r"(?:\\x[0-9a-f]{2}){12,}", re.I), Severity.HIGH),
    ("unicode escape padding", re.compile(r"(?:\\u[0-9a-f]{4}){10,}", re.I), Severity.HIGH),
]

# ── AI/agent supply-chain red flags for CI configs
CICD_RED_FLAGS = [
    ("pull_request_target with checkout of PR head",
     re.compile(r"pull_request_target[\s\S]{0,400}?actions/checkout[\s\S]{0,200}?ref:\s*\$\{\{\s*github\.event\.pull_request\.head", re.I),
     Severity.CRITICAL,
     "Classic untrusted-code execution path: a fork PR can run with repository secrets."),
    ("unpinned third-party action",
     re.compile(r"uses:\s*[\w.-]+/[\w.-]+@(master|main|v?\d+\b|latest)\s*$", re.M),
     Severity.MEDIUM,
     "Mutable tag reference — the action's owner can repoint it at malicious code at any time."),
    ("curl|bash in workflow",
     re.compile(r"(?:curl|wget)[^\n|]{0,120}\|\s*(?:ba)?sh", re.I),
     Severity.CRITICAL,
     "Remote script piped to a shell inside CI is an unreviewed supply-chain dependency."),
    ("credentials echoed",
     re.compile(r"(?:echo|print)\s+[^\n]{0,40}(?:secrets\.|GITHUB_TOKEN|API_KEY)", re.I),
     Severity.HIGH,
     "Secrets are being written to the CI log, which is frequently world-readable to contributors."),
    ("broad workflow permissions",
     re.compile(r"permissions\s*:\s*write-all|contents\s*:\s*write", re.I),
     Severity.HIGH,
     "Default token should be read-only; grant the minimum per job."),
    ("self-hosted runner on public repo",
     re.compile(r"runs-on\s*:\s*self-hosted", re.I),
     Severity.MEDIUM,
     "Self-hosted runners on pull_request execute untrusted code on persistent infrastructure."),
    ("npm install without lockfile integrity",
     re.compile(r"npm\s+(?:install|i)\b(?![^\n]*--ignore-scripts)", re.I),
     Severity.LOW,
     "Ensure the lockfile is used and install scripts are considered."),
    ("pip install from git/url",
     re.compile(r"pip\s+install\s+(?:git\+|-e\s+git|https?://)", re.I),
     Severity.MEDIUM,
     "Installing from an arbitrary URL bypasses registry integrity guarantees."),
]

GITHUB_ACTIONS = ["permissions", "pull_request_target", "actions/checkout",
                  "secrets.", "GITHUB_TOKEN", "id-token", "workflow_run"]


def _targets(ctx: RunContext) -> list[Path]:
    out: list[Path] = []
    if ctx.scope and ctx.scope.repos:
        out += [Path(r) for r in ctx.scope.repos]
    t = ctx.opt("targets") or []
    if isinstance(t, str):
        t = [x.strip() for x in t.split(",") if x.strip()]
    out += [Path(x) for x in t]
    if not out:
        out = [Path(ctx.workdir)]
    return [p for p in out if p.exists()]


def _code_exts() -> set[str]:
    return {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".rs", ".java",
            ".kt", ".rb", ".php", ".c", ".h", ".cpp", ".hpp", ".cs", ".swift", ".sh",
            ".bash", ".zsh", ".ps1", ".bat", ".env", ".yaml", ".yml", ".toml", ".ini",
            ".cfg", ".conf", ".json", ".tf", ".tfvars", ".properties", ".xml", ".md",
            ".txt", ".gradle", ".sbt", ".dockerfile", ".mk", ".pl", ".lua", ".sql"}


# ══════════════════════════════════════════════════════════════════ secrets
def scan_secrets(ctx: RunContext) -> list[Finding]:
    """Multi-pattern secret scan with classification and redaction.

    Patterns overlap by design (an Anthropic key also matches the generic
    OpenAI-shaped pattern), so results are de-duplicated on (file, line, value)
    and the most specific match wins.
    """
    from ..core.util import read_text, redact, walk_files
    out: list[Finding] = []
    exts = _code_exts()
    seen: set[tuple[str, int, str]] = set()
    for root in _targets(ctx):
        if root.is_file():
            files: Iterable[Path] = [root]
        else:
            files = walk_files(root, exts=exts, limit=120_000)
        nfiles = 0
        for f in files:
            body = read_text(f, limit=2_000_000)
            if not body or len(body) > 4_000_000:
                continue
            nfiles += 1
            rel = str(f)
            for name, pat, sev, what in SECRET_PATTERNS:
                rx = re.compile(pat)
                for m in rx.finditer(body):
                    val = next((g for g in m.groups() if g), m.group(0))
                    if not val or _is_placeholder(val):
                        continue
                    line = body[:m.start()].count("\n") + 1
                    key = (rel, line, redact(val, 8))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(Finding(
                        capability="s04_supplychain.secret_scan",
                        title=f"{what} in {f.name}",
                        severity=sev, target=rel,
                        detail=(f"{what} ({name}) at line {line}. Value (redacted): "
                                f"{redact(val)}. Treat as compromised and rotate now."),
                        attack_ids=["T1552.001"], tags=["secrets", "supplychain", "critical"],
                        confidence="high", cwe="CWE-798",
                        evidence=[Evidence(kind="file", summary=f"{name} @ line {line}",
                                           locator=rel, excerpt=redact(val))],
                        meta={"kind": name, "line": line, "redacted": redact(val)},
                        remediation="Revoke/rotate the credential, purge it from git history, "
                                    "and move to short-lived or keyless issuance.",
                    ))
        ctx.note(f"secret_scan: scanned {nfiles} files under {root}")
    return out


def _is_placeholder(v: str) -> bool:
    low = v.lower()
    return (len(v) < 12 or
            any(s in low for s in ("xxxx", "your-", "yourkey", "example", "changeme",
                                   "placeholder", "<", ">", "todo", "dummy", "test",
                                   "abcdef123", "00000000", "fake", "redacted", "$")))


# ══════════════════════════════════════════════════════════════════ unicode
def unicode_scan(ctx: RunContext) -> list[Finding]:
    """Invisible / bidi unicode in code and filenames (T1027.018)."""
    from ..core.util import walk_files
    out: list[Finding] = []
    for root in _targets(ctx):
        for f in walk_files(root, exts=_code_exts(), limit=60_000):
            try:
                raw = f.read_bytes()[:3_000_000]
            except Exception:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            inv = INVISIBLE_RE.findall(text)
            bidi = BIDI_RE.findall(text)
            if inv or bidi:
                out.append(Finding(
                    capability="s04_supplychain.malicious_package_scan",
                    title=f"Invisible Unicode in {f.name}",
                    severity=Severity.CRITICAL if bidi else Severity.HIGH,
                    target=str(f),
                    detail=(f"{len(inv)} invisible and {len(bidi)} bidi-control characters. "
                            "This is the Shai-Hulud/GlassWorm smuggling technique: the visible "
                            "source looks clean while hidden characters alter what runs."),
                    attack_ids=["T1027.018"],
                    tags=["supplychain", "malware", "unicode", "critical"],
                    confidence="high", cwe="CWE-94",
                    evidence=[Evidence(kind="file", summary=f"{len(inv)+len(bidi)} hidden chars",
                                       locator=str(f),
                                       excerpt="chars=" + " ".join(
                                           f"U+{ord(c):04X}" for c in (inv + bidi)[:20]))],
                    meta={"invisible": len(inv), "bidi": len(bidi)},
                    remediation="Reject any source or filename containing invisible Unicode; "
                                "verify the package against a known-good hash.",
                ))
    return out


# ══════════════════════════════════════════════════════════════════ packages
def scan_package(ctx: RunContext) -> list[Finding]:
    """Behaviour heuristics for a package directory or archive."""
    from ..core.util import read_text
    out: list[Finding] = []
    for root in _targets(ctx):
        for name, rx, sev in INSTALL_MARKERS:
            hits = []
            if root.is_dir():
                for pat in ("package.json", "setup.py", "pyproject.toml", "install.sh",
                            "Makefile", "*.js", "*.py", "*.sh", "*.ps1"):
                    for f in list(root.glob(pat))[:40]:
                        body = read_text(f)
                        if body and rx.search(body):
                            hits.append(f.name)
            else:
                body = read_text(root)
                if body and rx.search(body):
                    hits.append(root.name)
            if hits:
                out.append(Finding(
                    capability="s04_supplychain.malicious_package_scan",
                    title=f"Package behaviour: {name}", severity=sev, target=str(root),
                    detail=f"Matched in: {', '.join(sorted(set(hits))[:8])}",
                    attack_ids=["T1195.001", "T1059"],
                    tags=["supplychain", "malware", "package"], confidence="medium",
                    remediation="Verify the publisher, the release history, and whether this "
                                "behaviour is necessary. Wormable packages weaponise install hooks.",
                ))
    return out


def audit_registries(ctx: RunContext) -> list[Finding]:
    """Check a package exists only in registries it should."""
    http = ctx.http
    pkg = ctx.opt("package")
    if not pkg or not http:
        return []
    regs = {
        "npm": f"https://registry.npmjs.org/{pkg}",
        "pypi": f"https://pypi.org/pypi/{pkg}/json",
        "crates": f"https://crates.io/api/v1/crates/{pkg}",
        "maven": f"https://search.maven.org/solrsearch/select?q=a:{pkg}&rows=1&wt=json",
    }
    found = []
    for name, url in regs.items():
        r = http.get(url, allow_redirects=True)
        if r.ok and r.status < 400 and len(r.text or "") > 20:
            found.append(name)
    if len(found) > 1:
        return [Finding(
            capability="s04_supplychain.registry_presence",
            title=f"Package '{pkg}' published in {len(found)} registries: {', '.join(found)}",
            severity=Severity.MEDIUM, target=pkg,
            detail=("A name registered across ecosystems invites typosquat/dependency-confusion. "
                    "Each registry is a separate supply chain to police."),
            attack_ids=["T1195.001"], tags=["supplychain", "registry"],
            remediation="Publish to exactly the registries you support, and monitor the others "
                        "for impersonation.",
        )]
    return []


def check_registries_exposed(ctx: RunContext) -> list[Finding]:
    """Anonymous read/pull check against an internal registry host."""
    if not ctx.active or not ctx.http:
        return []
    hosts = ctx.opt("registries") or []
    if isinstance(hosts, str):
        hosts = [h.strip() for h in hosts.split(",") if h.strip()]
    out = []
    for h in hosts:
        base = h if "://" in h else f"https://{h}"
        for p in ("/v2/_catalog", "/v2/", "/api/v1/registries", "/nix/store", "/simple/"):
            r = ctx.http.get(base.rstrip("/") + p, allow_redirects=False)
            if r.status in (200, 401):
                sev = Severity.HIGH if r.status == 200 else Severity.MEDIUM
                out.append(Finding(
                    capability="s04_supplychain.artifact_registry_exposure",
                    title=f"{base}{p} → {r.status}", severity=sev, target=base + p,
                    detail=("Anonymous read of the registry catalogue — every artifact name is "
                            "enumerable and pulls may be possible."
                            if r.status == 200 else
                            "Registry reachable and requires auth (good, but confirm the auth is strong)."),
                    attack_ids=["T1530"], tags=["supplychain", "exposure", "registry"],
                    remediation="Require authentication for all reads and writes; alert on "
                                "anonymous pull attempts.",
                ))
                break
    return out


# ══════════════════════════════════════════════════════════════════ sbom
def sbom_generate(ctx: RunContext) -> list[Finding]:
    """Generate an SBOM. Delegates to syft when available."""
    from ..core.runner import execute
    from ..core.util import write_text
    out = []
    targets = _targets(ctx)
    rp = ctx.opt("_providers", {}).get("sbom_generate")
    if rp is not None and getattr(rp, "runnable", False):
        for root in targets:
            res = execute(rp.provider, [f"dir:{root}", "-o", "cyclonedx-json", "-q"],
                          ctx.config, timeout=300, workdir=ctx.workdir)
            if res.ok and res.stdout.strip():
                p = Path(ctx.workdir) / f"sbom-{root.name}.cdx.json"
                write_text(p, res.stdout)
                out.append(Finding(
                    capability="s04_supplychain.sbom_generate",
                    title=f"SBOM generated for {root.name}", severity=Severity.INFO,
                    target=str(p), detail=f"Produced via {res.how} ({len(res.stdout)} bytes).",
                    tags=["sbom", "supplychain"],
                    evidence=[Evidence(kind="file", summary="sbom", locator=str(p),
                                       excerpt=res.stdout[:600])],
                    remediation="Publish the SBOM with every release; feed it to the vuln pipeline.",
                ))
        return out
    # native fallback: manifest inventory
    for root in targets:
        comps: list[dict[str, str]] = []
        for mf, kind in (("package.json", "npm"), ("requirements.txt", "pypi"),
                         ("pyproject.toml", "pypi"), ("Cargo.toml", "cargo"),
                         ("go.mod", "go")):
            if not root.is_dir():
                continue
            p = root / mf
            if p.exists():
                from ..core.util import read_text
                body = read_text(p)
                for line in body.splitlines():
                    if kind == "go" and line.strip().startswith("require"):
                        continue
                    if kind in ("npm",) and '"' in line:
                        import re as _re
                        m = _re.search(r'"([^"@]+)@([^"]+)"', line)
                        if m:
                            comps.append({"name": m.group(1), "version": m.group(2), "type": "npm"})
                    elif kind in ("pypi",) and "==" in line:
                        n, _, v = line.strip().partition("==")
                        comps.append({"name": n, "version": v, "type": "pypi"})
        doc = {"bomFormat": "CycloneDX", "specVersion": "1.5",
               "metadata": {"component": {"type": "application", "name": root.name},
                            "tools": [{"name": "AEGIS-native"}]},
               "components": comps}
        p = Path(ctx.workdir) / f"sbom-{root.name}.cdx.json"
        write_text(p, json.dumps(doc, indent=2))
        out.append(Finding(
            capability="s04_supplychain.sbom_generate",
            title=f"Native SBOM for {root.name} ({len(comps)} components)",
            severity=Severity.INFO, target=str(p),
            detail=("syft not available; generated a manifest-level SBOM. Install syft "
                    "(`winget install Anchore.Syft`) for a full transitive inventory."),
            tags=["sbom", "supplychain"],
            remediation="Full SBOMs need transitive resolution — use syft or the docker image.",
        ))
    return out


def sbom_verify(ctx: RunContext) -> list[Finding]:
    """Policy check over an SBOM."""
    from ..core.util import read_text
    p = ctx.opt("sbom") or ""
    if not p or not Path(p).exists():
        return [Finding(capability="s04_supplychain.sbom_verify",
                        title="No SBOM supplied", severity=Severity.INFO, target=str(p),
                        detail="Pass --sbom <file>.", tags=["sbom"])]
    doc = json.loads(read_text(p) or "{}")
    comps = doc.get("components", []) or []
    banned_lic = {"agpl-3.0", "gpl-3.0", "sspl-1.0", "cc-by-nc-4.0"}
    findings = []
    for c in comps:
        lic = str((c.get("licenses") or [{}])[0].get("id", c.get("license", "")) if c.get("licenses") else c.get("license", "")).lower()
        if any(b in lic for b in banned_lic):
            findings.append(Finding(
                capability="s04_supplychain.sbom_verify",
                title=f"Restricted licence {lic} in {c.get('name')}",
                severity=Severity.MEDIUM, target=str(c.get("name")),
                detail=f"Component {c.get('name')}@{c.get('version')} carries licence '{lic}'.",
                tags=["sbom", "licence", "compliance"],
                remediation="Confirm this licence is compatible with your distribution model.",
            ))
    return findings or [Finding(
        capability="s04_supplychain.sbom_verify",
        title=f"SBOM verified: {len(comps)} components, no policy violations",
        severity=Severity.OK, target=p, tags=["sbom"])]


def license_audit(ctx: RunContext) -> list[Finding]:
    """Crude licence inventory from manifests — flag unknowns."""
    from ..core.util import read_text
    out = []
    for root in _targets(ctx):
        p = root / "LICENSE" if root.is_dir() else None
        if p and p.exists():
            head = read_text(p, 400).lower()
            kind = ("copyleft" if "gnu affero" in head or "gnu general public" in head
                    else "permissive" if "apache license" in head or "mit" in head
                    else "other")
            if kind == "copyleft":
                out.append(Finding(
                    capability="s04_supplychain.license_policy",
                    title=f"Copyleft licence in {root.name}", severity=Severity.LOW,
                    target=str(p), detail="Project root carries a GPL/AGPL-family licence.",
                    tags=["licence", "compliance"],
                    remediation="Confirm obligations are met for any derived distribution.",
                ))
    return out


# ══════════════════════════════════════════════════════════════════ deps
def scan_deps(ctx: RunContext) -> list[Finding]:
    """Dependency vulnerability scan. Delegates to installed tools, else parses lockfiles."""
    from ..core.runner import execute
    out: list[Finding] = []
    targets = _targets(ctx)

    rp = ctx.opt("_providers", {}).get("dependency_vuln")
    if rp is not None and getattr(rp, "runnable", False):
        for root in targets:
            res = execute(rp.provider, ["fs", "--scanners", "vuln", "--format", "json", str(root)],
                          ctx.config, timeout=600, workdir=ctx.workdir)
            if not res.ok:
                continue
            try:
                data = json.loads(res.stdout or "{}")
            except Exception:
                continue
            for r in (data.get("Results") or []):
                for v in (r.get("Vulnerabilities") or []):
                    sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                           "MEDIUM": Severity.MEDIUM}.get(v.get("Severity", ""), Severity.LOW)
                    out.append(Finding(
                        capability="s04_supplychain.dependency_vuln",
                        title=f"{v.get('VulnerabilityID')} in {v.get('PkgName')}",
                        severity=sev, target=str(root),
                        detail=(f"{v.get('PkgName')}@{v.get('InstalledVersion')} — "
                                f"{(v.get('Title') or '')[:120]}"),
                        attack_ids=["T1195.001"], tags=["supplychain", "vuln", "deps"],
                        refs=[v.get("PrimaryURL", "")] if v.get("PrimaryURL") else [],
                        remediation="Upgrade to a fixed version; verify the fix actually "
                                    "addresses the reachable code path.",
                    ))
        if out:
            return out

    # native fallback: report the lockfiles we found so coverage is explicit
    seen = []
    for root in targets:
        for lf in ("package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
                   "requirements.txt", "Cargo.lock", "go.sum", "Gemfile.lock",
                   "composer.lock"):
            p = root / lf if root.is_dir() else None
            if p and p.exists():
                seen.append(str(p))
    if seen:
        out.append(Finding(
            capability="s04_supplychain.dependency_vuln",
            title=f"{len(seen)} lockfiles found — install a vuln scanner",
            severity=Severity.MEDIUM, target=str(targets[0]),
            detail=("No dependency vulnerability scanner is available in this environment, so "
                    "dependency risk is UNMEASURED. Lockfiles present: " + ", ".join(seen[:10])),
            attack_ids=["T1195.001"], tags=["supplychain", "vuln", "gap"],
            remediation="Install one: `winget install AquaSecurity.Trivy` or "
                        "`pip install pip-audit`, or use the container images.",
            meta={"lockfiles": seen},
        ))
    return out


def scan_iac(ctx: RunContext) -> list[Finding]:
    """Native IaC misconfiguration rules for Terraform/K8s/compose."""
    RULES = [
        ("public S3 bucket", re.compile(r"acl\s*=\s*\"public-read(?:-write)?\"|block_public_acls\s*=\s*false", re.I), Severity.CRITICAL, "T1530"),
        ("0.0.0.0/0 ingress", re.compile(r"0\.0\.0\.0/0"), Severity.HIGH, "T1190"),
        ("::/0 ingress", re.compile(r"::/0"), Severity.HIGH, "T1190"),
        ("SSH open to world", re.compile(r"from_port\s*=\s*22[\s\S]{0,120}cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\""), Severity.HIGH, "T1190"),
        ("RDS publicly accessible", re.compile(r"publicly_accessible\s*=\s*true"), Severity.HIGH, "T1190"),
        ("IAM wildcard action", re.compile(r"Action\s*=\s*\"\*\"|\"Action\"\s*:\s*\"\*\""), Severity.CRITICAL, "T1078.004"),
        ("IAM wildcard resource", re.compile(r"Resource\s*=\s*\"\*\"|\"Resource\"\s*:\s*\"\*\""), Severity.HIGH, "T1078.004"),
        ("hardcoded credential in IaC", re.compile(r"(?i)(password|secret_key|token)\s*=\s*\"[^\"]{8,}\""), Severity.CRITICAL, "T1552.001"),
        ("privileged container", re.compile(r"privileged\s*:\s*true|privileged\s*=\s*true"), Severity.CRITICAL, "T1610"),
        ("allowPrivilegeEscalation", re.compile(r"allowPrivilegeEscalation\s*:\s*true"), Severity.HIGH, "T1610"),
        ("runAsRoot", re.compile(r"runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0"), Severity.HIGH, "T1610"),
        ("hostPath mount", re.compile(r"hostPath\s*:"), Severity.MEDIUM, "T1610"),
        ("hostNetwork", re.compile(r"hostNetwork\s*:\s*true"), Severity.HIGH, "T1610"),
        ("latest image tag", re.compile(r"image\s*:\s*\S+:latest"), Severity.LOW, "T1195.002"),
        ("no resource limits", re.compile(r"kind:\s*Deployment(?![\\s\\S]{0,600}resources:)"), Severity.LOW, "T1499"),
        ("default service account", re.compile(r"serviceAccountName\s*:\s*default", re.I), Severity.MEDIUM, "T1078.001"),
        ("cluster-admin binding", re.compile(r"cluster-admin", re.I), Severity.CRITICAL, "T1078.001"),
    ]
    from ..core.util import read_text, walk_files
    out = []
    for root in _targets(ctx):
        files = ([root] if root.is_file() else
                 walk_files(root, exts={".tf", ".tfvars", ".yaml", ".yml", ".json"},
                            skip={".git", "node_modules", "vendor"}, limit=20_000))
        for f in files:
            body = read_text(f, 4_000_000)
            if not body:
                continue
            for name, rx, sev, tid in RULES:
                m = rx.search(body)
                if not m:
                    continue
                line = body[:m.start()].count("\n") + 1
                out.append(Finding(
                    capability="s04_supplychain.iac_scan",
                    title=f"IaC: {name} in {f.name}",
                    severity=sev, target=str(f),
                    detail=f"{name} detected at line {line}: {m.group(0)[:80]!r}",
                    attack_ids=[tid], tags=["supplychain", "iac", "config"],
                    confidence="high", cwe="CWE-284",
                    evidence=[Evidence(kind="file", summary=name, locator=str(f),
                                       excerpt=body[max(0, m.start() - 80):m.start() + 160])],
                    remediation="Fix in source control so the pipeline blocks the deploy.",
                ))
    return out


def sast(ctx: RunContext) -> list[Finding]:
    """Lightweight SAST: dangerous sink detection by language."""
    SINKS = [
        ("python", re.compile(r"(?:os\.system|subprocess\.[a-z_]+|eval|exec)\s*\([^)]*(?:input|request|params|argv|environ)", re.I), "CWE-78"),
        ("python", re.compile(r"pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)", re.I), "CWE-502"),
        ("js", re.compile(r"eval\s*\(|new\s+Function\s*\([^)]*(?:req|params|body|query)", re.I), "CWE-95"),
        ("js", re.compile(r"child_process\.exec\s*\([^)]*\+", re.I), "CWE-78"),
        ("php", re.compile(r"\b(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", re.I), "CWE-78"),
        ("go", re.compile(r"os/exec\.(?:Command|CommandContext)\([^)]*os\.Getenv|exec\.Command\([^)]*\+"), "CWE-78"),
        ("java", re.compile(r"Runtime\.getRuntime\(\)\.exec\([^)]*(?:request|param|getParameter)", re.I), "CWE-78"),
        ("sqli", re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE)[^;\"']{0,80}(?:\+\s*\w+|%s|fmt\.Sprintf|String\s*\+)", re.I), "CWE-89"),
        ("xxe", re.compile(r"etree\.parse\(|DocumentBuilderFactory\.(?:newInstance|newNSInstance)"), "CWE-611"),
    ]
    from ..core.util import read_text, walk_files
    out = []
    for root in _targets(ctx):
        files = walk_files(root, exts=_code_exts() - {".md", ".txt"}, limit=60_000)
        for f in files:
            body = read_text(f, 1_500_000)
            if not body:
                continue
            for lang, rx, cwe in SINKS:
                for m in list(rx.finditer(body))[:5]:
                    line = body[:m.start()].count("\n") + 1
                    out.append(Finding(
                        capability="s04_supplychain.sast",
                        title=f"{cwe}: {lang} dangerous sink in {f.name}",
                        severity=Severity.MEDIUM, target=str(f),
                        detail=f"Line {line}: {(m.group(0)[:100])!r}",
                        attack_ids=["T1190"], tags=["supplychain", "sast", "code"],
                        cwe=cwe, confidence="medium",
                        remediation="Avoid the sink or sanitise the input; prefer parameterised "
                                    "queries and safe parsers.",
                    ))
    return out


def scan_image(ctx: RunContext) -> list[Finding]:
    """Container image analysis. Delegates to trivy/grype when available."""
    from ..core.runner import execute
    images = ctx.opt("images") or []
    if isinstance(images, str):
        images = [i.strip() for i in images.split(",") if i.strip()]
    out = []
    rp = ctx.opt("_providers", {}).get("container_scan")
    if rp is None or not getattr(rp, "runnable", False):
        if images:
            out.append(Finding(
                capability="s04_supplychain.container_scan",
                title=f"{len(images)} image(s) declared but no image scanner available",
                severity=Severity.MEDIUM, target=",".join(images[:5]),
                detail="Image risk is UNMEASURED. Install trivy or use the container image.",
                tags=["supplychain", "container", "gap"],
                remediation="`winget install AquaSecurity.Trivy` or run "
                            "`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image <img>`",
            ))
        return out
    for img in images[:10]:
        # `privileged=True` was passed but `execute` has no such parameter, so this
        # call raised TypeError on every container scan. Trivy reads the image via
        # the docker socket; the socket is supplied by the provider's own mounts,
        # so no extra privilege is needed here.
        res = execute(rp.provider, ["image", "--scanners", "vuln,misconfig,secret",
                                     "-f", "json", img],
                      ctx.config, timeout=900)
        if not res.ok:
            continue
        try:
            data = json.loads(res.stdout or "{}")
        except Exception:
            continue
        n = 0
        for r in (data.get("Results") or []):
            for v in (r.get("Vulnerabilities") or []):
                s = v.get("Severity", "")
                if s not in ("CRITICAL", "HIGH"):
                    continue
                n += 1
                out.append(Finding(
                    capability="s04_supplychain.container_scan",
                    title=f"{s}: {v.get('VulnerabilityID')} in {img}",
                    severity=Severity.CRITICAL if s == "CRITICAL" else Severity.HIGH,
                    target=f"{img}:{r.get('Target','')}",
                    detail=f"{v.get('PkgName')}@{v.get('InstalledVersion')} — {(v.get('Title') or '')[:110]}",
                    attack_ids=["T1195.002"], tags=["supplychain", "container", "vuln"],
                    remediation="Rebuild the image on a patched base; add the scanner to CI.",
                ))
            for m in (r.get("Misconfigurations") or []):
                if m.get("Severity") in ("CRITICAL", "HIGH"):
                    out.append(Finding(
                        capability="s04_supplychain.container_scan",
                        title=f"Image misconfig: {m.get('ID')} in {img}",
                        severity=Severity.HIGH, target=f"{img}:{r.get('Target','')}",
                        detail=(m.get("Message") or "")[:180],
                        attack_ids=["T1610"], tags=["supplychain", "container", "config"],
                        remediation=(m.get("Resolution") or "")[:200],
                    ))
        if n == 0:
            out.append(Finding(
                capability="s04_supplychain.container_scan",
                title=f"{img}: no critical/high vulns", severity=Severity.OK, target=img,
                tags=["supplychain", "container"],
            ))
    return out


# ══════════════════════════════════════════════════════════════════ cicd
def audit_cicd(ctx: RunContext) -> list[Finding]:
    """Static analysis of CI/CD workflow definitions."""
    from ..core.util import read_text, walk_files
    out = []
    found_any = False
    for root in _targets(ctx):
        for f in walk_files(root, exts={".yml", ".yaml"},
                           skip={".git", "node_modules", "vendor"}, limit=20_000):
            body = read_text(f, 1_500_000)
            if not body:
                continue
            if not any(k in body for k in GITHUB_ACTIONS):
                continue
            found_any = True
            # 4-tuples: (label, compiled regex, severity, explanation). The
            # explanation was declared in the table and silently discarded by the
            # old 3-value unpack, so the specific "why this matters" text never
            # reached any report.
            for name, rx, sev, why in CICD_RED_FLAGS:
                m = rx.search(body)
                if not m:
                    continue
                line = body[:m.start()].count("\n") + 1
                out.append(Finding(
                    capability="s04_supplychain.cicd_audit",
                    title=f"CI/CD: {name} in {f.name}", severity=sev, target=str(f),
                    detail=f"Line {line}. {why}",
                    attack_ids=["T1195.001", "T1552.001"], tags=["supplychain", "cicd", "critical"],
                    confidence="high",
                    evidence=[Evidence(kind="file", summary=name, locator=str(f),
                                       excerpt=body[max(0, m.start() - 100):m.start() + 200])],
                    remediation=("Split untrusted PR execution from privileged contexts; pin "
                                 "actions to commit SHAs; drop token privileges to read-only."),
                ))
    if not found_any:
        out.append(Finding(
            capability="s04_supplychain.cicd_audit", title="No CI/CD workflow definitions found",
            severity=Severity.INFO, target=str(_targets(ctx)[0] if _targets(ctx) else "?"),
            detail="Searched for GitHub Actions / pipeline definitions. None located.",
            tags=["supplychain", "cicd"],
            remediation="If you run CI elsewhere (GitLab/Jenkins/Azure), point the scan at that config.",
        ))
    return out


def check_runners(ctx: RunContext) -> list[Finding]:
    """Self-hosted runner exposure — the pivot in most CI/CD compromises."""
    from ..core.util import read_text, walk_files
    out = []
    for root in _targets(ctx):
        for f in walk_files(root, exts={".yml", ".yaml"}, limit=15_000):
            body = read_text(f, 800_000)
            if body and "runs-on: self-hosted" in body.replace("runs-on:self-hosted",
                                                               "runs-on: self-hosted"):
                sev = Severity.HIGH if "pull_request" in body or "issue_comment" in body else Severity.MEDIUM
                out.append(Finding(
                    capability="s04_supplychain.selfhosted_runner_exposure",
                    title=f"Self-hosted runner referenced in {f.name}", severity=sev,
                    target=str(f),
                    detail=("A workflow using a self-hosted runner is triggered by untrusted "
                            "input. The runner is persistent infrastructure that an attacker can "
                            "plant code on."),
                    attack_ids=["T1195.001"], tags=["supplychain", "cicd", "exposure"],
                    remediation="Use ephemeral runners per job; never expose them to fork PRs; "
                                "run them inside a disposable network segment.",
                ))
    if not out:
        # also probe declared hosts
        for h in (ctx.opt("runner_hosts") or []):
            if not ctx.active or not ctx.http:
                continue
            r = ctx.http.get(f"https://{h}:8443/", allow_redirects=False)
            if r.status in (200, 401, 403):
                out.append(Finding(
                    capability="s04_supplychain.selfhosted_runner_exposure",
                    title=f"Runner endpoint reachable at {h}:8443 ({r.status})",
                    severity=Severity.CRITICAL, target=f"{h}:8443",
                    detail="An actions-runner control port is reachable from outside.",
                    attack_ids=["T1195.001"], tags=["supplychain", "exposure", "critical"],
                    remediation="Runner control ports must never be internet-reachable.",
                ))
    return out


def audit_signing(ctx: RunContext) -> list[Finding]:
    """Release-signing and keyless-issuance hygiene."""
    from ..core.util import read_text, walk_files
    out = []
    saw_signing = False
    for root in _targets(ctx):
        for f in walk_files(root, exts={".yml", ".yaml", ".sh", ".ps1", ".toml"},
                           limit=15_000):
            body = read_text(f, 800_000)
            if not body:
                continue
            if re.search(r"(?:cosign|gpg\s+--detach|signtool|notarytool)", body, re.I):
                saw_signing = True
            if re.search(r"(?:GPG_KEY|GPG_PRIVATE_KEY|NPM_TOKEN)\s*[:=]\s*[\"']?[A-Za-z0-9+/=_\-]{16,}", body):
                out.append(Finding(
                    capability="s04_supplychain.signature_hygiene",
                    title=f"Long-lived signing/registry credential in {f.name}",
                    severity=Severity.CRITICAL, target=str(f),
                    detail="A static credential able to sign or publish releases is present. "
                           "This is the exact control that TeamPCP subverted.",
                    attack_ids=["T1553.002", "T1552.001"],
                    tags=["supplychain", "signing", "keys", "critical"],
                    remediation="Adopt keyless signing (Sigstore/Fulcio) or hardware-backed "
                                "short-lived keys in a KMS; rotate what is exposed.",
                ))
    if not saw_signing:
        out.append(Finding(
            capability="s04_supplychain.signature_hygiene",
            title="No artifact signing found in the repository", severity=Severity.MEDIUM,
            target=str(_targets(ctx)[0] if _targets(ctx) else "?"),
            detail="Neither cosign, GPG, signtool nor notarytool is used. Consumers cannot "
                   "verify the provenance of what you ship.",
            attack_ids=["T1195.001"], tags=["supplychain", "signing", "provenance"],
            remediation="Add Sigstore keyless signing to the release workflow.",
        ))
    return out


def verify_provenance(ctx: RunContext) -> list[Finding]:
    """Verify SLSA/in-toto attestations and signatures."""
    from ..core.runner import execute
    arts = ctx.opt("artifacts") or []
    if isinstance(arts, str):
        arts = [a.strip() for a in arts.split(",") if a.strip()]
    out = []
    if not arts:
        return [Finding(
            capability="s04_supplychain.provenance_verify",
            title="No artifacts supplied to verify", severity=Severity.INFO,
            target="provenance", detail="Pass --artifacts <file>[:<image>].",
            tags=["provenance"],
            remediation="Attestations are only meaningful if something checks them on pull.")]
    rp = ctx.opt("_providers", {}).get("provenance_verify")
    if rp is None or not getattr(rp, "runnable", False):
        out.append(Finding(
            capability="s04_supplychain.provenance_verify",
            title="Provenance verification UNAVAILABLE", severity=Severity.MEDIUM,
            target=",".join(arts[:4]),
            detail="cosign is not installed, so artifact provenance cannot be verified here.",
            attack_ids=["T1195.001"], tags=["provenance", "gap"],
            remediation="`winget install sigstore.cosign` or use the cosign container.",
        ))
        return out
    for art in arts[:10]:
        res = execute(rp.provider, ["verify-attestation", "--type", "slsaprovenance", art],
                      ctx.config, timeout=180)
        ok = res.ok and "verification successful" in (res.stdout or "").lower()
        out.append(Finding(
            capability="s04_supplychain.provenance_verify",
            title=f"{'Attestation valid' if ok else 'Attestation missing/invalid'}: {art}",
            severity=Severity.OK if ok else Severity.HIGH, target=art,
            detail=(res.stdout or res.stderr)[:400],
            attack_ids=["T1195.001"], tags=["provenance", "slsa"],
            remediation="If a build cannot be attested, treat the artifact as untrusted.",
        ))
    return out
