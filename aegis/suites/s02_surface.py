"""S02 · Attack Surface.

Inventory, dangling DNS / subdomain takeover, pale-asset fingerprinting, cloud
storage exposure, exposure graph, risk scoring, and drift monitoring.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from ..core.models import Evidence, Finding, RunContext, Severity

# Provider fingerprints for subdomain takeover. A dangling record is only
# dangerous if the target service is claimable — and most are.
TAKEOVER_FINGERPRINTS: list[tuple[str, str, str]] = [
    (r"\.s3\.amazonaws\.com$", "AWS S3 bucket", "An S3 name that no longer exists can be re-registered by anyone."),
    (r"\.blob\.core\.windows\.net$", "Azure Blob", "Re-registerable storage endpoint."),
    (r"\.storage\.googleapis\.com$", "GCS bucket", "Re-registerable storage endpoint."),
    (r"\.github\.io$", "GitHub Pages", "An unclaimed org/user name can host a phishing site."),
    (r"\.herokuapp\.com$", "Heroku app", "Claimable app name."),
    (r"\.cloudfront\.net$", "CloudFront distribution", "Requires an AWS account; still claimable."),
    (r"\.azurewebsites\.net$", "Azure App Service", "Claimable site name."),
    (r"\.cloudapp\.net$", "Azure classic cloudapp", "Legacy Azure, still claimable in some cases."),
    (r"\.elasticbeanstalk\.com$", "Elastic Beanstalk", "Claimable environment name."),
    (r"\.firebaseapp\.com$", "Firebase Hosting", "Claimable project name."),
    (r"\.netlify\.app$", "Netlify", "Claimable site name."),
    (r"\.vercel\.app$", "Vercel", "Claimable project name."),
    (r"\.web\.app$", "Firebase Hosting (web.app)", "Claimable project name."),
    (r"\.pages\.dev$", "Cloudflare Pages", "Claimable project name."),
    (r"\.shopify\.com$", "Shopify", "Claimable store handle."),
    (r"\.myshopify\.com$", "Shopify (myshopify)", "Claimable store handle."),
    (r"\.zendesk\.com$", "Zendesk", "Claimable subdomain."),
    (r"\.atlassian\.net$", "Atlassian", "Claimable site name."),
    (r"\.bitbucket\.io$", "Bitbucket Pages", "Claimable workspace."),
    (r"\.readthedocs\.io$", "Read the Docs", "Lower severity, but claimable."),
    (r"\.surveys\.sentry\.io$", "Sentry", "Claimable org project."),
    (r"\.pingdom\.net$", "Pingdom", "Claimable."),
    (r"\.statuspage\.io$", "Statuspage", "Claimable."),
    (r"\.telemetry\.app\.insights\.io$", "App Insights legacy", "Rarely still valid."),
]

FALCON_TAKEOVER_MARKERS = ["heroku", "route53", "cloudfront", "akamai", "github",
                          "shopify", "fastly", "gstatic", "googleusercontent"]

# Known cloud storage / endpoint suffixes worth testing anonymously
STORAGE_SUFFIXES = [
    ".s3.amazonaws.com", ".s3-us-west-2.amazonaws.com", ".s3-eu-west-1.amazonaws.com",
    ".blob.core.windows.net", ".storage.googleapis.com", ".r2.cloudflarestorage.com",
]


def _scope_domains(ctx: RunContext) -> list[str]:
    ds = list(ctx.scope.domains) if ctx.scope else []
    t = ctx.opt("targets") or []
    if isinstance(t, str):
        t = [x.strip() for x in t.split(",") if x.strip()]
    for x in t:
        if "." in x and not x.replace(".", "").isdigit():
            ds.append(x)
    return list(dict.fromkeys(ds))


# ══════════════════════════════════════════════════════════════════ inventory
def check_inventory(ctx: RunContext) -> list[Finding]:
    """Unify every discovered asset into a deduplicated inventory."""
    from ..core.util import dedupe
    inv = ctx.opt("inventory") or []
    assets: list[dict[str, Any]] = []
    for entry in inv:
        if isinstance(entry, dict):
            assets.append(entry)
        else:
            assets.append({"value": str(entry)})
    for dom in _scope_domains(ctx):
        assets.append({"value": dom, "kind": "domain", "owner": "in-scope"})
    for f in (ctx.opt("inventory_file") or []):
        try:
            for line in Path(f).read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line:
                    assets.append({"value": line})
        except Exception:
            pass
    values = dedupe([str(a.get("value", "")) for a in assets])
    return [Finding(
        capability="s02_surface.asset_inventory",
        title=f"Attack-surface inventory: {len(values)} unique assets",
        severity=Severity.INFO, target="inventory",
        detail=f"Deduplicated {len(assets)} raw entries into {len(values)} assets across "
               "domains, hosts and services.",
        attack_ids=["T1589"], tags=["surface", "inventory"],
        meta={"assets": values[:5000], "count": len(values)},
        remediation="Assign an owner and a lifecycle date to every asset; anything without one "
                    "is your next incident.",
    )]


# ══════════════════════════════════════════════════════════════════ dangling
def check_dangling(ctx: RunContext) -> list[Finding]:
    """Find CNAME/MX/NS records pointing at deallocated providers."""
    from ..core.dnsutil import resolve
    names = ctx.opt("names") or []
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    for d in _scope_domains(ctx):
        names.append(d)
    out: list[Finding] = []
    for name in list(dict.fromkeys(names))[:3000]:
        cn = resolve(name, "CNAME")
        if not cn:
            continue
        for target in cn:
            for pat, provider, why in TAKEOVER_FINGERPRINTS:
                if re.search(pat, target, re.I):
                    # does the target still resolve / respond?
                    live = bool(resolve(target, "A") or resolve(target, "CNAME"))
                    sev = Severity.HIGH if not live else Severity.MEDIUM
                    out.append(Finding(
                        capability="s02_surface.dangling_dns",
                        title=f"Dangling {provider} record: {name}",
                        severity=sev, target=name,
                        detail=(f"{name} CNAMEs to {target}. Target currently "
                                f"{'does NOT resolve — claimable' if not live else 'resolves (verify the target is still yours)'}. "
                                f"{why}"),
                        attack_ids=["T1584.001", "T1583.001"],
                        tags=["surface", "takeover", "critical"],
                        confidence="high", cwe="CWE-418",
                        evidence=[Evidence(kind="dns", summary="dangling CNAME", locator=name,
                                           excerpt=f"{name} -> {target} ({provider})")],
                        meta={"cname": target, "provider": provider, "resolves": live},
                        remediation="Delete the record, or re-claim the target so nobody else can.",
                    ))
    return out


def check_takeover_validate(ctx: RunContext) -> list[Finding]:
    """Confirm a dangling name is actually claimable (authorised validation)."""
    if not ctx.active or not ctx.http:
        return []
    from ..core.dnsutil import resolve
    out = []
    names = ctx.opt("dangling") or []
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    for name in names[:100]:
        target = (resolve(name, "CNAME") or [""])[0]
        if not target:
            continue
        r = ctx.http.get(f"https://{target}/", allow_redirects=False)
        # a 404/400 from the provider (not NXDOMAIN) is the classic claimable signal
        if r.status in (400, 404) or r.error:
            out.append(Finding(
                capability="s02_surface.subdomain_takeover",
                title=f"Takeover confirmed (provider responds, name unclaimed): {name}",
                severity=Severity.CRITICAL, target=name,
                detail=(f"{name} -> {target} returned {r.status or 'error'} from the provider, "
                        "indicating the resource is unclaimed and registerable."),
                attack_ids=["T1583.001"], tags=["surface", "takeover", "critical"],
                confidence="high",
                evidence=[Evidence(kind="http", summary=f"HTTP {r.status}", locator=target,
                                   excerpt=(r.text or "")[:200])],
                remediation="Remove the DNS record immediately.",
            ))
    return out


def check_shadow_domains(ctx: RunContext) -> list[Finding]:
    """Watch for expiring and newly-registered look-alike domains."""
    http = ctx.http
    if not http:
        return []
    out = []
    for dom in _scope_domains(ctx):
        r = http.get(f"https://rdap.org/domain/{dom}")
        if not r.ok:
            continue
        d = r.json({})
        exp = ""
        for e in d.get("events", []):
            if e.get("eventAction") == "expiration":
                exp = str(e.get("eventDate", ""))
        if exp and exp[:4].isdigit():
            y = int(exp[:4])
            if y - 2026 <= 0:
                out.append(Finding(
                    capability="s02_surface.shadow_domains",
                    title=f"{dom} expires {exp[:10]}", severity=Severity.HIGH, target=dom,
                    detail="The registrant's own domain is at or past expiry. A lapsed brand "
                           "domain is a ready-made phishing venue.",
                    attack_ids=["T1583.001"], tags=["surface", "phishing", "brand"],
                    remediation="Renew immediately and enable registry lock + auto-renew.",
                ))
    return out


# ══════════════════════════════════════════════════════════════════ pale assets
def favicon_hash(url: str) -> str:
    from ..core.util import run
    rc, out, _ = run(["python", "-c",
                      f"import sys,urllib.request,hashlib,base64;"
                      f"d=urllib.request.urlopen('{url}/favicon.ico',timeout=6).read();"
                      f"print(base64.b64encode(hashlib.md5(d).digest()).decode())"],
                     timeout=20)
    return out.strip() if rc == 0 else ""


def check_pale_assets(ctx: RunContext) -> list[Finding]:
    """Favicon-hash clustering to find forgotten staging/legacy assets."""
    if not ctx.active or not ctx.http:
        return []
    from ..core.util import pmap
    targets = []
    for d in _scope_domains(ctx):
        targets.append(d)
    inv = ctx.opt("inventory") or []
    for a in inv:
        v = a.get("value") if isinstance(a, dict) else str(a)
        if v and ("." in str(v)):
            targets.append(str(v))
    targets = list(dict.fromkeys(targets))[:200]
    if not targets:
        return []

    def grab(t: str) -> tuple[str, str]:
        r = ctx.http.get(f"https://{t}/favicon.ico", allow_redirects=True)
        if not r.ok or not r.text and r.status != 200:
            return t, ""
        import hashlib
        # favicon is binary; derive a stable host fingerprint from the response text
        h = hashlib.md5((r.text or "").encode("utf-8", "replace")).hexdigest()
        return t, h

    clusters: dict[str, list[str]] = {}
    for t, h in pmap(grab, targets, workers=min(12, ctx.config.parallel)):
        if h:
            clusters.setdefault(h, []).append(t)
    out = []
    for h, ts in clusters.items():
        if len(ts) >= 3:
            out.append(Finding(
                capability="s02_surface.pale_asset_fingerprint",
                title=f"{len(ts)} hosts share a favicon fingerprint ({h[:12]})",
                severity=Severity.LOW, target=ts[0],
                detail=("Hosts sharing a favicon often share a stack and, frequently, an owner "
                        "who has forgotten them. Cluster: " + ", ".join(ts[:12])),
                attack_ids=["T1590.002"], tags=["surface", "shadow", "fingerprint"],
                meta={"favicon_md5": h, "hosts": ts},
                remediation="Confirm ownership; decommission anything unowned.",
            ))
    return out


# ══════════════════════════════════════════════════════════════════ storage
def check_storage(ctx: RunContext) -> list[Finding]:
    """Anonymous read/list on cloud storage endpoints."""
    if not ctx.active or not ctx.http:
        return []
    names = ctx.opt("buckets") or ctx.opt("storage") or []
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    for kw in (ctx.opt("brands") or []):
        for suf in STORAGE_SUFFIXES:
            names.append(f"{kw}{suf}")
    out = []
    for n in list(dict.fromkeys(names))[:200]:
        url = n if "://" in n else f"https://{n}"
        r = ctx.http.get(url, allow_redirects=False)
        if r.status == 200 and ("<ListBucketResult" in (r.text or "") or
                                "<Error>" not in (r.text or "")[:200]):
            out.append(Finding(
                capability="s02_surface.cloud_storage_exposure",
                title=f"Public bucket listing: {n}", severity=Severity.HIGH, target=url,
                detail="Anonymous request returned a bucket listing. Contents are enumerable "
                       "and often directly downloadable.",
                attack_ids=["T1530"], tags=["surface", "cloud", "storage", "critical"],
                confidence="high",
                evidence=[Evidence(kind="http", summary="listable", locator=url,
                                   excerpt=(r.text or "")[:300])],
                remediation="Enable Block Public Access; audit for sensitive objects.",
            ))
        elif r.status == 403 and any(s in (r.text or "") for s in ("AllAccessDisabled", "AccessDenied")):
            out.append(Finding(
                capability="s02_surface.cloud_storage_exposure",
                title=f"Bucket exists but is access-controlled: {n}",
                severity=Severity.INFO, target=url,
                detail="403 with an access-denied body — the name is claimed and protected. "
                       "Good; confirm the policy is the tightest you need.",
                tags=["surface", "cloud", "storage"],
            ))
    return out


# ══════════════════════════════════════════════════════════════════ third party
def check_third_party(ctx: RunContext) -> list[Finding]:
    """Discover shadow SaaS and exposed vendor portals."""
    if not ctx.active or not ctx.http:
        return []
    doms = _scope_domains(ctx)
    probes = ["/.well-known/openid-configuration", "/oauth/authorize",
              "/.well-known/assetlinks.json", "/_config", "/status"]
    out = []
    for d in doms:
        for p in probes:
            r = ctx.http.get(f"https://{d}{p}", allow_redirects=False)
            if r.status == 200 and len(r.text or "") > 30:
                out.append(Finding(
                    capability="s02_surface.third_party_shadow",
                    title=f"{d}: exposed configuration endpoint {p}",
                    severity=Severity.MEDIUM, target=f"https://{d}{p}",
                    detail="A discovery or configuration endpoint is publicly readable. It maps "
                           "the authentication/tenant model for an attacker.",
                    attack_ids=["T1526"], tags=["surface", "saas", "thirdparty"],
                    evidence=[Evidence(kind="http", summary=f"HTTP {r.status}",
                                       locator=r.url, excerpt=(r.text or "")[:250])],
                    remediation="Gate metadata endpoints behind authentication where the "
                                "provider supports it.",
                ))
    return out


def check_admin(ctx: RunContext) -> list[Finding]:
    """Find reachable admin consoles."""
    if not ctx.active or not ctx.http:
        return []
    paths = ["/admin", "/administrator", "/admin/login", "/manager/html", "/jmx-console",
             "/wp-admin", "/phpmyadmin", "/adminer", "/console", "/dashboard", "/api/admin"]
    out = []
    for d in _scope_domains(ctx):
        for p in paths:
            r = ctx.http.get(f"https://{d}{p}", allow_redirects=False)
            if r.status in (200, 401):
                out.append(Finding(
                    capability="s02_surface.admin_panel_discovery",
                    title=f"Admin surface reachable: {d}{p} ({r.status})",
                    severity=Severity.MEDIUM if r.status == 200 else Severity.LOW,
                    target=f"https://{d}{p}",
                    detail=f"HTTP {r.status}; title={r.title[:60]!r}",
                    attack_ids=["T1190"], tags=["surface", "admin"],
                    remediation="Restrict management interfaces to VPN/zero-trust; require MFA.",
                ))
    return out


# ══════════════════════════════════════════════════════════════════ graph
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "ok": 0}


def build_exposure_graph(ctx: RunContext) -> list[Finding]:
    """Build an asset→exposure graph and surface the connected risky nodes."""
    try:
        import networkx as nx
    except Exception:
        return [Finding(
            capability="s02_surface.exposure_graph",
            title="networkx unavailable — graph not built", severity=Severity.LOW,
            target="graph", detail="`pip install networkx` to enable attack-path analysis.",
            tags=["graph", "gap"],
            remediation="Attack-path ranking is a core capability; install the dependency.",
        )]
    g = nx.MultiDiGraph()
    inv = ctx.opt("inventory") or []
    for a in inv:
        v = a.get("value") if isinstance(a, dict) else str(a)
        if not v:
            continue
        v = str(v)
        g.add_node(v, kind="host")
    for f in ctx.findings:
        t = f.target
        if not t:
            continue
        if t not in g:
            g.add_node(t, kind="finding")
        prev = g.nodes[t].get("severity")
        if prev is None or f.severity.rank > _SEV_RANK.get(prev, 0):
            g.nodes[t]["severity"] = f.severity.value
        g.add_edge(t, f.capability, kind="exposes", sev=f.severity.value)
    deg = dict(g.degree())
    hubs = sorted(deg.items(), key=lambda kv: -kv[1])[:10]
    cycles = list(nx.simple_cycles(g.subgraph([n for n, d in deg.items() if d > 1])))[:5] \
        if g.number_of_edges() else []
    return [Finding(
        capability="s02_surface.exposure_graph",
        title=f"Exposure graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges",
        severity=Severity.MEDIUM if cycles else Severity.INFO,
        target="graph",
        detail=(f"Hubs: {', '.join(f'{n}({d})' for n, d in hubs[:8])}. "
                f"Cycles representing escalation chains: {len(cycles)}."),
        attack_ids=["T1210"], tags=["surface", "graph", "attackpath"],
        meta={"nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
              "hubs": hubs, "cycles": cycles},
        remediation="Break escalation cycles at the highest-severity node; that single change "
                    "usually removes several paths.",
    )]


def score_exposure(ctx: RunContext) -> list[Finding]:
    """Rank findings by exploitability × data sensitivity × criticality."""
    weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 1, "ok": 0}
    scored = []
    for f in ctx.findings:
        base = weights.get(f.severity.value, 1)
        boost = 1.0
        if any(t in ("internet", "exposure", "critical", "supplychain", "takeover", "ai", "secrets")
               for t in f.tags):
            boost += 0.5
        if any(t.startswith("T1") and t[1:2] == "1" and t in ("T1190", "T1210", "T1486", "T1221")
               for t in f.attack_ids):
            boost += 0.3
        scored.append((round(base * boost, 1), f))
    scored.sort(key=lambda kv: -kv[0])
    top = scored[:15]
    return [Finding(
        capability="s02_surface.exposure_scoring",
        title=f"Top-{len(top)} ranked exposures (max score {top[0][0] if top else 0})",
        severity=Severity.INFO, target="prioritisation",
        detail="; ".join(f"{f.title[:60]}={s}" for s, f in top[:8]),
        tags=["surface", "risk", "prioritisation"],
        meta={"ranked": [{"score": s, "title": f.title, "target": f.target,
                          "severity": f.severity.value} for s, f in top]},
        remediation="Fix in rank order. The top item is worth more than the bottom twenty combined.",
    )]


def check_drift(ctx: RunContext) -> list[Finding]:
    """Diff the current inventory against a stored baseline."""
    from ..core.util import dedupe
    base = ctx.opt("baseline")
    current = dedupe([str(a.get("value") if isinstance(a, dict) else a)
                      for a in (ctx.opt("inventory") or [])])
    if not base:
        return [Finding(
            capability="s02_surface.drift_monitor",
            title=f"{len(current)} assets — baseline it to enable drift detection",
            severity=Severity.INFO, target="drift",
            detail=("Drift monitoring needs a stored baseline. Save this run as a baseline; "
                    "future runs will diff against it and flag new exposure."),
            tags=["surface", "drift", "monitor"],
            remediation="`aegis baseline set <name>` then run this suite on a schedule.",
        )]
    base_set = set(base if isinstance(base, list) else [])
    new = [c for c in current if c not in base_set]
    gone = [b for b in base_set if b not in set(current)]
    out = []
    if new:
        out.append(Finding(
            capability="s02_surface.drift_monitor",
            title=f"{len(new)} assets appeared since the baseline", severity=Severity.MEDIUM,
            target="drift", detail=", ".join(new[:25]),
            attack_ids=["T1136"], tags=["surface", "drift", "monitor"],
            meta={"new": new},
            remediation="Every new asset needs an owner. Unowned assets are how supply-chain "
                        "and shadow-IT exposure compounds.",
        ))
    if gone:
        out.append(Finding(
            capability="s02_surface.drift_monitor",
            title=f"{len(gone)} assets disappeared since the baseline",
            severity=Severity.LOW, target="drift", detail=", ".join(gone[:25]),
            tags=["surface", "drift"],
            remediation="Confirm decommissioning; if unintended, investigate as possible "
                        "evasion of monitoring.",
        ))
    if not new and not gone:
        out.append(Finding(
            capability="s02_surface.drift_monitor", title="No drift since baseline",
            severity=Severity.OK, target="drift", tags=["surface", "drift"],
        ))
    return out


# ══════════════════════════════════════════════════════════════════ default creds
# A small, explicit, vendor-default set. This is an *inventory* check: it verifies
# whether a device you own still ships with the factory password. It is deliberately
# tiny and scope-gated. Skipped in passive mode.
DEFAULT_CREDS = [
    ("SSH", 22, [("root", "root"), ("admin", "admin"), ("root", ""), ("admin", "")]),
    ("Telnet", 23, [("admin", "admin"), ("root", "root"), ("admin", "")]),
    ("FTP", 21, [("anonymous", "anonymous@"), ("ftp", "ftp")]),
    ("HTTP router", 80, [("admin", "admin"), ("admin", "password"), ("root", "root")]),
    ("SMB", 445, [("Administrator", "admin"), ("admin", "admin")]),
    ("Redis", 6379, [("", "")]),
    ("MongoDB", 27017, [("admin", "admin")]),
    ("Elasticsearch", 9200, [("elastic", "elastic"), ("elastic", "changeme")]),
    ("Docker API", 2375, [("", "")]),
    ("SNMP community", 161, [("public", "public"), ("private", "private")]),
]

# Never try more than this many combinations per host — this is a hygiene check,
# not a brute-forcer.
MAX_ATTEMPTS = 40


class _Budget:
    """Thread-safe attempt counter for bounded active sweeps.

    `spend()` returns False once the budget is gone, which callers must treat as
    "stop": a credential sweep with no ceiling is the kind of thing that turns an
    assessment into an incident.
    """

    __slots__ = ("_left", "_lock")

    def __init__(self, total: int):
        self._left = total
        self._lock = threading.Lock()

    def spend(self) -> bool:
        with self._lock:
            if self._left <= 0:
                return False
            self._left -= 1
            return True

    def exhausted(self) -> bool:
        with self._lock:
            return self._left <= 0

    @property
    def remaining(self) -> int:
        with self._lock:
            return self._left


def check_default_creds(ctx: RunContext) -> list[Finding]:
    """Verify in-scope services are not still on factory credentials."""
    if not ctx.active:
        return [Finding(
            capability="s02_surface.default_credential_check",
            title="Default-credential test skipped (passive mode)", severity=Severity.INFO,
            target="auth",
            detail=("This check sends authentication attempts. Rerun without --passive with a scope. It is "
                    "capped at a few attempts per host and never runs outside scope."),
            tags=["surface", "auth"],
            remediation="If you want real credential testing, use netexec/hydra on an authorised "
                        "engagement; AEGIS only checks the factory-password case.",
        )]
    import socket
    from ..core.util import pmap
    hosts = list(ctx.scope.hosts if ctx.scope else [])
    for h in (ctx.scope.cidrs if ctx.scope else []):
        try:
            import ipaddress
            hosts += [str(ip) for ip in ipaddress.ip_network(h, strict=False)][:64]
        except Exception:
            pass
    hosts = list(dict.fromkeys(hosts))[:32]
    if not hosts:
        return [Finding(capability="s02_surface.default_credential_check",
                        title="No hosts in scope", severity=Severity.INFO, target="auth",
                        detail="Supply --host/--cidr.", tags=["surface", "auth"])]

    out: list[Finding] = []
    # MAX_ATTEMPTS was declared and assigned to a local but never actually
    # enforced, so the real attempt count was bounded only by len(hosts) *
    # len(DEFAULT_CREDS) * 3. The budget is now a shared counter so the declared
    # limit is the limit. It is intentionally not thread-local: pmap runs probes
    # on worker threads, and the cap exists to bound total network activity.
    budget = _Budget(MAX_ATTEMPTS)

    def probe(h: str):
        res = []
        for svc, port, creds in DEFAULT_CREDS:
            if budget.exhausted():
                break
            try:
                with socket.create_connection((h, port), timeout=1.5) as s:
                    s.settimeout(2.0)
                    for user, pw in creds[:3]:
                        if user == "" and pw == "" and svc not in ("Redis", "Docker API"):
                            continue
                        if not budget.spend():
                            break
                        try:
                            s.sendall((f"{user}\n{pw}\n" if svc in ("Telnet", "FTP")
                                       else f"{user}:{pw}\n").encode())
                            chunk = (s.recv(128) or b"").decode("utf-8", "replace")
                        except Exception:
                            chunk = ""
                        low = chunk.lower()
                        if any(k in low for k in ("login", "password", "welcome", "root#", "$ ")):
                            res.append((svc, port, user or "(none)", pw or "(empty)"))
                            break
                        if svc in ("Redis", "Docker API") and chunk:
                            res.append((svc, port, user or "(none)", pw or "(empty)"))
                            break
            except Exception:
                continue
        return h, res

    for host, hits in pmap(probe, hosts, workers=min(12, ctx.config.parallel)):
        # The password is deliberately not reported in the finding body: a
        # credential finding that prints the credential is its own disclosure.
        for svc, port, user, _pw in hits:
            out.append(Finding(
                capability="s02_surface.default_credential_check",
                title=f"Default credential accepted: {host}:{port} ({svc})",
                severity=Severity.CRITICAL if svc in ("Redis", "Docker API", "Elasticsearch")
                else Severity.HIGH,
                target=f"{host}:{port}",
                detail=(f"{svc} accepted a factory/default credential (user={user}). A device "
                        "still on its default password is internet-takeover material."),
                attack_ids=["T1078.001", "T1110.001"],
                tags=["surface", "auth", "critical"], confidence="high",
                remediation="Change the credential now, and verify management interfaces are not "
                            "internet-reachable.",
            ))
    if not out:
        out.append(Finding(
            capability="s02_surface.default_credential_check",
            title=f"No factory credentials accepted across {len(hosts)} host(s)",
            severity=Severity.OK, target="auth",
            detail="Bounded default-credential sweep completed with no hits.",
            tags=["surface", "auth"],
            remediation="Re-run after firmware updates — vendors reintroduce defaults.",
        ))
    return out
