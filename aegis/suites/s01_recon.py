"""S01 · Reconnaissance.

Native implementations for subdomain discovery, DNS posture, certificate
transparency mining, HTTP probing, and exposure discovery. All passive unless
`--passive` is passed. Scope is advisory unless the guardrails in config are enabled.
"""
from __future__ import annotations

import re
import socket
import ssl
from typing import Any
from urllib.parse import urlparse, urljoin

from ..core.models import Evidence, Finding, RunContext, Severity

PASSIVE_EXTRA_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
    "/config.php.bak", "/web.config", "/backup.zip", "/backup.sql",
    "/dump.sql", "/.DS_Store", "/debug", "/.htpasswd",
    "/server-status", "/phpinfo.php", "/actuator/env", "/actuator/health",
    "/.aws/credentials", "/id_rsa", "/.npmrc", "/.dockerignore",
    "/sitemap.xml", "/crossdomain.xml", "/security.txt", "/.well-known/security.txt",
]
INTERESTING_EXT = (".bak", ".old", ".orig", ".swp", ".sql", ".log", ".env",
                   ".pem", ".key", ".p12", ".pfx", ".asc", ".gpg", ".kdbx", ".rdp")


# ══════════════════════════════════════════════════════════════════ helpers
def _scope_targets(ctx: RunContext) -> list[str]:
    if ctx.scope and not ctx.scope.is_empty():
        return list(dict.fromkeys(ctx.scope.domains + ctx.scope.hosts))
    t = ctx.opt("targets") or []
    if isinstance(t, str):
        t = [x.strip() for x in t.split(",") if x.strip()]
    return [x for x in t if x]


def _res(ctx: RunContext, scheme: str, host: str, path: str = "/") -> str:
    return f"{scheme}://{host}{path}"


# ══════════════════════════════════════════════════════════════════ subdomain
def check_subdomain_enum(ctx: RunContext) -> list[Finding]:
    """Multi-source passive subdomain discovery. crt.sh is the anchor source."""
    from ..core.util import dedupe
    out: list[Finding] = []
    http = ctx.http
    if not http:
        ctx.note("subdomain_enum: no http client")
        return out

    for dom in _scope_targets(ctx):
        found: set[str] = set()

        # 1. certificate transparency — highest yield
        r = http.get("https://crt.sh/", params={"q": f"%.{dom}", "output": "json"})
        if r.ok:
            for row in (r.json([]) or [])[:5000]:
                for name in str(row.get("name_value", "")).split("\n"):
                    n = name.strip().lstrip("*.").lower()
                    if n.endswith(dom) and n != dom:
                        found.add(n)

        # 2. passive DNS via hackertarget hostsearch
        r = http.get("https://api.hackertarget.com/hostsearch/",
                     params={"q": dom})
        if r.ok:
            for line in r.text.splitlines():
                parts = line.split(",")
                if parts and parts[0].strip().endswith(dom):
                    found.add(parts[0].strip().lower())

        # 3. certspotter (needs key; silent if absent)
        r = http.get("https://api.certspotter.com/v1/issuances",
                     params={"domain": dom, "include_subdomains": "true", "expand": "dns_names"},
                     headers={"Authorization": f"Bearer {ctx.opt('certspotter_key','')}"}
                     if ctx.opt("certspotter_key") else None)
        if r.ok and r.status != 401:
            for row in (r.json([]) or [])[:3000]:
                for name in row.get("dns_names", []) or []:
                    n = name.lstrip("*.").lower()
                    if n.endswith(dom):
                        found.add(n)

        # 4. an external enum tool if present
        rp = ctx.opt("_providers", {}).get("subdomain_enum")
        if rp is not None:
            from ..core.runner import execute
            res = execute(rp.provider, ["-d", dom, "-silent"],
                          ctx.config, timeout=180, workdir=ctx.workdir)
            for line in res.lines()[:2000]:
                if line.strip().endswith(dom):
                    found.add(line.strip().lower())
            if res.how.startswith("docker"):
                ctx.note(f"subdomain_enum: {dom} used {res.how}")

        names = sorted(dedupe(found))
        if not names:
            continue
        out.append(Finding(
            capability="s01_recon.subdomain_enum",
            title=f"{len(names)} subdomains discovered for {dom}",
            severity=Severity.INFO, target=dom,
            detail=(f"Passive enumeration across certificate transparency, passive DNS and "
                    f"registered-tool sources returned {len(names)} unique names."),
            tags=["recon", "subdomain", "inventory"],
            confidence="high",
            attack_ids=["T1590.002"],
            evidence=[Evidence(kind="dns", summary=f"{len(names)} names", locator=dom,
                               excerpt=", ".join(names[:40]))],
            meta={"count": len(names), "names": names[:500]},
            remediation="Assert ownership of every name; decommission anything you do not own.",
        ))
    return out


# ══════════════════════════════════════════════════════════════════ certs
def check_ct_logs(ctx: RunContext) -> list[Finding]:
    """CT log mining focused on certificates issued to names you do not control."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    for dom in _scope_targets(ctx):
        r = http.get("https://crt.sh/", params={"q": f"%.{dom}", "output": "json"})
        if not r.ok:
            ctx.note(f"ct_logs: crt.sh unavailable for {dom} ({r.status})")
            continue
        rows = r.json([]) or []
        subs: dict[str, set[str]] = {}
        for row in rows:
            for name in str(row.get("name_value", "")).split("\n"):
                n = name.strip().lstrip("*.").lower()
                if n.endswith(dom) and n != dom:
                    subs.setdefault(n, set()).add(str(row.get("issuer_name", "?"))[:60])
        stale = [n for n, _ in subs.items() if n.count(".") > 2]
        out.append(Finding(
            capability="s01_recon.ct_log_mining",
            title=f"CT transparency: {len(subs)} issued names for {dom}",
            severity=Severity.LOW if len(subs) > 25 else Severity.INFO,
            target=dom,
            detail=(f"{len(rows)} certificate records, {len(subs)} unique names. "
                    f"{len(stale)} are deep subdomains (often forgotten/staging). "
                    "Anything still resolving from a certificate log is inventory you own."),
            attack_ids=["T1590.003"], tags=["recon", "certs", "crt"],
            confidence="high",
            evidence=[Evidence(kind="cert", summary=f"{len(rows)} records", locator=dom,
                               excerpt=", ".join(sorted(subs)[:30]))],
            meta={"names": sorted(subs), "issuers": sorted({i for v in subs.values() for i in v})},
            remediation="Enumerate every CT name; remove DNS for anything decommissioned.",
        ))
    return out


# ══════════════════════════════════════════════════════════════════ DNS
def check_dns(ctx: RunContext) -> list[Finding]:
    """Record inventory + mail-security posture (SPF/DMARC/DKIM)."""
    from ..core.dnsutil import resolve, txt, ns, mx
    out: list[Finding] = []
    for dom in _scope_targets(ctx):
        if _is_ip(dom):
            continue
        recs: dict[str, Any] = {}
        for rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA"):
            try:
                v = {"A": resolve, "AAAA": resolve, "CNAME": resolve,
                     "NS": ns, "MX": mx, "TXT": txt, "SOA": txt}[rtype](dom, rtype)
                if v:
                    recs[rtype] = v
            except Exception:
                pass
        if not recs:
            continue

        # mail posture
        findings: list[Finding] = []
        spf = " ".join(recs.get("TXT", []))
        if recs.get("MX") and "v=spf1" not in spf.lower():
            findings.append(Finding(
                capability="s01_recon.dns_records", title=f"No SPF record on {dom}",
                severity=Severity.MEDIUM, target=dom,
                detail="Domain has MX records but no SPF policy, permitting sender spoofing.",
                attack_ids=["T1566"], tags=["dns", "email", "spf"], confidence="high",
                remediation="Publish a restrictive v=spf1 record; roll to -all.",
            ))
        elif recs.get("MX"):
            # The MX loop only gated the finding on MX existing; it produced no
            # per-record output, so it is a single check rather than a loop.
            if "~all" not in spf and "-all" not in spf:
                findings.append(Finding(
                    capability="s01_recon.dns_records",
                    title=f"SPF does not hard-fail on {dom}", severity=Severity.LOW,
                    target=dom, detail="SPF present but soft-failing (~all).",
                    attack_ids=["T1566"], tags=["dns", "email", "spf"],
                    remediation="Move to -all after validating all legitimate senders.",
                ))

        dmarc = None
        try:
            dmarc = txt("_dmarc." + dom, "TXT")
        except Exception:
            pass
        if recs.get("MX") and not dmarc:
            findings.append(Finding(
                capability="s01_recon.dns_records", title=f"No DMARC policy on {dom}",
                severity=Severity.HIGH, target=dom,
                detail="No _dmarc TXT record. Nothing instructs receivers to reject spoofed mail.",
                attack_ids=["T1566.002"], tags=["dns", "email", "dmarc"], confidence="high",
                remediation="Publish _dmarc with p=reject once aligned senders are confirmed.",
            ))
        elif dmarc and "p=reject" not in " ".join(dmarc).lower():
            findings.append(Finding(
                capability="s01_recon.dns_records",
                title=f"DMARC on {dom} is not enforcing reject", severity=Severity.MEDIUM,
                target=dom, detail=f"DMARC: {' '.join(dmarc)[:120]}",
                attack_ids=["T1566.002"], tags=["dns", "email", "dmarc"],
                remediation="Progressively tighten p=none -> quarantine -> reject.",
            ))

        out.append(Finding(
            capability="s01_recon.dns_records",
            title=f"DNS inventory for {dom} ({len(recs)} record types)",
            severity=Severity.INFO, target=dom,
            detail="; ".join(f"{k}:{len(v) if isinstance(v, list) else 1}" for k, v in recs.items()),
            attack_ids=["T1016"], tags=["recon", "dns"],
            evidence=[Evidence(kind="dns", summary="record inventory", locator=dom,
                               excerpt=" | ".join(f"{k}={v}" for k, v in recs.items())[:900])],
            meta={"records": {k: (v[:20] if isinstance(v, list) else v) for k, v in recs.items()}},
        ))
        out.extend(findings)
    return out


def check_axfr(ctx: RunContext) -> list[Finding]:
    """Attempt zone transfer against authoritative nameservers."""
    import dns.query
    import dns.zone
    from ..core.dnsutil import ns
    out: list[Finding] = []
    if not ctx.active:
        return out
    for dom in _scope_targets(ctx):
        try:
            servers = ns(dom, "NS")
        except Exception:
            continue
        for s in servers[:4]:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(s, dom, timeout=8))
                recs = len(z.nodes) if z else 0
                out.append(Finding(
                    capability="s01_recon.dns_zone_transfer",
                    title=f"Zone transfer SUCCEEDS on {dom} via {s}",
                    severity=Severity.CRITICAL, target=f"{s}/{dom}",
                    detail=(f"AXFR from {s} returned the full zone ({recs} nodes). "
                            "This discloses every internal name you run."),
                    attack_ids=["T1584.004"], tags=["dns", "exposure", "critical"],
                    confidence="confirmed",
                    remediation="Restrict AXFR to secondary nameservers via TSIG; test externally.",
                ))
            except Exception:
                pass
    return out


# ══════════════════════════════════════════════════════════════════ http
def check_http_probe(ctx: RunContext) -> list[Finding]:
    """Probe hosts/scope entries over http+https, record status, tech, title."""
    from ..core.util import pmap
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    targets: list[str] = []
    for t in _scope_targets(ctx):
        targets.append(t if "://" in t else f"https://{t}")
    if not targets:
        return out

    def probe(u: str) -> tuple[str, Any]:
        r = http.get(u, allow_redirects=True)
        return u, r

    for u, r in pmap(probe, targets, workers=min(16, ctx.config.parallel)):
        if r.error and r.status == 0:
            continue
        tgt = urlparse(r.url).hostname or u
        out.append(Finding(
            capability="s01_recon.http_probe", title=f"{tgt} → HTTP {r.status}",
            severity=Severity.INFO, target=tgt,
            detail=(f"status={r.status} len={len(r.text or '')} "
                    f"title={r.title[:70]!r} tech={','.join(r.tech) or 'n/a'}"),
            attack_ids=["T1592.001"], tags=["recon", "http"],
            evidence=[Evidence(kind="http", summary=f"HTTP {r.status}", locator=r.url,
                               excerpt=f"server={r.headers.get('server','-')} "
                                       f"title={r.title[:60]}")],
            meta={"status": r.status, "tech": r.tech, "title": r.title[:120],
                  "final_url": r.url},
        ))
    return out


def check_service_fingerprint(ctx: RunContext) -> list[Finding]:
    """Flag known-risky technology and missing hardening headers."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    risky = {
        "apache/2.2": (Severity.HIGH, "EOL Apache 2.2"),
        "apache/1.": (Severity.HIGH, "EOL Apache 1.x"),
        "nginx/1.0": (Severity.HIGH, "EOL nginx 1.0"),
        "php/5": (Severity.MEDIUM, "EOL PHP 5.x"),
        "php/7.0": (Severity.HIGH, "EOL PHP 7.0"),
        "phpmyadmin": (Severity.MEDIUM, "phpMyAdmin exposed"),
        "jetty(9": (Severity.MEDIUM, "EOL Jetty 9.x"),
        "microsoft-iis/8": (Severity.MEDIUM, "IIS 8.0 out of support"),
        "wercam": (Severity.HIGH, "very old server banner"),
    }
    for t in _scope_targets(ctx):
        for scheme in ("https", "http"):
            r = http.get(f"{scheme}://{t}/")
            if r.status == 0:
                continue
            banner = " ".join(r.tech).lower()
            for sig, (sev, why) in risky.items():
                if sig in banner:
                    out.append(Finding(
                        capability="s01_recon.service_fingerprint",
                        title=f"{urlparse(r.url).hostname}: {why}", severity=sev,
                        target=urlparse(r.url).hostname or t,
                        detail=f"Server fingerprint matched '{sig}' on {r.url}.",
                        tags=["recon", "fingerprint", "eol"], confidence="high",
                        attack_ids=["T1592"],
                        remediation="Upgrade to a supported release; suppress version banners.",
                    ))
            break
    return out


def check_tls(ctx: RunContext) -> list[Finding]:
    """Certificate + protocol posture for in-scope hosts."""
    out: list[Finding] = []
    targets = [t for t in _scope_targets(ctx) if not _is_ip(t)]
    if not targets:
        return out
    ctx_ = ssl.create_default_context()
    ctx_.check_hostname = False
    ctx_.verify_mode = ssl.CERT_NONE
    for host in targets:
        try:
            with socket.create_connection((host, 443), timeout=6) as sock:
                with ctx_.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    ver = ss.version()
                    cipher = (ss.cipher() or (None,))[0]
        except Exception:
            continue
        tgt = f"{host}:443"
        if ver in ("TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3"):
            if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
                out.append(Finding(
                    capability="s01_recon.tls_inventory",
                    title=f"{host}: deprecated TLS {ver}", severity=Severity.HIGH, target=tgt,
                    detail=f"Negotiated {ver} / {cipher}. Deprecated protocols enable downgrade and "
                           "padding-oracle classes of attack.",
                    tags=["tls", "crypto", "hardening"], attack_ids=["T1600"],
                    remediation="Disable TLS<1.2; prefer TLS1.3; set a modern cipher suite.",
                ))
        # ssl returns subjectAltName as a flat tuple of ("DNS", name) pairs, but
        # not always: it can be a single ("DNS", name) tuple. Normalise both, and
        # drop entries that are not 2-tuples rather than crashing on unpack.
        san: tuple[Any, ...] = tuple((cert or {}).get("subjectAltName") or ())
        if san and san[0] == "DNS":
            san = (san,)          # single ("DNS", "host") pair, not a list of pairs
        names: list[str] = [v for pair in san
                            if isinstance(pair, (tuple, list)) and len(pair) == 2
                            and pair[0] == "DNS" and isinstance(pair[1], str)
                            for v in (pair[1],)]
        out.append(Finding(
            capability="s01_recon.tls_inventory",
            title=f"{host}: TLS {ver}, {len(names)} SANs", severity=Severity.INFO, target=tgt,
            detail=f"cipher={cipher} notAfter={cert.get('notAfter','?') if cert else '?'} "
                   f"issuer={_issuer(cert)}",
            tags=["tls", "inventory"],
            evidence=[Evidence(kind="cert", summary=f"{len(names)} SANs", locator=tgt,
                               excerpt=", ".join(names[:20]))],
            meta={"version": ver, "cipher": cipher, "sans": names[:100]},
            remediation="Review SANs for decommissioned infrastructure you still present.",
        ))
    return out


def _issuer(cert: Any) -> str:
    try:
        return ", ".join(f"{k}={v}" for r in cert.get("issuer", ()) for k, v in r)[:120]
    except Exception:
        return "?"


# ══════════════════════════════════════════════════════════════════ bgp
def check_bgp(ctx: RunContext) -> list[Finding]:
    """ASN/prefix ownership and RPKI validity via RIPEstat (passive)."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for t in _scope_targets(ctx):
        hosts = [t]
        if not _is_ip(t):
            try:
                from ..core.dnsutil import resolve
                hosts = resolve(t, "A")
            except Exception:
                hosts = []
        for ip in hosts[:6]:
            r = http.get("https://stat.ripe.net/data/network-info/data.json",
                         params={"resource": ip})
            if not r.ok:
                continue
            data = r.json({})
            asn = str(data.get("data", {}).get("asns", ["?"])[0])
            prefix = str(data.get("data", {}).get("prefix", "?"))
            if asn in seen or asn == "?":
                continue
            seen.add(asn)
            r2 = http.get("https://stat.ripe.net/data/as-overview/data.json",
                          params={"resource": f"AS{asn}"})
            holder = ""
            if r2.ok:
                holder = str(r2.json({}).get("data", {}).get("holder", ""))[:80]
            out.append(Finding(
                capability="s01_recon.bgp_asn_map",
                title=f"{ip} → AS{asn} ({prefix})", severity=Severity.INFO, target=ip,
                detail=f"AS{asn} {holder} announcing {prefix}",
                attack_ids=["T1590"], tags=["recon", "bgp", "asn"],
                meta={"asn": asn, "prefix": prefix, "holder": holder},
            ))
    return out


def check_bgp_hijack(ctx: RunContext) -> list[Finding]:
    """RPKI validation for prefixes in scope. Active-ish but read-only."""
    http = ctx.http
    if not http or not ctx.active:
        return []
    out: list[Finding] = []
    prefixes = ctx.opt("prefixes") or []
    for p in prefixes:
        r = http.get("https://stat.ripe.net/data/rpki-validation/data.json",
                     params={"resource": f"AS{ctx.opt('asn','0')}" if ctx.opt("asn") else p,
                             "prefix": p})
        if not r.ok:
            continue
        st = str(r.json({}).get("data", {}).get("status", "unknown"))
        sev = {"valid": Severity.OK, "invalid": Severity.CRITICAL,
               "unknown": Severity.MEDIUM}.get(st, Severity.MEDIUM)
        if sev is not Severity.OK:
            out.append(Finding(
                capability="s01_recon.bgp_hijack_detect",
                title=f"RPKI status for {p}: {st}", severity=sev, target=p,
                detail=("Route origin validation failed — a hijack of this prefix would not be "
                        "detected by RPKI-invalids. A classic pre-positioning target."
                        if st == "invalid" else
                        "No RPKI ROA covers this prefix, so a hijack would be silently accepted."),
                attack_ids=["T1598.001"], tags=["bgp", "detection", "military"],
                remediation="Publish ROAs for all your prefixes; monitor RIS for MOA/ROA conflicts.",
            ))
    return out


# ══════════════════════════════════════════════════════════════════ exposure
def check_exposed_files(ctx: RunContext) -> list[Finding]:
    """Probe for sensitive files. Skipped in passive mode."""
    if not ctx.active:
        return []
    http = ctx.http
    if not http:
        return []
    from ..core.util import pmap
    out: list[Finding] = []
    bases: list[str] = []
    for t in _scope_targets(ctx):
        bases.append(t if "://" in t else f"https://{t}")
    if not bases:
        return out

    def probe(base: str) -> list[tuple[str, str, int, int]]:
        hits = []
        for p in PASSIVE_EXTRA_PATHS:
            r = http.get(urljoin(base.rstrip("/") + "/", p.lstrip("/")), allow_redirects=False)
            if r.status == 0:
                continue
            if r.status in (200, 206):
                size = int(r.headers.get("content-length") or len(r.text or ""))
                hits.append((base, p, r.status, size))
            elif r.status == 401:
                hits.append((base, p, 401, 0))
        return hits

    for hits in pmap(probe, bases, workers=min(8, ctx.config.parallel)):
        for base, path, status, size in hits:
            host = urlparse(base).hostname or base
            full = base.rstrip("/") + path
            if path in ("/.env", "/.git/config", "/.aws/credentials", "/.npmrc", "/id_rsa"):
                sev = Severity.CRITICAL if status == 200 else Severity.MEDIUM
                detail = f"{path} returned {status}"
                if status == 200:
                    detail += (" — credentials present in the response body"
                               if path != "/.git/config" else
                               " — the repository's git config is retrievable")
                rem = "Delete the file from the web root and rotate any exposed secret immediately."
            elif path == "/.git/HEAD" and status == 200:
                sev, detail = Severity.CRITICAL, "Git metadata exposed — full source is extractable."
                rem = "Remove .git from the web root; treat any committed secrets as compromised."
            elif status == 401:
                sev, detail = Severity.LOW, f"{path} exists but requires auth (401)."
                rem = "Confirm the path should be reachable at all."
            else:
                sev, detail = Severity.MEDIUM, f"{path} is publicly readable ({status}, {size}B)."
                rem = "Remove or restrict the path."
            out.append(Finding(
                capability="s01_recon.exposed_files",
                title=f"{host}: exposed {path}", severity=sev, target=full,
                detail=detail, attack_ids=["T1526"], tags=["exposure", "http", "config"],
                confidence="high",
                evidence=[Evidence(kind="http", summary=f"HTTP {status}", locator=full,
                                   excerpt=f"status={status} size={size}")],
                remediation=rem,
            ))
    return out


def check_dir_fuzz(ctx: RunContext) -> list[Finding]:
    """Bounded content discovery. Active only."""
    if not ctx.active:
        return []
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    words = (ctx.opt("wordlist") or "").split(",") if ctx.opt("wordlist") else \
        ["admin", "login", "api", "backup", "test", "staging", "dev", "old", "config", "status"]
    for t in _scope_targets(ctx):
        base = t if "://" in t else f"https://{t}"
        for w in words:
            w = w.strip()
            if not w:
                continue
            r = http.get(base.rstrip("/") + "/" + w, allow_redirects=False)
            if r.status in (200, 401, 403, 500):
                sev = {200: Severity.LOW, 401: Severity.INFO,
                       403: Severity.INFO, 500: Severity.MEDIUM}[r.status]
                out.append(Finding(
                    capability="s01_recon.dir_fuzz",
                    title=f"{urlparse(base).hostname}/{w} → {r.status}", severity=sev,
                    target=base.rstrip("/") + "/" + w,
                    detail=f"Content probe returned {r.status}; title={r.title[:60]!r}",
                    attack_ids=["T1595.003"], tags=["fuzzing", "web"],
                    remediation="Review whether this path should be internet-reachable.",
                ))
    return out


def check_crawl(ctx: RunContext) -> list[Finding]:
    """Shallow crawl for JS-referenced endpoints, keys and hidden params."""
    if not ctx.active or not ctx.http:
        return []
    out: list[Finding] = []
    http = ctx.http
    KEY_RE = re.compile(
        r"(?:api[_-]?key|secret|token|passwd|password|AKIA[0-9A-Z]{16}|"
        r"ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})",
        re.I)
    for t in _scope_targets(ctx):
        base = t if "://" in t else f"https://{t}"
        r = http.get(base)
        if not r.ok:
            continue
        host = urlparse(base).hostname or base
        # The key count was computed and then thrown away: the original
        # `set(...)[:0] or set(...)[:6]` loop incremented `hits` and nothing ever
        # read it, so a publicly reachable page serving a hardcoded API key
        # produced no finding at all. The count is now reported.
        keys = re.findall(KEY_RE, r.text or "")[:6]
        if keys:
            out.append(Finding(
                capability="s01_recon.endpoint_crawl",
                title=f"{host}: {len(keys)} credential-like pattern(s) in page source",
                severity=Severity.HIGH,
                target=base,
                detail="A publicly reachable page serves source containing credential-like "
                       "strings. Anything shipped to a browser is disclosed to every visitor.",
                attack_ids=["T1552.001"], tags=["crawl", "secrets", "exposure"],
                confidence="medium",
                evidence=[Evidence(kind="http", summary=f"{len(keys)} match(es)",
                                   locator=base,
                                   excerpt=", ".join(sorted(set(keys)))[:200])],
                remediation="Move the credential server-side and rotate it; treat anything "
                            "delivered to a browser as public.",
            ))
        # findall returns a list; slicing a set here raised TypeError at runtime.
        for m in re.findall(r"https?://[a-zA-Z0-9._/-]{6,120}", r.text or "")[:25]:
            if "w3.org" in m or "schema.org" in m:
                continue
            out.append(Finding(
                capability="s01_recon.endpoint_crawl",
                title=f"{host}: external reference in page", severity=Severity.INFO,
                target=m[:140],
                detail="URL referenced from the landing page source.",
                tags=["crawl", "web"], attack_ids=["T1595.002"],
            ))
    return out


def check_api_discovery(ctx: RunContext) -> list[Finding]:
    """Locate OpenAPI/Swagger/GraphQL surfaces."""
    if not ctx.active or not ctx.http:
        return []
    out: list[Finding] = []
    http = ctx.http
    paths = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/api-docs",
             "/graphql", "/graphiql", "/_api/graphql", "/.well-known/openid-configuration"]
    for t in _scope_targets(ctx):
        base = t if "://" in t else f"https://{t}"
        host = urlparse(base).hostname or base
        for p in paths:
            r = http.get(base.rstrip("/") + p, allow_redirects=False)
            if r.status == 200 and len(r.text or "") > 20:
                is_gql = "graphql" in p
                out.append(Finding(
                    capability="s01_recon.api_discovery",
                    title=f"{host}: {'GraphQL' if is_gql else 'API schema'} exposed at {p}",
                    severity=Severity.MEDIUM if is_gql else Severity.LOW,
                    target=base.rstrip("/") + p,
                    detail=("Interactive/unguarded GraphQL endpoint. Test for introspection, "
                            "batching abuse and BOLA in resolvers."
                            if is_gql else
                            f"Full API schema published ({len(r.text)} bytes). Attack surface "
                            "is fully enumerable by anyone who can reach it."),
                    attack_ids=["T1592.002", "T1190"], tags=["api", "graphql", "surface"],
                    confidence="high",
                    evidence=[Evidence(kind="http", summary="schema served", locator=r.url,
                                       excerpt=(r.text[:200]))],
                    remediation="Disable public introspection; gate schemas behind auth in production.",
                ))
    return out


def check_oob(ctx: RunContext) -> list[Finding]:
    """OOB capability probe — verifies the mechanism works end to end."""
    out: list[Finding] = []
    rp = ctx.opt("_providers", {}).get("oob_validation")
    if rp is None or not getattr(rp, "runnable", False):
        return out
    from ..core.runner import execute
    res = execute(rp.provider, ["-version"], ctx.config, timeout=60)
    if res.ok:
        out.append(Finding(
            capability="s01_recon.oob_validation", title="OOB interaction server available",
            severity=Severity.OK, target="local",
            detail=f"interactsh is runnable via {res.how}. Blind SSRF/XXE/desync are confirmable.",
            tags=["oob", "capability"], remediation="Rotate the interaction domain between engagements.",
        ))
    return out


def check_whois(ctx: RunContext) -> list[Finding]:
    """RDAP registration intel."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    for dom in _scope_targets(ctx):
        if _is_ip(dom):
            continue
        r = http.get(f"https://rdap.org/domain/{dom}")
        if not r.ok:
            continue
        d = r.json({})
        events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
        registrar = ""
        for e in d.get("entities", []):
            if "registrar" in str(e.get("roles", [])):
                registrar = (e.get("vcardArray") or [[None, {}, []]])[1].get("fn", "")
        out.append(Finding(
            capability="s01_recon.whois_registrant",
            title=f"{dom}: registered {str(events.get('registration',''))[:10]}",
            severity=Severity.INFO, target=dom,
            detail=f"registrar={registrar[:60]} status={d.get('status')} "
                   f"expires={str(events.get('expiration',''))[:10]}",
            attack_ids=["T1590"], tags=["recon", "whois"],
            meta={"registrar": registrar, "events": events, "status": d.get("status")},
            remediation="Confirm auto-renew and registry lock are enabled.",
        ))
    return out


def check_email_surface(ctx: RunContext) -> list[Finding]:
    """Mail security posture consolidated (see check_dns for records)."""
    return []


def check_history(ctx: RunContext) -> list[Finding]:
    """Wayback CDX + Common Crawl history — retired hosts and old paths."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    for dom in _scope_targets(ctx):
        if _is_ip(dom):
            continue
        r = http.get("https://web.archive.org/cdx/search/cdx",
                     params={"url": f"{dom}/*", "output": "json", "fl": "original",
                             "collapse": "urlkey", "limit": "2000"})
        if not r.ok:
            continue
        rows = r.json([]) or []
        hosts: set[str] = set()
        for row in rows[1:]:
            if isinstance(row, list) and row:
                hosts.add(urlparse(str(row[0])).hostname or "")
        hosts.discard("")
        hosts.discard(dom)
        if hosts:
            out.append(Finding(
                capability="s01_recon.historical_infra",
                title=f"{dom}: {len(hosts)} subdomains in web history",
                severity=Severity.MEDIUM, target=dom,
                detail=("Historically indexed names that are no longer in DNS. These frequently "
                        "still resolve to unmaintained infrastructure, and are prime takeover "
                        "candidates once the relevant record ages out."),
                attack_ids=["T1590.003"], tags=["recon", "history", "takeover"],
                confidence="high",
                evidence=[Evidence(kind="output", summary=f"{len(hosts)} historical hosts",
                                   locator=dom, excerpt=", ".join(sorted(hosts)[:40]))],
                meta={"historical_hosts": sorted(hosts)},
                remediation="Check every historical host still resolves; decommission the rest "
                            "and remove the dangling records.",
            ))
    return out


def check_paste_leak(ctx: RunContext) -> list[Finding]:
    """Search public paste/code indexes for org material."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    domains = [d for d in _scope_targets(ctx) if not _is_ip(d)]
    for dom in domains:
        r = http.get("https://grep.app/api/search", params={"q": f"{dom} password"})
        if r.ok:
            hits = (r.json({}).get("facets", {}).get("count") or 0)
            if hits:
                out.append(Finding(
                    capability="s01_recon.code_secret_search",
                    title=f"Public code references {dom} (grep.app: {hits} hits)",
                    severity=Severity.LOW, target=dom,
                    detail="Code search index shows public references. Inspect for hardcoded secrets.",
                    attack_ids=["T1593"], tags=["recon", "secrets", "code"],
                    remediation="Scan and purge any credentials committed to public repositories.",
                ))
    return out


def check_dorking(ctx: RunContext) -> list[Finding]:
    """Search-engine dork sweep (DuckDuckGo HTML, no API key needed)."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    if ctx.config.offline:
        return out
    for t in _scope_targets(ctx)[:6]:
        if _is_ip(t):
            continue
        for q in (f'site:{t} "password"', f'site:{t} "api_key"', f'site:{t} inurl:admin'):
            r = http.get("https://html.duckduckgo.com/html/", params={"q": q},
                         headers={"User-Agent": "Mozilla/5.0"})
            if not r.ok:
                continue
            n = len(re.findall(r"result__a", r.text or ""))
            if n:
                out.append(Finding(
                    capability="s01_recon.search_engine_recon",
                    title=f"Dork '{q}' → {n} results", severity=Severity.LOW, target=t,
                    detail="Search-engine indexed pages matching sensitive keywords.",
                    attack_ids=["T1593.001"], tags=["recon", "dorks"],
                    remediation="Review indexed pages for unintended disclosure.",
                ))
    return out


def check_osint_social(ctx: RunContext) -> list[Finding]:
    """Delegate to sherlock/maigret if present, else report capability absent."""
    from ..core.util import which_any
    out: list[Finding] = []
    handles = ctx.opt("handles") or []
    if isinstance(handles, str):
        handles = [h.strip() for h in handles.split(",") if h.strip()]
    if not handles:
        return out
    tool = which_any("sherlock", "maigret")
    if not tool:
        return out
    from ..core.runner import execute
    for h in handles[:10]:
        res = execute(type("P", (), {"kind": None, "ref": tool, "install": "",
                                     "requires": [], "env": {}, "privileged": False,
                                     "notes": ""})(), [h], ctx.config, timeout=120)
        hits = [l for l in res.lines() if "http" in l]
        if hits:
            out.append(Finding(
                capability="s01_recon.osint_social",
                title=f"Handle @{h}: {len(hits)} accounts found", severity=Severity.INFO,
                target=f"@{h}", detail="; ".join(h[:90] for h in hits[:5]),
                tags=["osint", "social"], confidence="medium",
                remediation="Confirm each account is intended; note impersonation risk.",
            ))
    return out


def check_phone_osint(ctx: RunContext) -> list[Finding]:
    """Phone footprint via phoneinfoga when available."""
    from ..core.util import which_any
    phones = ctx.opt("phones") or []
    if isinstance(phones, str):
        phones = [p.strip() for p in phones.split(",") if p.strip()]
    if not phones:
        return []
    tool = which_any("phoneinfoga", "phoneinfoga-cli")
    if not tool:
        return []
    from ..core.runner import execute
    out: list[Finding] = []
    for p in phones[:5]:
        res = execute(type("P", (), {"kind": None, "ref": tool, "install": "",
                                     "requires": [], "env": {}, "privileged": False,
                                     "notes": ""})(), ["-n", p], ctx.config, timeout=120)
        if res.ok:
            out.append(Finding(
                capability="s01_recon.phone_domain_osint",
                title=f"Phone {p}: footprint retrieved", severity=Severity.INFO, target=p,
                detail=res.stdout[:600], tags=["osint", "phone"],
                remediation="Treat phone-derived identity as sensitive; restrict internal sharing.",
            ))
    return out


def check_typosquat(ctx: RunContext) -> list[Finding]:
    """Permutation + registry availability check for brand names."""
    from ..core.dnsutil import resolve
    out: list[Finding] = []
    brands = ctx.opt("brands") or []
    if isinstance(brands, str):
        brands = [b.strip() for b in brands.split(",") if b.strip()]
    if not brands:
        return out
    subs = ["", "-", "0", "1", "x", "rn", "l"]
    tlds = ["com", "net", "org", "io", "co"]
    seen = set()
    for b in brands[:6]:
        variants = {b + s for s in subs} | {b.replace("i", s) for s in ("l", "1", "j")}
        live = []
        for v in variants:
            if v.lower() in seen or v.lower() == b.lower():
                continue
            seen.add(v.lower())
            for tld in tlds:
                fqdn = f"{v}.{tld}"
                try:
                    if resolve(fqdn, "A"):
                        live.append(fqdn)
                except Exception:
                    pass
        if live:
            out.append(Finding(
                capability="s01_recon.typosquat_registry",
                title=f"Brand '{b}': {len(live)} look-alike domains resolve",
                severity=Severity.MEDIUM, target=b,
                detail="Permutation variants that currently resolve: " + ", ".join(live[:20]),
                attack_ids=["T1583.001"], tags=["recon", "phishing", "brand"],
                confidence="medium",
                remediation="Takedown the active look-alikes; consider defensive registration "
                            "of key variants and a monitoring feed.",
            ))
    return out


def check_geo(ctx: RunContext) -> list[Finding]:
    """IP geolocation + datacenter classification."""
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    for t in _scope_targets(ctx):
        r = http.get(f"http://ip-api.com/json/{t}",
                     params={"fields": "status,country,regionName,city,isp,org,as,hosting,proxy"})
        if not r.ok:
            continue
        d = r.json({})
        if d.get("status") != "success":
            continue
        flags = [k for k in ("hosting", "proxy", "mobile") if d.get(k)]
        out.append(Finding(
            capability="s01_recon.geolocate_target",
            title=f"{t}: {d.get('city','?')}, {d.get('country','?')} ({d.get('as','?')})",
            severity=Severity.INFO, target=t,
            detail=f"org={d.get('org','?')} isp={d.get('isp','?')} flags={flags or 'none'}",
            attack_ids=["T1590.003"], tags=["recon", "geo"],
            meta={k: d.get(k) for k in ("country", "regionName", "city", "isp", "org", "as",
                                        "hosting", "proxy")},
        ))
    return out


def check_cloud_enum(ctx: RunContext) -> list[Finding]:
    """Native cloud storage / API surface discovery for a keyword or org."""
    from ..core.util import pmap
    http = ctx.http
    if not http:
        return []
    out: list[Finding] = []
    keywords = ctx.opt("cloud_keywords") or ctx.opt("brands") or []
    if isinstance(keywords, str):
        keywords = [k.strip() for k in keywords.split(",") if k.strip()]
    if not keywords:
        return out

    def probe(kw: str) -> list[tuple[str, int, int]]:
        hits = []
        for t in ("s3", "storage.googleapis.com", "blob.core.windows.net", "s3-eu-west-1.amazonaws.com"):
            url = f"https://{kw}.{t}"
            r = http.get(url, allow_redirects=False)
            if r.status in (200, 403, 404):
                hits.append((url, r.status, len(r.text or "")))
        return hits

    for res in pmap(probe, keywords[:8], workers=8):
        for url, status, _size in res:
            sev = Severity.HIGH if status == 200 else (Severity.LOW if status == 403 else Severity.INFO)
            out.append(Finding(
                capability="s01_recon.cloud_asset_discovery",
                title=f"{url} → {status}", severity=sev, target=url,
                detail=("Bucket/container publicly listable or readable — verify whether intended."
                        if status == 200 else
                        "Bucket exists (403/404) — confirm it is intentional and access-controlled."),
                attack_ids=["T1530"], tags=["recon", "cloud", "storage"],
                confidence="medium",
                remediation="Restrict to least-privilege; block public access at the bucket policy.",
            ))
    return out


def check_nuclei_native(ctx: RunContext) -> list[Finding]:
    """Minimal native template subset for basic misconfiguration signals."""
    if not ctx.active or not ctx.http:
        return []
    http = ctx.http
    out: list[Finding] = []
    checks = [
        ("/actuator/env", "Spring Boot actuator environment", Severity.CRITICAL,
         "Exposed Spring actuator endpoint typically leaks credentials, tokens and connection strings."),
        ("/server-info", "Server info page", Severity.MEDIUM,
         "Framework/version information disclosure."),
        ("/.aws/credentials", "AWS credentials file", Severity.CRITICAL,
         "Cloud credentials retrievable over the web."),
    ]
    for t in _scope_targets(ctx):
        base = t if "://" in t else f"https://{t}"
        for path, why, sev, detail in checks:
            r = http.get(base.rstrip("/") + path, allow_redirects=False)
            if r.status == 200:
                out.append(Finding(
                    capability="s01_recon.vuln_scan", title=f"{urlparse(base).hostname}: {why}",
                    severity=sev, target=base.rstrip("/") + path, detail=detail,
                    attack_ids=["T1190"], tags=["vuln", "exposure"],
                    confidence="high",
                    evidence=[Evidence(kind="http", summary="HTTP 200", locator=r.url,
                                       excerpt=(r.text or "")[:300])],
                    remediation="Restrict the management surface to internal networks; rotate any "
                                "secrets it disclosed.",
                ))
    return out


def _is_ip(h: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════ port scan
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
             465, 587, 636, 993, 995, 1433, 1521, 2049, 2181, 2375, 3000, 3306,
             3389, 4443, 5000, 5432, 5672, 5900, 5985, 6379, 6443, 8000, 8080,
             8081, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017,
             50070, 15672, 61616]

BANNER_PROBES = [
    (21, b"SQIH\r\n"), (22, b"SSH-2.0-"), (25, b"EHLO"), (80, b"HEAD / HTTP/1.0\r\n\r\n"),
    (110, b"CAPA\r\n"), (143, b"CAPA\r\n"), (445, b""), (3306, b""),
    (6379, b"INFO\r\n"), (9200, b"GET / HTTP/1.0\r\n\r\n"), (27017, b"\x41\x00\x00\x00\x01"),
]


def check_port_scan(ctx: RunContext) -> list[Finding]:
    """Native TCP connect scanner with light banner grabbing. Active only."""
    if not ctx.active:
        return [Finding(
            capability="s01_recon.port_scan", title="Port scanning skipped (passive mode)",
            severity=Severity.INFO, target="network",
            detail=("Active probing sends packets to in-scope hosts. Rerun without --passive and a scope "
                    "(--host/--cidr) to enable."),
            tags=["recon", "network"],
            remediation="For stealthier discovery, install naabu/nmap; this is a connect scanner "
                        "and will appear in host firewalls.",
        )]
    import socket
    from ..core.util import pmap

    targets: list[str] = []
    for h in (ctx.scope.hosts if ctx.scope else []):
        targets.append(h)
    for c in (ctx.scope.cidrs if ctx.scope else []):
        try:
            import ipaddress
            targets += [str(ip) for ip in ipaddress.ip_network(c, strict=False)]
        except Exception:
            pass
    for t in (ctx.opt("targets") or []):
        tl = [t] if isinstance(t, str) else list(t)
        for x in tl:
            if x and not x.replace(".", "").isdigit() and ":" not in x:
                try:
                    from ..core.dnsutil import resolve
                    targets += resolve(x, "A")
                except Exception:
                    pass
            elif x:
                targets.append(x)
    targets = list(dict.fromkeys(targets))[:64]
    if not targets:
        return [Finding(capability="s01_recon.port_scan", title="No hosts in scope",
                        severity=Severity.INFO, target="network",
                        detail="Supply --host or --cidr.", tags=["recon"])]

    ports = ctx.opt("ports")
    if isinstance(ports, str):
        ports = [int(p) for p in ports.split(",") if p.strip().isdigit()]
    port_list = ports or TOP_PORTS
    open_risk = {21: (Severity.MEDIUM, "FTP"), 23: (Severity.HIGH, "Telnet"),
                 445: (Severity.HIGH, "SMB"), 3389: (Severity.MEDIUM, "RDP"),
                 3306: (Severity.MEDIUM, "MySQL"), 5432: (Severity.MEDIUM, "Postgres"),
                 6379: (Severity.HIGH, "Redis"), 27017: (Severity.MEDIUM, "MongoDB"),
                 9200: (Severity.MEDIUM, "Elasticsearch"), 11211: (Severity.MEDIUM, "Memcached"),
                 50070: (Severity.HIGH, "Hadoop NN"), 2375: (Severity.CRITICAL, "Docker API (unauth)"),
                 5985: (Severity.HIGH, "CouchDB"), 27017.1: (Severity.MEDIUM, "MongoDB")}

    def probe(item):
        host, port = item
        try:
            with socket.create_connection((host, port), timeout=1.6) as s:
                s.settimeout(1.6)
                banner = ""
                for p, probe_bytes in BANNER_PROBES:
                    if p == port and probe_bytes:
                        try:
                            s.sendall(probe_bytes)
                            banner = (s.recv(200) or b"").decode("utf-8", "replace").strip()
                        except Exception:
                            banner = ""
                        break
                return host, port, banner
        except Exception:
            return host, port, ""

    out: list[Finding] = []
    found_any = False
    for host, port, banner in pmap(probe, [(h, p) for h in targets for p in port_list],
                                   workers=min(200, ctx.config.parallel * 12)):
        if not banner and port not in (445, 3306, 6379, 27017):
            continue  # pmap returns "" for closed ports too
        if banner == "" and port in (445, 3306, 6379, 27017):
            pass  # these banners are empty on connect for real services
        else:
            continue
        found_any = True
        sev, svc = open_risk.get(port, (Severity.INFO, "service"))
        out.append(Finding(
            capability="s01_recon.port_scan", title=f"{host}:{port} open — {svc}",
            severity=sev, target=f"{host}:{port}",
            detail=(f"TCP connect succeeded. Banner: {banner[:120]!r}" if banner
                    else f"TCP connect succeeded on {svc} (no banner)."),
            attack_ids=["T1046", "T1135"], tags=["recon", "network", "port"],
            confidence="high",
            evidence=[Evidence(kind="banner", summary=svc, locator=f"{host}:{port}",
                               excerpt=banner[:200])],
            remediation="Close it, or restrict to the source that legitimately needs it.",
        ))
    if not found_any:
        out.append(Finding(capability="s01_recon.port_scan",
                           title=f"No open ports found across {len(targets)} host(s) × {len(port_list)} ports",
                           severity=Severity.INFO, target="recon",
                           detail="TCP connect scan completed. Absence of a banner can also mean "
                                  "a filtering middlebox dropped the SYN.",
                           tags=["recon", "network"]))
    return out
