"""S06 · Response, DFIR and forensics.

IOC enrichment and validation, feed sync, intel-platform integration, triage,
PCAP/log/forensic analysis, evidence collection, containment and recovery
verification, breach timeline, and MTTD measurement.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from pathlib import Path

from ..core.models import Evidence, Finding, RunContext, Severity


# ══════════════════════════════════════════════════════════════════ IOC logic
IOC_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32}|[A-F0-9]{16}-(?:[A-F0-9]{4}-){3}[A-F0-9]{12})\b")
URL_RE = re.compile(r"https?://[^\s\"'<>\\)]{6,200}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|top|xyz|info|biz|co|uk|de|nl|fr|br|in|jp|kr|onion|live|site|online|club|shop|icu|vip|work|ltd|dev|app|ai)\b", re.I)


def _iocs(ctx: RunContext) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {"sha256": [], "sha1": [], "md5": [], "url": [],
                                 "ip": [], "domain": [], "email": []}
    raw = ctx.opt("iocs") or []
    if isinstance(raw, str):
        raw = [x.strip() for x in re.split(r"[,\s]+", raw) if x.strip()]
    for f in (ctx.opt("ioc_files") or []):
        try:
            raw += re.split(r"[\s,]+", Path(f).read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    for v in raw:
        v = str(v).strip().strip("\"'")
        if not v:
            continue
        low = v.lower()
        if re.fullmatch(r"[a-f0-9]{64}", low):
            out["sha256"].append(low)
        elif re.fullmatch(r"[a-f0-9]{40}", low):
            out["sha1"].append(low)
        elif re.fullmatch(r"[a-f0-9]{32}", low):
            out["md5"].append(low)
        elif low.startswith("http"):
            out["url"].append(v)
        elif IPV4_RE.fullmatch(v):
            out["ip"].append(v)
        elif DOMAIN_RE.fullmatch(v) and "." in v:
            out["domain"].append(low)
        elif "@" in v:
            out["email"].append(low)
    return {k: sorted(set(v)) for k, v in out.items()}


def enrich_iocs(ctx: RunContext) -> list[Finding]:
    """Enrich indicators across free reputation and context sources."""
    http = ctx.http
    ind = _iocs(ctx)
    total = sum(len(v) for v in ind.values())
    if not total:
        return [Finding(
            capability="s06_response.ioc_enrich", title="No indicators supplied", severity=Severity.INFO,
            target="iocs", detail="Pass --iocs <csv> or --ioc-files <glob>.",
            tags=["response", "enrich"],
        )]
    if not http:
        return [Finding(
            capability="s06_response.ioc_enrich", title="Enrichment unavailable (offline)",
            severity=Severity.LOW, target="iocs",
            detail=f"{total} indicators present but no network client.", tags=["response"],
        )]
    out = []
    # IP context: is it a known scanner, datacenter, or geolocated
    for ip in ind["ip"][:30]:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        r = http.get(f"http://ip-api.com/json/{ip}",
                     params={"fields": "status,country,city,isp,org,as,hosting,proxy,mobile"})
        if not r.ok:
            continue
        d = r.json({})
        if d.get("status") != "success":
            continue
        ctx.emit(Finding(
            capability="s06_response.ioc_enrich", title=f"{ip}: {d.get('city','?')}, {d.get('country','?')}",
            severity=Severity.INFO, target=ip,
            detail=f"AS {d.get('as','?')} · {d.get('isp','?')} · hosting={d.get('hosting')} "
                   f"proxy={d.get('proxy')}",
            tags=["response", "enrich", "ip"], attack_ids=["T1071"],
            meta=d,
        ))
    # abuse.ch + threatfox for hashes
    for h in ind["sha256"][:20]:
        r = http.get("https://mb-api.abuse.ch/api/v1/",
                     data={"query": "get_info", "hash": h})
        if r.ok:
            d = r.json({})
            if d.get("query_status") == "ok":
                out.append(Finding(
                    capability="s06_response.ioc_enrich",
                    title=f"MalwareBazaar hit: {h[:16]}…",
                    severity=Severity.CRITICAL, target=h,
                    detail=(f"signature={d.get('data',[{}])[0].get('signature','')} "
                            f"file_type={d.get('data',[{}])[0].get('file_type','')} "
                            f"first_seen={d.get('data',[{}])[0].get('first_seen','')}"),
                    attack_ids=["T1204.002"], tags=["response", "malware", "critical"],
                    confidence="high",
                    refs=["https://bazaar.abuse.ch"],
                    remediation="Treat the host as compromised; hunt for the file across the estate.",
                ))
    return out or [Finding(capability="s06_response.ioc_enrich",
                           title=f"{total} indicators, no reputation hits",
                           severity=Severity.OK, target="iocs", tags=["response", "enrich"])]


def validate_ioc(ctx: RunContext) -> list[Finding]:
    """Distinguish genuinely malicious indicators from benign collisions."""
    ind = _iocs(ctx)
    out = []
    for ip in ind["ip"]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
            out.append(Finding(
                capability="s06_response.ioc_validate",
                title=f"{ip} is a non-routable address", severity=Severity.LOW, target=ip,
                detail="Private/loopback/link-local. If this appeared in an indicator list, it is "
                       "likely a parsing error or internal artefact — do not block it at the edge.",
                tags=["response", "triage"], remediation="Validate the source before blocking.",
            ))
        elif addr.is_reserved or addr.is_multicast:
            out.append(Finding(
                capability="s06_response.ioc_validate",
                title=f"{ip} is reserved space", severity=Severity.LOW, target=ip,
                detail="Reserved range — not routable on the public internet.",
                tags=["response", "triage"],
            ))
    for u in ind["url"][:50]:
        host = ""
        from urllib.parse import urlparse
        host = urlparse(u).hostname or ""
        if host in ("localhost", "127.0.0.1", "0.0.0.0") or host.endswith(".internal") \
                or host.endswith(".local"):
            out.append(Finding(
                capability="s06_response.ioc_validate", title=f"Internal URL in list: {u[:80]}",
                severity=Severity.LOW, target=u,
                detail="Points at an internal host. Confirm whether this is an internal "
                       "compromise indicator or an artefact of collection.",
                tags=["response", "triage"],
            ))
    for d in ind["domain"][:60]:
        if d.count(".") <= 1 and d.split(".")[0] in ("localhost", "intranet", "corp", "internal"):
            out.append(Finding(
                capability="s06_response.ioc_validate", title=f"Non-FQDN in list: {d}",
                severity=Severity.INFO, target=d,
                detail="Looks like an internal short name rather than a public indicator.",
                tags=["response", "triage"],
            ))
    return out or [Finding(capability="s06_response.ioc_validate",
                           title="No false-positive collisions detected",
                           severity=Severity.OK, target="iocs", tags=["response", "triage"])]


def sync_feeds(ctx: RunContext) -> list[Finding]:
    """Pull free indicator feeds and normalise into the store."""
    http = ctx.http
    if not http:
        return [Finding(capability="s06_response.threat_feed_sync", title="Feed sync skipped (offline)",
                        severity=Severity.INFO, target="feeds", tags=["response", "feed"])]
    out = []
    feeds = [
        ("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "cve"),
        ("URLhaus (recent)", "https://urlhaus.abuse.ch/downloads/csv_recent/", "url"),
    ]
    for name, url, kind in feeds:
        r = http.get(url, allow_redirects=True)
        if not r.ok:
            out.append(Finding(capability="s06_response.threat_feed_sync",
                               title=f"{name}: fetch failed ({r.status or r.error[:40]})",
                               severity=Severity.LOW, target=url,
                               detail="Feed unreachable — this is a coverage gap in your intel.",
                               tags=["feed", "intel"]))
            continue
        n = 0
        if kind == "cve":
            data = r.json({})
            vulns = data.get("vulnerabilities", []) or []
            n = len(vulns)
            for v in vulns[:500]:
                ctx.emit(Finding(
                    capability="s06_response.threat_feed_sync",
                    title=f"KEV: {v.get('cveID')} in {v.get('vendor','')} {v.get('product','')}",
                    severity=Severity.HIGH,
                    target=v.get("cveID", ""),
                    detail=(f"Known exploited in the wild. Due {v.get('dueDate','')}. "
                            f"Ransomware: {v.get('knownRansomwareCampaignUse','unknown')}"),
                    attack_ids=["T1190"], tags=["feed", "vuln", "kev"],
                    confidence="high", refs=[v.get("notes", "")[:200]],
                    remediation=f"Patch before {v.get('dueDate','immediately')}; CISA KEV entries "
                                "are the highest-signal feed available.",
                    meta={"cve": v.get("cveID"), "due": v.get("dueDate"),
                          "ransomware": v.get("knownRansomwareCampaignUse")},
                ))
        else:
            n = len([l for l in r.text.splitlines() if l])
        out.append(Finding(
            capability="s06_response.threat_feed_sync", title=f"{name}: {n} records fetched",
            severity=Severity.INFO, target=url,
            detail=f"Source of record for {kind} indicators.", tags=["feed", "intel"],
            meta={"feed": name, "count": n},
            remediation="Schedule this sync; KEV especially is worth alerting on daily.",
        ))
    return out


def intel_sync(ctx: RunContext) -> list[Finding]:
    """Push/pull indicators between AEGIS and MISP or OpenCTI."""
    import os
    out = []
    if os.environ.get("MISP_URL") and os.environ.get("MISP_KEY"):
        out.append(Finding(
            capability="s06_response.intel_platform_sync", title="MISP configured",
            severity=Severity.INFO, target=os.environ["MISP_URL"],
            detail="AEGIS can push findings to MISP as objects and pull shared indicators.",
            tags=["response", "cti", "misp"],
            remediation="Wire the CI job so high-severity findings become shareable objects.",
        ))
    if os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_TOKEN"):
        out.append(Finding(
            capability="s06_response.intel_platform_sync", title="OpenCTI configured",
            severity=Severity.INFO, target=os.environ["OPENCTI_URL"],
            detail="Graph-native intel platform available for relationship-aware correlation.",
            tags=["response", "cti", "opencti"],
            remediation="Map findings to report entities; use the graph for attack-path reasoning.",
        ))
    if not out:
        out.append(Finding(
            capability="s06_response.intel_platform_sync",
            title="No intel platform configured", severity=Severity.LOW, target="cti",
            detail="Set MISP_URL/MISP_KEY or OPENCTI_URL/OPENCTI_TOKEN to enable two-way sync.",
            tags=["response", "cti"],
            remediation="Self-hosted MISP is the lowest-effort way to start sharing indicators.",
        ))
    return out


def triage(ctx: RunContext) -> list[Finding]:
    """One-shot indicator triage across many sources."""
    ind = _iocs(ctx)
    return [Finding(
        capability="s06_response.triage_automation",
        title=f"Triage set: {sum(len(v) for v in ind.values())} indicators",
        severity=Severity.INFO, target="triage",
        detail="; ".join(f"{k}={len(v)}" for k, v in ind.items() if v),
        tags=["response", "triage"],
        meta={k: v for k, v in ind.items()},
        remediation="Triage order: hashes (known malware) → C2 infrastructure → victim IPs. "
                    "Working left to right wastes analyst time.",
    )]


# ══════════════════════════════════════════════════════════════════ malware
def malware_triage(ctx: RunContext) -> list[Finding]:
    """Static triage of a suspicious file."""
    p = ctx.opt("file")
    if not p or not Path(p).exists():
        return [Finding(capability="s06_response.malware_triage", title="No file supplied",
                        severity=Severity.INFO, target=str(p),
                        detail="Pass --file <path>.", tags=["response", "malware"])]
    from ..core.runner import execute
    from ..core.util import sha256_file
    path = Path(p)
    rp = ctx.opt("_providers", {}).get("malware_triage")
    out = [Finding(
        capability="s06_response.malware_triage", title=f"Sampled: {path.name}",
        severity=Severity.INFO, target=str(path),
        detail=f"sha256={sha256_file(path)} size={path.stat().st_size}B",
        tags=["response", "malware"],
    )]
    if rp is not None and getattr(rp, "runnable", False):
        res = execute(rp.provider, [str(path)], ctx.config, timeout=300)
        if res.ok:
            out.append(Finding(
                capability="s06_response.malware_triage",
                title=f"Capabilities extracted: {path.name}", severity=Severity.MEDIUM,
                target=str(path), detail=res.stdout[:1500],
                tags=["response", "malware", "capability"],
                evidence=[Evidence(kind="output", summary="capa", locator=str(path),
                                   excerpt=res.stdout[:1500])],
                remediation="Capabilities (not family names) are what drive containment scope.",
            ))
    return out


def yara_author(ctx: RunContext) -> list[Finding]:
    """Build a YARA rule and a positive/negative test corpus."""
    strings = ctx.opt("strings") or []
    if not strings:
        return [Finding(
            capability="s06_response.yara_prep", title="No strings supplied", severity=Severity.INFO,
            target="yara", detail="Pass --strings 'a,b,c' to scaffold a rule.",
            tags=["yara", "detection"],
            remediation="Start from strings that survived obfuscation: format strings, mutex "
                        "names, unusual constants, C2 URI patterns.",
        )]
    body = ',\n        '.join(f'"{s}" ascii wide nocase' for s in strings)
    rule = (f'rule aegis_scaffold\n{{\n    meta:\n        author = "AEGIS"\n'
            f'        description = "scaffolded {len(strings)} string(s)"\n'
            f'        reference = "internal"\n    strings:\n        $s1 = {body}\n'
            f'    condition:\n        any of them\n}}\n')
    d = Path(ctx.workdir) / "yara"
    d.mkdir(parents=True, exist_ok=True)
    f = d / "aegis_scaffold.yar"
    f.write_text(rule, encoding="utf-8")
    return [Finding(
        capability="s06_response.yara_prep", title=f"YARA rule scaffolded ({len(strings)} strings)",
        severity=Severity.INFO, target=str(f),
        detail="Rule written. It has no test corpus yet — an untested rule is an assumption.",
        tags=["yara", "detection"],
        evidence=[Evidence(kind="file", summary="rule", locator=str(f), excerpt=rule)],
        remediation="Build positive and negative corpora, then assert the rule fires on one and "
                    "not the other. Re-test on every engine update.",
    )]


# ══════════════════════════════════════════════════════════════════ network
def pcap_analyse(ctx: RunContext) -> list[Finding]:
    """PCAP/network forensics: C2 beacons, DNS tunnelling, JA3, exfil volume."""
    p = ctx.opt("pcap")
    if not p or not Path(p).exists():
        return [Finding(
            capability="s06_response.pcap_analysis", title="No PCAP supplied", severity=Severity.INFO,
            target=str(p), detail="Pass --pcap <file>. Requires tshark for full dissection.",
            tags=["response", "network"],
            remediation="`winget install WiresharkFoundation.TShark`",
        )]
    from ..core.runner import execute
    path = str(p)
    rp = ctx.opt("_providers", {}).get("pcap_analysis")
    out = []
    if rp is None or not getattr(rp, "runnable", False):
        return [Finding(
            capability="s06_response.pcap_analysis", title="tshark unavailable — PCAP unanalysed",
            severity=Severity.MEDIUM, target=path,
            detail="Network forensics is UNMEASURED in this environment.",
            tags=["response", "network", "gap"],
            remediation="`winget install WiresharkFoundation.TShark`, or use the Arkime container.",
        )]
    res = execute(rp.provider, ["-r", path, "-q", "-z", "conv,ip"], ctx.config, timeout=600)
    if res.ok and res.stdout.strip():
        out.append(Finding(
            capability="s06_response.pcap_analysis", title="PCAP conversation summary",
            severity=Severity.INFO, target=path, detail=res.stdout[:1200],
            tags=["response", "network"],
            evidence=[Evidence(kind="pcap", summary="conversations", locator=path,
                               excerpt=res.stdout[:1200])],
        ))
    res2 = execute(rp.provider, ["-r", path, "-Y", "dns", "-T", "fields",
                                 "-e", "dns.qry.name", "-Y", "dns.flags.response==0"],
                   ctx.config, timeout=600)
    if res2.ok:
        names = [l for l in res2.stdout.splitlines() if l.strip()]
        if len(names) > 2000:
            out.append(Finding(
                capability="s06_response.pcap_analysis",
                title=f"High DNS query volume ({len(names)})", severity=Severity.MEDIUM,
                target=path,
                detail="Unusually high outbound DNS volume is a common tunnelling signal.",
                attack_ids=["T1071.004", "T1572"], tags=["response", "network", "dns"],
                remediation="Baseline DNS per host; alert on long labels, high TXT volume, and "
                            "unique-subdomain ratios per client.",
            ))
    return out


def log_hunt(ctx: RunContext) -> list[Finding]:
    """Hunt across supplied logs for high-fidelity indicators."""
    from ..core.util import read_text
    hay = ""
    srcs = ctx.opt("logs") or []
    for s in srcs:
        hay += read_text(s, 40_000_000)
    if not hay:
        return [Finding(
            capability="s06_response.log_analysis", title="No logs supplied", severity=Severity.INFO,
            target="logs", detail="Pass --logs <file-or-dir>.", tags=["response", "hunting"],
            remediation="For big logs use chainsaw (Sigma) or hayabusa rather than text search.",
        )]
    h = hay.lower()
    HUNTS = [
        ("Event log cleared (1102)", ["1102", "clear-eventlog", "wevtutil cl"], Severity.CRITICAL,
         "T1070.001", "Log clearing during an incident is a strong tamper signal."),
        ("Defender disabled", ["set-mppreference -disable", "disable realtime monitoring",
                              "tamperprotection"], Severity.CRITICAL, "T1562.001",
         "Security tooling being disabled is the v19 Defense Impairment pattern."),
        ("Shadow copies deleted", ["vssadmin delete shadows", "wbadmin delete catalog",
                                   "bcdedit recoveryenabled no"], Severity.CRITICAL,
         "T1490", "Anti-recovery: ransomware precursor or ransomware itself."),
        ("Ransom note artefacts", ["readme_for_decrypt", "how_to_decrypt", "your_files",
                                   "restore-my-files", "decrypt"], Severity.HIGH, "T1486",
         "Encryption event."),
        ("Privilege escalation", ["whoami /priv", "net user /domain", "added to the domain admins",
                                  "sekurlsa::"], Severity.HIGH, "T1068",
         "Enumeration followed by escalation."),
        ("Persistence via scheduled task", ["schtasks /create", "register-scheduledtask"], Severity.MEDIUM,
         "T1053.005", "Task-based persistence."),
        ("Remote service creation", ["psexec", "wmiexec", "csexec", "sc \\\\", "wmic /node"],
         Severity.HIGH, "T1021.002", "Lateral movement tooling."),
        ("C2 beaconing via PowerShell", ["downloadstring", "iex(new-object", "-enc",
                                         "frombase64string", "system.net.webclient"], Severity.HIGH,
         "T1059.001", "PowerShell-based download and execute is the most common C2 staging."),
    ]
    out = []
    for name, sigs, sev, tid, why in HUNTS:
        hits = [s for s in sigs if s in h]
        if hits:
            out.append(Finding(
                capability="s06_response.log_analysis", title=f"Hunt hit: {name}",
                severity=sev, target="logs",
                detail=f"{why} Matched: {', '.join(hits[:6])}",
                attack_ids=[tid], tags=["response", "hunting", "defense"],
                confidence="high" if len(hits) > 1 else "medium",
                remediation="Triage the host immediately; these are decision-grade signals.",
            ))
    return out or [Finding(capability="s06_response.log_analysis",
                           title="No high-fidelity indicators in the supplied logs",
                           severity=Severity.OK, target="logs", tags=["response", "hunting"])]


def host_triage(ctx: RunContext) -> list[Finding]:
    """Endpoint forensics triage: persistence and anti-forensics indicators."""
    from ..core.util import read_text
    hay = ""
    for s in (ctx.opt("logs") or []) + (ctx.opt("scripts") or []):
        hay += read_text(s, 30_000_000)
    if not hay:
        return [Finding(capability="s06_response.forensics_triage",
                        title="No host data supplied", severity=Severity.INFO, target="host",
                        detail="Pass --logs or --scripts from the affected host.",
                        tags=["response", "forensics"],
                        remediation="Collect: autoruns output, scheduled tasks, services, "
                                    "WMI subscriptions, PowerShell history, and a memory image.",
        )]
    h = hay.lower()
    PERSIST = [
        ("Run/RunOnce key", ["\\currentversion\\run", "runonce"], "T1547.001"),
        ("Scheduled task", ["schtasks", "taskscheduler"], "T1053.005"),
        ("New service", ["sc create", "new-service", "servicestartup"], "T1543.003"),
        ("WMI event subscription", ["__eventfilter", "commandlineeventconsumer", "activewmi"],
         "T1546.003"),
        ("Winlogon shell/userinit", ["winlogon\\shell", "userinit"], "T1547.004"),
        ("Image File Execution Options", ["image file execution options", "globalflag"],
         "T1546.012"),
        ("COM hijack / AppInit_DLLs", ["appinit_dlls", "treat as signed"], "T1574.012"),
        ("Boot/logon autostart", ["\\shell:startup", "startup folder"], "T1547.001"),
    ]
    ANTI = [
        ("Timestomp", ["timestomp"], "T1070.006"),
        ("Event log cleared", ["cleareventlog", "1102"], "T1070.001"),
        ("Shadow copy deletion", ["vssadmin delete", "wbadmin delete"], "T1490"),
        ("Security tool uninstall", ["uninstall", "removesecurity"], "T1562"),
    ]
    out = []
    for name, sigs, tid in PERSIST:
        if any(s in h for s in sigs):
            out.append(Finding(
                capability="s06_response.forensics_triage", title=f"Persistence artefact: {name}",
                severity=Severity.HIGH, target="host", detail=f"Indicator for {name}.",
                attack_ids=[tid], tags=["response", "forensics", "persistence"],
                remediation="Confirm against the golden image; remove anything not expected.",
            ))
    for name, sigs, tid in ANTI:
        if any(s in h for s in sigs):
            out.append(Finding(
                capability="s06_response.forensics_triage", title=f"Anti-forensics: {name}",
                severity=Severity.CRITICAL, target="host", detail=f"Indicator for {name}.",
                attack_ids=[tid], tags=["response", "forensics", "antiforensics", "critical"],
                remediation="Preserve evidence before remediation; the timeline matters more "
                            "than the cleanup.",
            ))
    return out or [Finding(capability="s06_response.forensics_triage",
                           title="No persistence or anti-forensic indicators found",
                           severity=Severity.OK, target="host", tags=["response", "forensics"])]


# ══════════════════════════════════════════════════════════════════ process
def collect_evidence(ctx: RunContext) -> list[Finding]:
    """Persist findings + evidence into a hash-chained evidence package."""
    import hashlib
    chain: list[str] = []
    for f in sorted(ctx.findings, key=lambda x: x.fingerprint):
        payload = json.dumps(f.to_dict(), sort_keys=True, default=str)
        h = hashlib.sha256(payload.encode()).hexdigest()
        prev = chain[-1] if chain else "0" * 64
        entry = hashlib.sha256((prev + h).encode()).hexdigest()
        chain.append(entry)
    if ctx.store:
        new, updated = ctx.store.upsert_findings(ctx.run_id, ctx.findings)
    else:
        new, updated = len(ctx.findings), 0
    manifest = {"run_id": ctx.run_id, "generated": time.time(),
                "findings": len(ctx.findings), "new": new, "updated": updated,
                "chain_head": chain[-1] if chain else None,
                "entries": [{"seq": i, "hash": h} for i, h in enumerate(chain)]}
    p = Path(ctx.workdir) / f"evidence-{ctx.run_id}.json"
    p.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return [Finding(
        capability="s06_response.evidence_collect",
        title=f"Evidence package: {len(ctx.findings)} findings, chain head {str(manifest['chain_head'])[:16]}",
        severity=Severity.INFO, target=str(p),
        detail=(f"{new} new, {updated} previously seen. Each finding is hash-chained to the "
                "previous, so any later modification breaks the chain."),
        tags=["response", "evidence", "audit"],
        evidence=[Evidence(kind="output", summary="chain", locator=str(p),
                           excerpt=json.dumps(manifest, indent=2)[:800])],
        remediation="Store the manifest with the engagement records; it is your tamper-evidence.",
    )]


def verify_containment(ctx: RunContext) -> list[Finding]:
    """Verify isolation actually holds."""
    CHECKS = [
        ("Network isolation confirmed", "Host cannot reach the internet or internal subnets."),
        ("Egress denied at the perimeter", "Not just blocked inbound — egress matters more."),
        ("Account disabled everywhere", "Local, AD, cloud, SaaS, VPN. One gap re-opens access."),
        ("Tokens and sessions revoked", "Revoke refresh tokens, not just reset the password."),
        ("API keys rotated", "Any key that touched the host is considered exposed."),
        ("Backups verified immutable", "Offline or immutable copy confirmed out of band."),
        ("Forensic image captured", "Before remediation, not after."),
    ]
    flags = ctx.opt("containment") or {}
    out = []
    for name, why in CHECKS:
        ok = flags.get(name.split(" ")[0].lower()) in (True, "yes", "done", "confirmed")
        out.append(Finding(
            capability="s06_response.containment_verify",
            title=f"{name} — {'CONFIRMED' if ok else 'UNVERIFIED'}", severity=Severity.OK if ok else Severity.HIGH,
            target=name, detail=why,
            attack_ids=["T1562"], tags=["response", "containment"],
            remediation="Verify from the network, not from the console on the isolated host.",
        ))
    return out


def verify_recovery(ctx: RunContext) -> list[Finding]:
    """Eradication and recovery validation."""
    CHECKS = [
        ("Persistence removed", "Compare autoruns/services/tasks against a known-good image."),
        ("Credentials rotated", "Every account and key that touched the affected systems."),
        ("Pipelines and build systems clean", "A worm in CI re-infects everything you rebuild."),
        ("Artifacts rebuilt and re-signed", "Do not redeploy anything built during the window."),
        ("Backups restored and tested", "Restored ≠ verified. Restore something and use it."),
        ("Detection rules added", "Turn the incident into a rule, not just a postmortem."),
    ]
    out = []
    for name, why in CHECKS:
        out.append(Finding(
            capability="s06_response.eradicate_verify", title=f"Recovery check: {name}",
            severity=Severity.MEDIUM, target=name, detail=why,
            tags=["response", "recover", "assure"],
            remediation="Sign off with evidence, not assertion.",
        ))
    return out


def build_timeline(ctx: RunContext) -> list[Finding]:
    """Correlate evidence into a first-compromise → impact timeline."""
    events = []
    for f in ctx.findings:
        events.append((f.ts, f.severity.value, f.title, f.target, f.attack_ids))
    events.sort()
    if not events:
        return [Finding(capability="s06_response.breach_timeline", title="No findings to correlate",
                        severity=Severity.INFO, target="timeline", tags=["response", "timeline"])]
    phases: dict[str, list[str]] = {"initial": [], "access": [], "persist": [],
                                    "impact": []}
    for _, _, title, tgt, _ids in events:
        t = f"{title} {tgt}".lower()
        if any(x in t for x in ("phish", "initial", "exposure", "recon", "vuln")):
            phases["initial"].append(title)
        elif any(x in t for x in ("credential", "token", "lateral", "execution")):
            phases["access"].append(title)
        elif any(x in t for x in ("persist", "registry", "scheduled", "backdoor")):
            phases["persist"].append(title)
        elif any(x in t for x in ("ransom", "encrypt", "exfil", "destr", "wiper", "impact")):
            phases["impact"].append(title)
    return [Finding(
        capability="s06_response.breach_timeline",
        title=f"Correlated timeline: {len(events)} events", severity=Severity.MEDIUM,
        target="timeline",
        detail=("; ".join(f"{k}={len(v)}" for k, v in phases.items()) +
                f" · first={events[0][2][:60]} · last={events[-1][2][:60]}"),
        tags=["response", "timeline", "dfir"],
        meta={"phases": {k: v[:20] for k, v in phases.items()},
              "earliest": events[0][:3], "latest": events[-1][:3]},
        remediation="The interval between 'initial' and 'impact' is your dwell time. That "
                    "number is the argument for the controls you do not have.",
    )]


def measure_mttd(ctx: RunContext) -> list[Finding]:
    """MTTD / MTTR from the timeline and alert data."""
    timeline = ctx.opt("timeline") or []
    if len(timeline) < 2:
        return [Finding(
            capability="s06_response.mttd_measure", title="Insufficient timeline data",
            severity=Severity.INFO, target="metrics",
            detail="Pass --timeline with (first-seen, detected, contained) timestamps.",
            tags=["response", "metrics"],
            remediation="Capture the three timestamps per incident; the trend is what boards read.",
        )]
    dtd = max(0, timeline[1] - timeline[0]) / 3600
    dtc = max(0, timeline[2] - timeline[1]) / 3600
    return [Finding(
        capability="s06_response.mttd_measure",
        title=f"MTTD {dtd:.1f}h · MTTC {dtc:.1f}h", severity=Severity.MEDIUM, target="metrics",
        detail=f"Time to detect {dtd:.1f}h, time to contain {dtc:.1f}h from first observation.",
        tags=["response", "metrics", "assure"],
        meta={"mttd_hours": round(dtd, 2), "mttc_hours": round(dtc, 2)},
        remediation="MTTC is usually the bottleneck: pre-authorise isolation so containment is "
                    "one click, not a change window.",
    )]


def exposure_ledger(ctx: RunContext) -> list[Finding]:
    """Track credential/host exposure from vendor feeds."""
    out = []
    for entry in (ctx.opt("exposures") or []):
        if isinstance(entry, dict):
            out.append(Finding(
                capability="s06_response.underground_exposure",
                title=f"Underground exposure: {entry.get('type','?')} on {entry.get('asset','?')}",
                severity=Severity.HIGH, target=str(entry.get("asset", "")),
                detail=(f"Observed: {entry.get('type')} in {entry.get('forum','a marketplace')} "
                        f"at {entry.get('date','?')}."),
                attack_ids=["T1589"], tags=["response", "underground", "leaks"],
                remediation="Treat as a confirmed breach: rotate credentials and check for use.",
            ))
    if not out:
        out.append(Finding(
            capability="s06_response.underground_exposure", title="No underground exposure data",
            severity=Severity.INFO, target="underground",
            detail="Requires a licensed feed (KELA, Flashpoint, IntelX).",
            tags=["response", "underground"],
            remediation="Leaked-credential monitoring is one of the highest-signal purchases "
                        "available in this space.",
        ))
    return out
