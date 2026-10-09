"""S09 · Assurance, compliance and reporting.

Control-framework mapping, post-quantum inventory, HNDL exposure, supply-chain
policy-as-code, drift, SANS 5 ICS controls, audit trail, evidence packages,
continuous monitoring, risk metrics and executive reporting.
"""
from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..core.models import Evidence, Finding, RunContext, Severity

# ══════════════════════════════════════════════════════════════════ control maps
# ATT&CK technique -> (CIS Control, NIST CSF 2.0 function, NIST 800-53, CMMC domain)
CONTROL_MAP: dict[str, tuple[str, str, str, str]] = {
    "T1195.001": ("16.1", "PR.PS-01", "SA-10", "SR-3-1"),
    "T1195.002": ("16.1", "PR.PS-02", "SA-10", "SR-3-1"),
    "T1190": ("7.5", "PR.DS-06", "SI-2", "SI-2"),
    "T1055": ("10.5", "DE.CM-09", "SI-7", "SI-3"),
    "T1003": ("10.5", "DE.CM-09", "SI-7", "SI-3"),
    "T1070": ("8.2", "DE.CM-09", "AU-9", "AU-9"),
    "T1562": ("4.8", "PR.AA-05", "AC-6(9)", "AC-3-3"),
    "T1685": ("8.5", "DE.CM-01", "AU-9", "SI-3"),
    "T1686": ("13.4", "PR.IR-01", "SC-7", "SC-7"),
    "T1528": ("5.4", "PR.AA-01", "IA-2", "AC-2"),
    "T1550": ("6.5", "PR.AA-05", "IA-2", "AC-2"),
    "T1078": ("5.3", "PR.AA-05", "AC-2", "AC-2"),
    "T1552": ("3.11", "PR.DS-01", "SC-28", "SC-28"),
    "T1490": ("11.1", "RC.RP-01", "CP-9", "RC.RP-03"),
    "T1486": ("11.1", "RS.MA-01", "CP-10", "RS.MA-01"),
    "T1530": ("3.3", "PR.AA-05", "AC-3", "AC-3"),
    "T1610": ("12.1", "PR.DS-06", "CM-7", "SC-3"),
    "T1134": ("5.4", "PR.AA-05", "AC-6", "AC-6"),
    "T1558": ("5.2", "PR.AA-05", "IA-5", "AC-2"),
    "T1207": ("5.2", "PR.AA-05", "IA-5", "AC-2"),
    "T1566": ("9.6", "PR.AA-05", "SC-7", "SI-2"),
    "T1041": ("12.4", "DE.CM-03", "SC-7", "SC-7"),
    "T1213": ("3.3", "PR.DS-01", "AC-3", "AC-3"),
    "T1210": ("7.4", "PR.DS-06", "SC-7", "SC-7"),
    "T1598": ("16.1", "GV.SC-04", "RA-5", "RA-5"),
    "T1590": ("16.1", "ID.RA-01", "RA-5", "RA-5"),
    "T1204": ("14.2", "PR.AA-05", "AT-2", "AT-2"),
    "T1027": ("10.7", "DE.CM-01", "SI-3", "SI-3"),
}

# Post-quantum-relevant cryptography discovery.
# Every entry is a 3-tuple (label, compiled regex, severity). This list was
# previously a mix of 2- and 3-tuples, and the consumer took only entry[0]/entry[1]
# then re-derived severity from the label - so the declared severities were
# discarded. Ragged tuples in a data table are the same defect class as the
# CICD_RED_FLAGS 3-value unpack, so the type is now uniform.
CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("RSA", re.compile(r"(?i)\bRSA[_\-]?(?:KEY|LEN|BITS)?"), Severity.INFO),
    ("EC/ECDSA", re.compile(r"(?i)\b(?:ECDSA|EC[_\-]?KEY|secp\d+r1|prime256v1|P-256)\b"), Severity.INFO),
    ("DH/DHE", re.compile(r"(?i)\b(?:Diffie[_\-]?Hellman|DHE|dh[_\-]?params|ffdhe)\b"), Severity.INFO),
    ("TLS certificate (classical)", re.compile(r"(?i)(?:BEGIN CERTIFICATE|tls[_a-z]*certificate|ssl_certificate)"), Severity.MEDIUM),
    ("TLS (1.2/1.3 handshake)", re.compile(r"(?i)\bTLSv?1\.[23]\b|ssl_protocols|TLS_VERSION"), Severity.MEDIUM),
    ("static symmetric key", re.compile(r"(?i)\b(?:aes[_\-]?key|encryption_key|secret_key)\s*[=:]\s*[\"'][A-Za-z0-9+/=]{16,}"), Severity.HIGH),
    ("PKCS12/PFX bundle", re.compile(r"(?i)\.(?:pfx|p12|jks|keystore)\b"), Severity.INFO),
    ("HNDL candidate (long-lived data)", re.compile(
        r"(?i)(?:archive|retention|backup|immutab|data_retention|legal_hold)"), Severity.MEDIUM),
]

PQC_RE = re.compile(r"(?i)\b(?:ml[-_]?kem|kyber|ml[-_]?dsa|dilithium|falcon|sphincs|"
                    r"slh[-_]?dsa|post[-_]?quantum|oqs|pqclean)\b")


def map_controls(ctx: RunContext) -> list[Finding]:
    """Map findings onto CIS / NIST CSF / 800-53 / CMMC."""
    framework = (ctx.opt("framework") or "all").lower()
    agg: dict[str, dict[str, Any]] = {}
    unmapped = 0
    for f in ctx.findings:
        for tid in f.attack_ids:
            m = CONTROL_MAP.get(tid)
            if not m:
                unmapped += 1
                continue
            cis, csf, nist, cmmc = m
            for name, val in (("CIS", cis), ("NIST-CSF", csf), ("NIST-800-53", nist), ("CMMC", cmmc)):
                if framework not in ("all", name.lower()):
                    continue
                k = f"{name}:{val}"
                e = agg.setdefault(k, {"framework": name, "control": val, "findings": [],
                                       "max_sev": Severity.INFO, "techniques": set()})
                e["findings"].append(f.fingerprint)
                e["techniques"].add(tid)
                if f.severity.rank > e["max_sev"].rank:
                    e["max_sev"] = f.severity
    out = []
    for k, e in sorted(agg.items(), key=lambda kv: -kv[1]["max_sev"].rank):
        out.append(Finding(
            capability="s09_assure.control_mapping",
            title=f"{e['framework']} {e['control']}: {len(e['findings'])} finding(s)",
            severity=e["max_sev"], target=k,
            detail=(f"Control {e['framework']} {e['control']} is implicated by "
                    f"{', '.join(sorted(e['techniques']))}."),
            attack_ids=sorted(e["techniques"]),
            tags=["assure", "compliance", "controls", e["framework"].lower()],
            meta={"framework": e["framework"], "control": e["control"],
                  "count": len(e["findings"]), "techniques": sorted(e["techniques"])},
            remediation="This is evidence for an audit: control, technique, and finding are "
                        "all traceable.",
        ))
    if unmapped:
        out.append(Finding(
            capability="s09_assure.control_mapping",
            title=f"{unmapped} technique reference(s) have no control mapping",
            severity=Severity.LOW, target="coverage",
            detail="ATT&CK techniques in this run that are not in the mapping table.",
            tags=["assure", "compliance", "gap"],
            remediation="Extend CONTROL_MAP; unmapped techniques are compliance blind spots.",
        ))
    return out or [Finding(capability="s09_assure.control_mapping",
                           title="No findings to map", severity=Severity.INFO,
                           target="controls", tags=["assure"])]


def pqc_inventory(ctx: RunContext) -> list[Finding]:
    """Find classical cryptography you will have to migrate."""
    from ..core.util import read_text, walk_files
    exts = {".py", ".js", ".ts", ".go", ".java", ".cs", ".rb", ".php", ".sh", ".yaml",
            ".yml", ".json", ".toml", ".conf", ".cfg", ".ini", ".pem", ".properties", ".md"}
    found: dict[str, list[str]] = {}
    worst: dict[str, Severity] = {}
    pqc_seen = False
    for root in ((ctx.scope.repos if ctx.scope else []) or [str(ctx.workdir)]):
        for f in walk_files(root, exts=exts, limit=60_000):
            body = read_text(f, 900_000)
            if not body:
                continue
            if PQC_RE.search(body):
                pqc_seen = True
            for name, rx, sev in CRYPTO_PATTERNS:
                if rx.search(body):
                    found.setdefault(name, []).append(str(f))
                    # keep the MOST severe declared severity (highest score)
                    if name not in worst or sev.score > worst[name].score:
                        worst[name] = sev
    out = []
    for name, files in sorted(found.items()):
        # severity comes from the pattern table, not from guessing at the label
        sev = worst.get(name, Severity.INFO)
        out.append(Finding(
            capability="s09_assure.pqc_inventory",
            title=f"Classical crypto: {name} in {len(files)} file(s)", severity=sev,
            target=name,
            detail=("You cannot migrate what you cannot find. This is the ACDI problem: "
                    "automated crypto discovery is the actual bottleneck, not algorithm choice."
                    if not name.startswith("HNDL") else
                    "Long-lived data retention/archival is the highest-value harvest-now-"
                    "decrypt-later target."),
            attack_ids=["T1600.001"], tags=["assure", "pqc", "crypto"],
            confidence="medium",
            meta={"kind": name, "files": files[:100], "count": len(files)},
            remediation="Adopt automated discovery (CISA's ACDI direction), then plan migration "
                        "by data lifetime: what you must keep 10+ years moves first.",
        ))
    if pqc_seen:
        out.append(Finding(
            capability="s09_assure.pqc_inventory", title="Post-quantum primitives already present",
            severity=Severity.OK, target="pqc",
            detail="PQC references (ML-KEM/ML-DSA/Kyber-class) were found.",
            tags=["assure", "pqc"],
            remediation="Confirm they are used for key establishment, not just referenced.",
        ))
    return out or [Finding(
        capability="s09_assure.pqc_inventory", title="No classical crypto references found",
        severity=Severity.INFO, target="pqc",
        detail="Nothing scanned — or the estate really is clean. Verify the scan covered the "
               "repositories and services you expect.",
        tags=["assure", "pqc"])]


def hndl_review(ctx: RunContext) -> list[Finding]:
    """Prioritise data by harvest-now-decrypt-later risk."""
    data = ctx.opt("long_lived_data") or []
    out = []
    for entry in data:
        name = entry.get("name") if isinstance(entry, dict) else str(entry)
        years = entry.get("retention_years", 0) if isinstance(entry, dict) else 0
        sens = (entry.get("sensitivity") or "unknown") if isinstance(entry, dict) else "unknown"
        if isinstance(years, (int, float)) and years >= 10:
            sev = Severity.HIGH if str(sens).lower() in ("high", "critical", "pii", "phi") \
                else Severity.MEDIUM
            out.append(Finding(
                capability="s09_assure.harvest_now_decrypt",
                title=f"HNDL risk: {name} ({years}y retention, {sens})",
                severity=sev, target=str(name),
                detail=(f"Data retained {years} years outlives RSA-2048/ECP-256 by a wide margin. "
                        "An adversary can collect it now and decrypt it once a cryptographically "
                        "relevant quantum computer exists."),
                attack_ids=["T1600.001"], tags=["assure", "pqc", "data", "critical"],
                remediation="Migrate the key exchange for this data now; the data itself cannot "
                            "be retro-protected, only the access path can.",
            ))
    if not out:
        out.append(Finding(
            capability="s09_assure.harvest_now_decrypt", title="No long-lived data inventory supplied",
            severity=Severity.INFO, target="hndl",
            detail="Pass --long-lived-data to prioritise. The metric that matters is: how long "
                   "must you keep this, and can that key still be broken?",
            tags=["assure", "pqc"],
            remediation="CSA's 2026 note on PQC risk to AI infrastructure is worth reading — model "
                        "weights and training data are the longest-lived, highest-value targets.",
        ))
    return out


def policy_engine(ctx: RunContext) -> list[Finding]:
    """Evaluate findings against the org's supply-chain policy."""
    policy = ctx.opt("policy") or {}
    if not policy:
        return [Finding(
            capability="s09_assure.supplychain_policy", title="No supply-chain policy loaded",
            severity=Severity.MEDIUM, target="policy",
            detail=("Without a written policy, remediation is a matter of opinion. Provide a "
                    "policy dict, e.g. "
                    "{'block_critical_deps': True, 'require_provenance': True, "
                    "'forbid_long_lived_keys': True, 'forbid_wildcard_iam': True}."),
            tags=["assure", "supplychain", "policy"],
            remediation="Codify the rules; then this becomes a CI gate, not a discussion.",
        )]
    out = []
    RULES = [
        ("block_critical_deps", "critical", "Critical dependency vulnerabilities must block the build", Severity.CRITICAL),
        ("require_provenance", "provenance", "Every release artifact must carry verified provenance", Severity.HIGH),
        ("forbid_long_lived_keys", "signing", "Long-lived signing/registry keys are forbidden", Severity.CRITICAL),
        ("forbid_wildcard_iam", "iam", "Wildcard IAM permissions are forbidden", Severity.CRITICAL),
        ("block_missing_attestation", "attestation", "Missing attestations block release", Severity.HIGH),
    ]
    for key, tag, why, sev in RULES:
        if not policy.get(key):
            continue
        hits = [f for f in ctx.findings if tag in f.tags]
        if hits:
            out.append(Finding(
                capability="s09_assure.supplychain_policy",
                title=f"Policy violated: {why}", severity=sev,
                target=key,
                detail=f"{len(hits)} finding(s) violate this rule: " +
                       "; ".join(h.title[:60] for h in hits[:4]),
                tags=["assure", "supplychain", "policy", "critical"],
                remediation="Fail the pipeline. A policy that warns is not a policy.",
            ))
    return out or [Finding(capability="s09_assure.supplychain_policy",
                           title="All loaded supply-chain policies satisfied",
                           severity=Severity.OK, target="policy",
                           tags=["assure", "supplychain", "policy"])]


def drift_check(ctx: RunContext) -> list[Finding]:
    """Detect drift from a hardening baseline."""
    baseline = ctx.opt("baseline") or {}
    current = ctx.opt("current") or {}
    if not baseline:
        return [Finding(
            capability="s09_assure.config_drift", title="No baseline to compare against",
            severity=Severity.INFO, target="drift",
            detail="Pass --baseline <json> and --current <json> key/value maps.",
            tags=["assure", "drift"])]
    changed = {k: (baseline.get(k), current.get(k))
               for k in set(baseline) | set(current)
               if baseline.get(k) != current.get(k)}
    out = [Finding(
        capability="s09_assure.config_drift",
        title=f"Configuration drift: {len(changed)} key(s) changed",
        severity=Severity.MEDIUM if changed else Severity.OK, target="drift",
        detail="; ".join(f"{k}: {a!r} -> {b!r}" for k, (a, b) in list(changed.items())[:12]),
        attack_ids=["T1562"], tags=["assure", "drift", "hardening"],
        meta={"changed": {k: {"from": a, "to": b} for k, (a, b) in changed.items()}},
        remediation="Weakening changes (firewall, logging, MFA) deserve an immediate explanation.",
    )]
    return out


def ics_controls(ctx: RunContext) -> list[Finding]:
    """SANS 5 ICS critical controls."""
    FIVE = [
        ("ICS1", "Use a secure network architecture", Severity.HIGH,
         "Identity-based segmentation, not IP-based trust."),
        ("ICS2", "Configure monitoring", Severity.MEDIUM,
         "OT visibility: no monitoring means no detection in a domain that cannot patch."),
        ("ICS3", "Segment control system networks", Severity.CRITICAL,
         "Compromise of IT should not reach the control system."),
        ("ICS4", "Use application allowlisting", Severity.HIGH,
         "Allowlisting is the only realistic control in an unpatchable environment."),
        ("ICS5", "Detect and respond to inappropriate changes", Severity.MEDIUM,
         "Configuration change detection in OT."),
    ]
    ev = ctx.opt("ics_evidence") or {}
    out = []
    for code, name, sev, why in FIVE:
        ok = ev.get(code) in (True, "yes", "done")
        out.append(Finding(
            capability="s09_assure.ics_control_check",
            title=f"{code} {name} — {'ASSESSED' if ok else 'NOT ASSESSED'}",
            severity=Severity.OK if ok else sev, target=code,
            detail=why, tags=["assure", "ics", "ot", "military"],
            remediation="Dragos recorded 708 ransomware incidents against industrial entities in "
                        "a single quarter. Identity-based segmentation is the decisive control.",
        ))
    return out


def audit_export(ctx: RunContext) -> list[Finding]:
    """Export the audit trail."""
    if not ctx.store:
        return [Finding(capability="s09_assure.audit_trail", title="No store attached",
                        severity=Severity.INFO, target="audit", tags=["assure", "audit"])]
    trail = ctx.store.audit_trail(500)
    p = Path(ctx.workdir) / f"audit-{ctx.run_id}.json"
    p.write_text(json.dumps(trail, indent=2, default=str), encoding="utf-8")
    return [Finding(
        capability="s09_assure.audit_trail", title=f"Audit trail exported ({len(trail)} events)",
        severity=Severity.INFO, target=str(p),
        detail="Every run, scan and action is recorded with a timestamp and actor.",
        tags=["assure", "audit", "compliance"],
        evidence=[Evidence(kind="output", summary="audit", locator=str(p),
                           excerpt=json.dumps(trail[-10:], indent=2, default=str)[:800])],
        remediation="Ship to your SIEM or a WORM store if audit integrity is in scope.",
    )]


def evidence_package(ctx: RunContext) -> list[Finding]:
    """Assemble the engagement evidence bundle."""
    from ..core.util import write_json
    pkg = {
        "run_id": ctx.run_id,
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scope": ctx.scope.to_dict() if ctx.scope else {},
        "active": ctx.active,
        "profile": ctx.profile,
        "findings": [f.to_dict() for f in ctx.findings],
        "notes": ctx.notes,
    }
    p = Path(ctx.workdir) / f"package-{ctx.run_id}.json"
    write_json(p, pkg)
    if ctx.store:
        new, upd = ctx.store.upsert_findings(ctx.run_id, ctx.findings)
    else:
        new, upd = len(ctx.findings), 0
    return [Finding(
        capability="s09_assure.evidence_package",
        title=f"Evidence package: {len(ctx.findings)} findings ({new} new, {upd} known)",
        severity=Severity.INFO, target=str(p),
        detail="Scope, findings, evidence and notes serialised for defensible retention.",
        tags=["assure", "evidence", "audit"],
        evidence=[Evidence(kind="output", summary="package", locator=str(p),
                           excerpt=json.dumps(pkg, indent=2, default=str)[:700])],
        remediation="Attach the scope authorisation record. 'I was authorised' is a defence.",
    )]


def monitor_loop(ctx: RunContext) -> list[Finding]:
    """Continuous monitoring: one pass, plus a diff against the stored baseline."""
    from ..core.util import dedupe
    cur = dedupe([f.target for f in ctx.findings if f.target])
    if ctx.store:
        prev_rows = ctx.store.findings(limit=5000)
        prev = {r["target"] for r in prev_rows if r.get("target")}
    else:
        prev = set()
    new = sorted(set(cur) - prev) if prev else []
    return [Finding(
        capability="s09_assure.continuous_monitor",
        title=f"Monitoring pass: {len(cur)} targets with findings, {len(new)} newly appearing",
        severity=Severity.MEDIUM if new else Severity.INFO, target="monitor",
        detail=("New targets: " + ", ".join(new[:15])) if new else "No new exposure this cycle.",
        tags=["assure", "monitor", "continuous"],
        meta={"new_targets": new, "known_targets": len(prev)},
        remediation="Run this on a schedule; the value is in the trend, not any single pass.",
    )]


def rollup(ctx: RunContext) -> list[Finding]:
    """Board-level metrics: severity distribution, risk, coverage, trend."""
    from collections import Counter
    c = Counter(f.severity.value for f in ctx.findings)
    risk = round(sum(f.severity.score for f in ctx.findings), 1)
    techniques = {a for f in ctx.findings for a in f.attack_ids}
    caps = {f.capability for f in ctx.findings}
    trend = ctx.store.coverage_trend(30) if ctx.store else []
    out = [Finding(
        capability="s09_assure.metrics_rollup",
        title=f"Risk rollup: {len(ctx.findings)} findings, score {risk}",
        severity=Severity.MEDIUM if c.get("critical") else Severity.INFO, target="metrics",
        detail=("; ".join(f"{k}={v}" for k, v in sorted(c.items())) +
                f" · {len(techniques)} techniques · {len(caps)} capabilities"),
        tags=["assure", "metrics", "board"],
        meta={"severity": dict(c), "risk": risk, "techniques": len(techniques),
              "capabilities": len(caps), "coverage_trend": trend[-10:]},
        remediation="Report the trend of critical/high count, not the absolute number. A flat "
                    "number with rising MTTR is deterioration.",
    )]
    return out


def report(ctx: RunContext) -> list[Finding]:
    """Render the full report set from the current run."""
    from ..core import render
    fmts = ctx.opt("formats") or ["md", "sarif", "csv", "html", "json"]
    if isinstance(fmts, str):
        fmts = [f.strip() for f in fmts.split(",") if f.strip()]
    meta = {"run_id": ctx.run_id, "profile": ctx.profile, "active": ctx.active,
            "authorised_by": ctx.scope.authorised_by if ctx.scope else "",
            "reference": ctx.scope.reference if ctx.scope else ""}
    written: list[str] = []
    base = Path(ctx.workdir)
    # The two human-readable renderers take (findings, meta); the machine formats
    # take (findings) only. Keeping that distinction in the table, rather than at
    # the call site, means a new format cannot be wired up with the wrong arity.
    writers: dict[str, tuple[str, Callable[[list[Any], dict[str, Any]], str]]] = {
        "md": ("report.md", render.to_markdown),
        "html": ("report.html", render.to_html),
    }
    writers_single: dict[str, tuple[str, Callable[[list[Any]], str]]] = {
        "sarif": ("report.sarif", render.to_sarif),
        "csv": ("report.csv", render.to_csv),
        "json": ("report.json", render.findings_json),
    }
    for f in fmts:
        if f in writers:
            name, text = writers[f][0], writers[f][1](ctx.findings, meta)
        elif f in writers_single:
            name, text = writers_single[f][0], writers_single[f][1](ctx.findings)
        else:
            continue
        p = base / f"{ctx.run_id}-{name}"
        try:
            p.write_text(text, encoding="utf-8")
            written.append(f"{f}→{p.name}")
        except Exception as e:  # noqa: BLE001
            ctx.note(f"report format {f} failed: {e}")
    return [Finding(
        capability="s09_assure.executive_report",
        title=f"Reports written: {', '.join(written) or 'none'}",
        severity=Severity.INFO, target=str(base),
        detail=f"{len(ctx.findings)} findings rendered into {len(written)} format(s).",
        tags=["assure", "reporting"],
        remediation="SARIF uploads to code-scanning dashboards; SARIF + HTML is the pairing "
                    "engineers and executives both accept.",
    )]
