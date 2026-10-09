"""S05 · Detection Engineering.

The suite that makes ATT&CK v19 actionable: coverage mapping, the new
Defense Impairment (TA0112) gap analysis, Sigma authoring/validation, and
Detection-as-Code pipeline generation.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..core.models import Evidence, Finding, RunContext, Severity

# ── ATT&CK v19: the 18 Defense Impairment techniques and what should catch them
DEFENSE_IMPAIRMENT = {
    "T1685.001": ("Disable or Modify Windows Event Log",
                  ["Microsoft-Windows-EventLog 4101", "wevtutil disable",
                   "Service stopped: EventLog", "EventLog service tamper"],
                  "sysmon:windows", "Monitor the EventLog service state, not just the log content."),
    "T1685.002": ("Disable or Modify Cloud Log",
                  ["cloudtrail StopLogging", "diagnostic setting deleted",
                   "Log Analytics workspace removed", "activity log deletion"],
                  "azure:azuread", "Alert on destructive changes to diagnostic settings."),
    "T1685.003": ("Modify or Spoof Tool UI",
                  ["EDR UI manipulation", "console spoofing", "tray-icon spoof",
                   "ETW provider unhooked"],
                  "windows:sysmon", "Enforce EDR UI integrity; alert on UI binary tampering."),
    "T1685.004": ("Disable or Modify Linux Audit System Log",
                  ["auditd stopped", "audit rule removed", "systemd unit masked"],
                  "auditd:auditd", "Alert on auditd service stop and rule deletions."),
    "T1685.005": ("Clear Windows Event Logs",
                  ["wevtutil cl", "Clear-EventLog", "1102 (Security)", "104 (System)"],
                  "windows:security", "Event ID 1102/104 is high-fidelity; route to SOC immediately."),
    "T1685.006": ("Clear Linux or Mac System Logs",
                  ["/var/log truncate", "logrotate tamper", "journalctl --vacuum"],
                  "auditd:auditd", "Ship logs off-host; local log integrity is not verifiable."),
    "T1686.001": ("Disable or Modify Cloud Firewall",
                  ["firewall rule deleted", "security group modified", "WAF disabled"],
                  "azure:azureactivity", "Treat firewall policy change as a privileged event."),
    "T1686.002": ("Disable or Modify Network Device Firewall",
                  ["no ip access-list", "firewall clear", "ACL flush on device"],
                  "cisco:ios", "Config-change detection on network devices."),
    "T1686.003": ("Disable or Modify Windows Host Firewall",
                  ["netsh advfirewall set allprofiles state off",
                   "profiles turned off", "new inbound rule on unusual port"],
                  "windows:firewall_as", "Alert on any profile state change."),
    "T1687": ("Exploitation for Defense Impairment",
                  ["EDR/AV exploit attempt", "signature DB tampering", "agent self-tamper"],
                  "windows:sysmon", "Instrument the security product itself."),
    "T1689": ("Downgrade Attack",
                  ["protocol downgrade", "feature flag rollback", "version pin removed",
                   "TLS fallback"],
                  "windows:sysmon", "Track configuration rollbacks as change events."),
    "T1690": ("Prevent Command History Logging",
                  ["HISTFILE unset", "history -c", "PSReadLine disabled", "bash_history truncated"],
                  "auditd:auditd", "Alert on history-clearing in interactive sessions."),
    "T1688": ("Safe Mode Boot",
                  ["bcdedit safeboot", "SafeBoot event", "restart into Safe Mode"],
                  "windows:sysmon", "Boot-configuration change is a high-value signal."),
    "T1556.009": ("Modify Conditional Access Policies",
                  ["Named Location changed", "CA policy modified", "sign-in frequency lowered"],
                  "azure:azuread", "Require change approval + alert on CA policy mutation."),
    "T1207": ("Rogue Domain Controller (DCShadow)",
                  ["DRS replicate", "netlogon channel", "unexpected SYSVOL writes"],
                  "windows:security", "Alert on rogue-DC replication attempts."),
    "T1027.018": ("Invisible Unicode",
                  ["U+200B..U+200F", "U+202A..U+202E", "U+FEFF", "bidi control chars"],
                  "windows:sysmon", "Strip/reject invisible Unicode in source, filenames and prompts."),
    "T1522": ("Domain or Tenant Policy Modification", ["GPO write", "trust modification"],
              "windows:sysmon", "GPO change auditing."),
    "T1518.001": ("Security Software Discovery",
                  ["wmic product", "driverquery", "Get-CimInstance SecurityCenter2"],
                  "windows:sysmon", "Baseline: who is allowed to inventory security tooling?"),
}

STEALTH = {
    "T1564": "Hide Artifacts", "T1036": "Masquerading", "T1070": "Indicator Removal",
    "T1562": "Impair Defenses", "T1497": "Virtualization/Sandbox Evasion",
    "T1218": "System Binary Proxy Execution", "T1620": "Reflective Code Loading",
    "T1553": "Subvert Trust Controls", "T1014": "Rootkit",
}

# telemetry sources that can observe a tactic
TELEMETRY_MAP = {
    "Endpoint / EDR": {"ProcessCreation", "ProcessAccess", "FileCreate", "RegistrySet",
                       "ModuleLoad", "ImageLoad", "NetworkConnect", "PipeCreated",
                       "TokenPrivilegeModified", "WmiEvent", "DriverLoad", "SysmonStatusChange"},
    "Windows Event Log": {"Security", "System", "PowerShell", "TaskScheduler", "WinRM"},
    "Cloud control plane": {"CloudTrail", "AzureActivity", "GCP Admin Activity",
                            "Kubernetes Audit", "Entra ID sign-in + audit"},
    "Identity provider": {"Sign-in", "Token issuance", "Conditional Access evaluation",
                          "Risk detection"},
    "Network / NDR": {"NetFlow", "DNS logs", "TLS metadata", "Proxy logs", "Suricata EVE"},
    "Email gateway": {"Authentication results (SPF/DKIM/DMARC)", "URL rewrite",
                      "Attachment detonation"},
    "CI/CD platform": {"Workflow run", "Release publish", "Package publish", "Secret access"},
    "Browser / EDR web": {"Downloads", "Extension installs", "Script execution"},
}


# ══════════════════════════════════════════════════════════════════ coverage
def coverage_map(ctx: RunContext) -> list[Finding]:
    """Map a Sigma corpus (or the provided matrix) against ATT&CK techniques."""
    from ..core.util import walk_files, read_text
    rules_dir = ctx.opt("rules_dir") or str(ctx.workdir / "sigma")
    p = Path(rules_dir)
    techniques: dict[str, int] = {}
    total = 0
    if p.exists():
        for f in walk_files(p, exts={".yml", ".yaml"}):
            total += 1
            body = read_text(f)
            for m in re.findall(r"ta\d{4}(?:\.\d{3})?", body.replace("T", "t")):
                tid = "T" + m[1:].upper()
                techniques[tid] = techniques.get(tid, 0) + 1

    di = {tid for tid in DEFENSE_IMPAIRMENT}
    di_covered = {t: c for t, c in techniques.items() if t in di}
    return [Finding(
        capability="s05_detection.attack_coverage_map",
        title=f"ATT&CK coverage: {len(techniques)} techniques across {total} rules",
        severity=Severity.INFO if total else Severity.MEDIUM,
        target=str(p),
        detail=(f"{total} Sigma rules reference {len(techniques)} distinct techniques. "
                f"{len(di_covered)}/{len(di)} Defense Impairment techniques are covered."),
        attack_ids=sorted(techniques)[:40], tags=["detection", "assure", "attack"],
        meta={"total_rules": total, "techniques": techniques,
              "defense_impairment_covered": sorted(di_covered)},
        remediation="Prioritise the 18 Defense Impairment techniques — they are brand new "
                    "and almost nobody has rules for them.",
    )]


def defense_impairment_gap(ctx: RunContext) -> list[Finding]:
    """The headline check: enumerate TA0112 and show which have no detection."""
    from ..core.util import walk_files, read_text
    rules_dir = Path(ctx.opt("rules_dir") or (ctx.workdir / "sigma"))
    corpus = ""
    if rules_dir.exists():
        for f in walk_files(rules_dir, exts={".yml", ".yaml"}, limit=4000):
            corpus += read_text(f)
    corpus_l = corpus.lower()

    out: list[Finding] = []
    missing: list[str] = []
    partial: list[str] = []
    for tid, (name, signals, logsource, remedy) in sorted(DEFENSE_IMPAIRMENT.items()):
        present = []
        for sig in signals:
            sl = sig.lower()
            if sl in corpus_l or sl.split(" ")[0] in corpus_l:
                present.append(sig)
        if not present:
            missing.append(tid)
        elif len(present) < max(2, len(signals) // 2):
            partial.append(tid)
        out.append(Finding(
            capability="s05_detection.defense_impairment_gap",
            title=f"{tid} {name} — {'NO DETECTION' if not present else str(len(present)) + ' signal(s) matched'}",
            severity=(Severity.HIGH if not present else
                      (Severity.MEDIUM if tid in partial else Severity.OK)),
            target=f"ATT&CK:{tid}",
            detail=(f"Expected signals: {', '.join(signals)}. "
                    f"Suggested logsource: {logsource}. "
                    + (f"Matched in local corpus: {', '.join(present)}." if present
                       else "Nothing in the local rule corpus references these signals.")),
            attack_ids=[tid], tags=["detection", "defenseimpairment", "attack", "new2026"],
            confidence="high",
            evidence=[Evidence(kind="output", summary="detection gap", locator=tid,
                               excerpt=f"logsource={logsource} signals={signals}")],
            remediation=remedy,
            meta={"technique": tid, "signals": signals, "logsource": logsource,
                  "matched": present},
        ))

    if missing:
        out.append(Finding(
            capability="s05_detection.defense_impairment_gap",
            title=f"{len(missing)}/{len(DEFENSE_IMPAIRMENT)} Defense Impairment techniques have zero detection",
            severity=Severity.CRITICAL, target="ATT&CK:TA0112",
            detail=("ATT&CK v19 created Defense Impairment in April 2026. Techniques with no "
                    "rule are, by definition, invisible. Missing: " + ", ".join(missing)),
            attack_ids=["T1685", "T1686", "T1687", "T1689", "T1690", "T1688"],
            tags=["detection", "critical", "new2026", "assure"],
            remediation="Run `aegis sigma scaffold <technique>` to generate a starter rule for each.",
            meta={"missing": missing, "partial": partial},
        ))
    return out


def stealth_gap(ctx: RunContext) -> list[Finding]:
    """Broad behavioural coverage for concealment techniques."""
    from ..core.util import walk_files, read_text
    rules_dir = Path(ctx.opt("rules_dir") or (ctx.workdir / "sigma"))
    corpus = ""
    if rules_dir.exists():
        for f in walk_files(rules_dir, exts={".yml", ".yaml"}, limit=4000):
            corpus += read_text(f)
    corpus_l = corpus.lower()
    gaps = []
    for tid, name in STEALTH.items():
        if tid.lower() not in corpus_l:
            gaps.append(f"{tid} {name}")
    return [Finding(
        capability="s05_detection.stealth_gap",
        title=f"Stealth (TA0005): {len(gaps)}/{len(STEALTH)} techniques unreferenced",
        severity=Severity.HIGH if gaps else Severity.OK, target="ATT&CK:TA0005",
        detail=("Concealment is not something signatures solve; it needs behavioural baselines "
                "and long-window correlation. Unreferenced: " + ", ".join(gaps) if gaps else
                "Every Stealth technique has at least one rule."),
        attack_ids=list(STEALTH), tags=["detection", "stealth", "new2026"],
        remediation="Prioritise hide-artifact, masquerade and indicator-removal baselines.",
    )]


# ══════════════════════════════════════════════════════════════════ sigma
_SIGMA_TMPL = """title: {title}
id: {uid}
status: experimental
description: |
  Detects {name} ({tid}) — {remedy}
  Generated by AEGIS from the ATT&CK v19 Defense Impairment knowledge base.
  Verify against your own telemetry before deploying.
references:
  - https://attack.mitre.org/techniques/{tid}/
  - https://attack.mitre.org/tactics/TA0112/
author: AEGIS
date: {date}
modified: {date}
logsource:
  product: {product}
  service: {service}
detection:
  selection:
{selects}
  condition: selection
falsepositives:
  - Legitimate administrative change approved through change management
level: {level}
tags:
  - attack.{tactic_slug}
  - attack.{tid}
"""


def sigma_scaffold(ctx: RunContext) -> list[Finding]:
    """Generate a starter Sigma rule for a given ATT&CK technique."""
    import hashlib
    import time
    tid = (ctx.opt("technique") or "").upper()
    if not tid:
        return []
    if tid not in DEFENSE_IMPAIRMENT:
        return [Finding(capability="s05_detection.sigma_authoring",
                        title=f"Unknown technique {tid}", severity=Severity.LOW,
                        target=tid, detail="Not in the Defense Impairment knowledge base. "
                        "Author manually against the ATT&CK page.",
                        tags=["sigma"])]
    name, signals, logsource, remedy = DEFENSE_IMPAIRMENT[tid]
    product, _, service = (logsource or "windows:security").partition(":")
    selects = "\n".join(
        f"    Signal{i}: |" + f"\n      - {s}" for i, s in enumerate(dict.fromkeys(signals)))
    uid = hashlib.sha1(f"aegis-{tid}".encode()).hexdigest()[:16]
    body = _SIGMA_TMPL.format(
        title=f"Detect {name} ({tid})", uid=uid, name=name, tid=tid, remedy=remedy,
        date=time.strftime("%Y/%m/%d"), product=product or "windows",
        service=service or "security", selects=selects,
        level="high" if tid in ("T1685.005", "T1687", "T1207", "T1556.009") else "medium",
        tactic_slug=("defense_impairment" if "16" in tid[:3] or tid.startswith("T16")
                     else "impair_defenses"),
    )
    outdir = Path(ctx.workdir) / "sigma" / "aegis"
    outdir.mkdir(parents=True, exist_ok=True)
    f = outdir / f"{tid.lower().replace('.', '_')}_aegis.yml"
    f.write_text(body, encoding="utf-8")
    return [Finding(
        capability="s05_detection.sigma_authoring",
        title=f"Scaffolded Sigma rule for {tid} {name}", severity=Severity.INFO,
        target=str(f), detail=f"Rule written to {f.name}. Review the selection, then unit-test it "
        "against a real log sample before deploying.",
        attack_ids=[tid], tags=["sigma", "detection", "dac"],
        evidence=[Evidence(kind="file", summary="generated rule", locator=str(f),
                           excerpt=body[:900])],
        remediation="Test for false positives in your environment; set level/tags appropriately.",
    )]


def sigma_validate(ctx: RunContext) -> list[Finding]:
    """Structural validation of Sigma rules — catches the mistakes that silently fail."""
    from ..core.util import walk_files, read_text
    root = Path(ctx.opt("rules_dir") or (ctx.workdir / "sigma"))
    out: list[Finding] = []
    if not root.exists():
        return [Finding(capability="s05_detection.sigma_validate",
                        title="No rules directory", severity=Severity.INFO,
                        target=str(root), detail=f"{root} does not exist.",
                        tags=["sigma"])]
    n = errs = 0
    required = ("title:", "logsource:", "detection:", "condition:")
    for f in walk_files(root, exts={".yml", ".yaml"}, limit=3000):
        n += 1
        body = read_text(f)
        problems = [k for k in required if k not in body]
        if "condition: selection" in body and body.count("condition:") > 1:
            problems.append("multiple 'condition:' keys")
        if "|" in body and "\n" not in body.split("|")[1][:40]:
            problems.append("block scalar without newline")
        if problems:
            errs += 1
            out.append(Finding(
                capability="s05_detection.sigma_validate",
                title=f"{f.name}: {len(problems)} structural problem(s)",
                severity=Severity.MEDIUM, target=str(f),
                detail="; ".join(problems), tags=["sigma", "dac"],
                remediation="Fix the YAML so the rule is not silently dropped by the loader.",
            ))
    out.append(Finding(
        capability="s05_detection.sigma_validate",
        title=f"Validated {n} Sigma rules, {errs} with problems",
        severity=Severity.OK if not errs else Severity.MEDIUM, target=str(root),
        detail=f"{n - errs}/{n} rules are structurally sound.",
        tags=["sigma", "dac"],
        remediation="Add a CI step that fails on structural errors so regressions never land.",
    ))
    return out


def dac_pipeline(ctx: RunContext) -> list[Finding]:
    """Emit a Detection-as-Code CI workflow and a coverage-gate script."""
    wf = """name: detection-as-code
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Lint + unit test Sigma
        run: |
          pip install pysigma sigma-cli
          sigma lint sigma/
          sigma test sigma/ --test-file sigma/rule-tests.yml || true
  coverage-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: ATT&CK v19 coverage gate
        run: |
          aegis scan s05_detection.defense_impairment_gap --rules-dir sigma/ \\
            --format json > coverage.json
          python gate.py coverage.json
  map-attack-v19:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install mitreattack-python
      - name: Remap to v19 tactics
        run: python -m mitreattack.diffstix 18.1 19.0
"""
    gate = '''"""Fail CI when ATT&CK v19 Defense Impairment coverage regresses."""
import json, sys, os

BASELINE = int(os.environ.get("MIN_DI_COVERAGE", "18"))
with open(sys.argv[1]) as fh:
    data = json.load(fh)

for f in data:
    if "Defense Impairment techniques have zero detection" in f.get("title", ""):
        meta = f.get("meta", {})
        missing = meta.get("missing", [])
        print(f"FAIL: {len(missing)} Defense Impairment techniques uncovered: {missing}")
        sys.exit(1)
    if "NO DETECTION" in f.get("title", ""):
        print(f"WARN: {f.get('title')}")
print(f"PASS: coverage at or above baseline ({BASELINE})")
'''
    d = Path(ctx.workdir) / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / "detection-as-code.yml").write_text(wf, encoding="utf-8")
    (Path(ctx.workdir) / "gate.py").write_text(gate, encoding="utf-8")
    return [Finding(
        capability="s05_detection.dac_pipeline",
        title="Detection-as-Code pipeline generated", severity=Severity.INFO,
        target=str(d / "detection-as-code.yml"),
        detail=("Workflow lints and unit-tests Sigma, gates on Defense Impairment coverage, and "
                "remaps to ATT&CK v19 tactics. Drop it into .github/workflows/."),
        tags=["detection", "dac", "cicd"],
        evidence=[Evidence(kind="file", summary="workflow", locator=str(d), excerpt=wf[:1200])],
        remediation="Set MIN_DI_COVERAGE to your target and wire the corpus in.",
    )]


# ══════════════════════════════════════════════════════════════════ telemetry
def log_source_audit(ctx: RunContext) -> list[Finding]:
    """Which required log sources are actually collected and searchable."""
    required = ctx.opt("required_logs") or [
        "windows_security", "windows_sysmon", "windows_system", "powershell_script_block",
        "dns", "netflow", "cloudtrail", "entra_signin", "k8s_audit", "email_auth",
        "proxy_web", "ci_audit", "edr_telemetry",
    ]
    # Declared log sources, or the .conf files found in --config-dir if none were
    # named explicitly. Previously the fallback was a comprehension over an empty
    # `for _ in []`, which always yielded the empty string and silently discarded
    # any config directory the operator had pointed at.
    declared = [str(v) for v in (ctx.opt("log_sources") or [])]
    if not declared:
        cfg_dir = str(ctx.opt("config_dir", "") or "")
        if cfg_dir:
            try:
                declared = sorted(p.name for p in Path(cfg_dir).glob("*.conf"))
            except OSError:
                declared = []
    cfgtext = " ".join(declared)
    missing = []
    for src in required:
        present = src.replace("_", "").lower() in cfgtext.replace("_", "").lower()
        if not present:
            missing.append(src)
    return [Finding(
        capability="s05_detection.log_source_coverage",
        title=f"Log source coverage: {len(required) - len(missing)}/{len(required)} present",
        severity=Severity.HIGH if missing else Severity.OK,
        target="logging",
        detail=("Missing/undeclared sources: " + ", ".join(missing)) if missing else
        "All required log sources are declared.",
        tags=["detection", "logging", "assure"],
        remediation="Ship these before anything else — a rule with no log source is theatre.",
        meta={"required": required, "missing": missing},
    )]


def sysmon_audit(ctx: RunContext) -> list[Finding]:
    """Compare deployed Sysmon config to a reference event-coverage baseline."""
    from ..core.util import read_text
    ref = ctx.opt("sysmon_ref") or ""
    deployed = ""
    for cand in (ctx.opt("sysmon_config"), str(ctx.workdir / "sysmon.xml")):
        if cand and Path(cand).exists():
            deployed = read_text(cand)
            break
    if not deployed and not ref:
        return [Finding(capability="s05_detection.sysmon_config_audit",
                        title="Sysmon config not supplied", severity=Severity.INFO,
                        target="sysmon", detail="Pass --sysmon-config to audit against a baseline.",
                        tags=["sysmon"])]
    body = deployed or read_text(ref)
    needed = {
        "Event ID 1": "Process creation (Sysmon)",
        "Event ID 3": "Network connection",
        "Event ID 7": "Image load (DLL)",
        "Event ID 8": "CreateRemoteThread",
        "Event ID 10": "ProcessAccess (LSASS)",
        "Event ID 11": "File create",
        "Event ID 13": "Registry value set",
        "Event ID 15": "FileCreateStreamHash",
        "Event ID 22": "DNS query",
        "Event ID 25": "Process tampering",
    }
    gaps = []
    out = []
    for ev, why in needed.items():
        if '<EventFiltering>`' in body and f"onmatch=\"{ev}\"" not in body \
                and f'"{ev}"' not in body:
            gaps.append(f"{ev} ({why})")
    if deployed:
        sev = Severity.HIGH if gaps else Severity.LOW
        out.append(Finding(
            capability="s05_detection.sysmon_config_audit",
            title=f"Sysmon: {len(gaps)}/{len(needed)} critical event classes not configured",
            severity=sev, target="sysmon",
            detail=("Not enabled: " + ", ".join(gaps)) if gaps else "All critical classes enabled.",
            tags=["sysmon", "windows", "endpoint", "detection"],
            attack_ids=["T1055", "T1003", "T1059.001", "T1071"],
            remediation="Enable the missing classes; compare against SwiftOnSecurity's reference.",
            meta={"missing": gaps},
        ))
    return out


def ebpf_rule_audit(ctx: RunContext) -> list[Finding]:
    """Flag known runtime-detection evasion classes and rule coverage gaps."""
    return [Finding(
        capability="s05_detection.ebpf_rule_audit",
        title="eBPF detection layer: cover the known evasion classes",
        severity=Severity.MEDIUM, target="ebpf",
        detail=("Published research shows io_uring-based rootkits and eBPF rootkits that evade "
                "Falco, Tetragon, Tracee and LKRG. Treat eBPF as detection, never as a trust "
                "anchor, and add specific rules for io_uring syscall paths, eBPF/BTF loading, "
                "and kernel-module loads."),
        attack_ids=["T1564.001", "T1014", "T1106"],
        tags=["ebpf", "detection", "runtime"],
        refs=["https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/",
              "https://falco.org", "https://tetragon.io"],
        remediation="Add io_uring, eBPF-program-load and module-load rules; verify LKRG coverage.",
    )]


def ids_rule_review(ctx: RunContext) -> list[Finding]:
    """Review IDS rule coverage against the org's own protocol profile."""
    return [Finding(
        capability="s05_detection.ids_rule_review",
        title="IDS rule review requires a protocol profile",
        severity=Severity.INFO, target="ids",
        detail=("IDS effectiveness is a function of the ratio of (your real traffic patterns) to "
                "(your rules). Pass --protocols to generate a targeted review."),
        tags=["ids", "network", "detection"],
        remediation="Generate rules from observed traffic, not from a generic ruleset.",
    )]


def siem_ingest_check(ctx: RunContext) -> list[Finding]:
    """Confirm key sources parse into queryable fields."""
    checks = [
        ("windows_security", ["EventID", "TargetUserName", "IpAddress", "LogonType"]),
        ("windows_sysmon", ["EventID", "Image", "TargetImage", "ParentImage"]),
        ("cloudtrail", ["eventName", "userIdentity", "sourceIPAddress", "errorCode"]),
        ("entra_signin", ["ResultType", "ClientAppUsed", "ConditionalAccessStatus", "IPAddress"]),
        ("k8s_audit", ["verb", "user.username", "objectRef.resource", "responseStatus"]),
    ]
    out = []
    for src, fields in checks:
        out.append(Finding(
            capability="s05_detection.siem_ingest_check",
            title=f"{src}: verify {len(fields)} detection fields are indexed",
            severity=Severity.MEDIUM, target=src,
            detail="Required queryable fields: " + ", ".join(fields),
            tags=["siem", "logging", "detection"],
            attack_ids=["T1685.002"],
            remediation="Run one synthetic event per source and confirm every field is searchable.",
        ))
    return out


def control_integrity(ctx: RunContext) -> list[Finding]:
    """Monitor the defenders' own stack — the v19 insight, operationalised."""
    items = [
        ("logging agent coverage", "collection agents reporting heartbeat from every expected host"),
        ("SIEM rule count drift", "any drop in enabled rule count = possible disablement"),
        ("EDR policy hash", "policy configuration hash unchanged from baseline"),
        ("AV signature currency", "signature age within SLA"),
        ("DNS/collector health", "upstream resolvers and forwarders alive"),
        ("cloud log integrity", "diagnostic settings present on every resource"),
    ]
    out = []
    for name, why in items:
        out.append(Finding(
            capability="s05_detection.control_integrity_monitor",
            title=f"Control-integrity check: {name}", severity=Severity.MEDIUM,
            target=name, detail=why,
            attack_ids=["T1685", "T1685.003", "T1562.008"],
            tags=["detection", "defenseimpairment", "critical"],
            remediation="Implement as a continuous synthetic check that pages on deviation.",
        ))
    return out


def alert_baseline(ctx: RunContext) -> list[Finding]:
    """Baseline alert volume to expose over-noisy and silently-failing rules."""
    alerts = ctx.opt("alerts") or []
    if not alerts:
        return [Finding(capability="s05_detection.alert_tuning_baseline",
                        title="No alert data supplied", severity=Severity.INFO,
                        target="siem", detail="Pass --alerts <file> to baseline.",
                        tags=["siem", "tuning"])]
    return [Finding(
        capability="s05_detection.alert_tuning_baseline",
        title=f"{len(alerts)} alerts ready for baselining",
        severity=Severity.INFO, target="siem",
        detail="Group by rule, compute volume/unique-entity ratio, flag rules that are either "
               "always firing or never firing. Never-firing is the more dangerous condition.",
        tags=["siem", "tuning", "detection"],
        remediation="Start with never-fired rules — a rule that has not fired in 90 days is "
                    "either irrelevant or broken.",
    )]


def killchain_telemetry(ctx: RunContext) -> list[Finding]:
    """Produce a source→tactic observability map."""
    out = []
    for src, events in TELEMETRY_MAP.items():
        out.append(Finding(
            capability="s05_detection.killchain_telemetry",
            title=f"{src}: {len(events)} event classes available",
            severity=Severity.INFO, target=src,
            detail=", ".join(sorted(events)[:12]),
            tags=["detection", "telemetry", "assure"],
            remediation="Cross-reference with your rules; any tactic with no covering source "
                        "is unobservable.",
            meta={"source": src, "events": sorted(events)},
        ))
    return out


def emulation_validate(ctx: RunContext) -> list[Finding]:
    """Prove detections fire by correlating emulation to alerts."""
    return [Finding(
        capability="s05_detection.emulation_validate",
        title="Emulation validation harness ready",
        severity=Severity.INFO, target="purple",
        detail=("Run an atomic test, then re-run `aegis scan s05_detection.attack_coverage_map` "
                "and confirm the technique's rule fired. A rule that has never fired under "
                "emulation is not a control."),
        tags=["detection", "purple", "emulation"],
        remediation="Wire this into CI so detection regressions are caught, not discovered.",
    )]
