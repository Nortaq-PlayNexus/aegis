"""S08 · Lab, ranges and adversary emulation.

Lab orchestration, vulnerable-by-design environments, atomic test execution,
purple-team campaign correlation, C2 sanitisation, and the detection test harness.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ..core.models import Evidence, Finding, RunContext, Severity

# Practice targets that are safe by design. Pull-on-demand, disposable.
LABS: dict[str, dict[str, Any]] = {
    "kubernetes-goat": {
        "desc": "Vulnerable-by-design Kubernetes cluster (madhuakula)",
        "image": "madhuakula/kubernetes-goat", "refs": ["https://github.com/madhuakula/kubernetes-goat"],
        "ports": [8001, 8002, 8003],
    },
    "terraformgoat": {
        "desc": "Vulnerable multi-cloud Terraform deployment (HXSecurity)",
        "image": None, "refs": ["https://github.com/HXSecurity/TerraformGoat"],
    },
    "juice-shop": {
        "desc": "OWASP JuiceShop — the reference vulnerable web app",
        "image": "bkimminich/juice-shop", "refs": ["https://github.com/juice-shop/juice-shop"],
        "ports": [3000],
    },
    "dvwa": {
        "desc": "Damn Vulnerable Web App",
        "image": "vulnerableweb/dvwa", "refs": ["https://github.com/digininja/DVWA"],
        "ports": [80],
    },
    "metasploitable": {
        "desc": "Intentionally vulnerable VM image",
        "image": None, "refs": ["https://sourceforge.net/projects/metasploitable/"],
    },
    "vulnapp": {
        "desc": "Generic vulnerable container for tool testing",
        "image": "nicolaka/netshoot", "refs": ["https://github.com/c0d3x/B0at/B10at"],
        "ports": [],
    },
    "aegis-native": {
        "desc": "AEGIS self-contained checks — no container required",
        "image": None, "refs": [],
    },
}

# Atomic test subset that is safe to run on a practice host.
SAFE_ATOMICS = {
    "T1059.001": {"name": "PowerShell", "cmd": "powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwB0AG8A",
                  "desc": "Encoded PowerShell execution."},
    "T1082": {"name": "System Information Discovery", "cmd": "systeminfo",
              "desc": "Host enumeration."},
    "T1057": {"name": "Process Discovery", "cmd": "tasklist",
              "desc": "Process enumeration."},
    "T1083": {"name": "File and Directory Discovery", "cmd": "dir C:\\",
              "desc": "Filesystem enumeration."},
    "T1016": {"name": "System Network Configuration Discovery", "cmd": "ipconfig /all",
              "desc": "Network enumeration."},
    "T1049": {"name": "System Network Connections Discovery", "cmd": "netstat -ano",
              "desc": "Connection enumeration."},
    "T1012": {"name": "Query Registry", "cmd": "reg query HKLM\\SOFTWARE",
             "desc": "Registry enumeration."},
    "T1033": {"name": "System Owner/User Discovery", "cmd": "whoami /all",
              "desc": "Identity enumeration."},
}


# ══════════════════════════════════════════════════════════════════ range
def _docker_ok() -> bool:
    return shutil.which("docker") is not None


def lab_control(ctx: RunContext) -> list[Finding]:
    """Report the state of practice labs and whether they can be started."""
    out = []
    if not _docker_ok():
        out.append(Finding(
            capability="s08_lab.vuln_lab_control", title="Docker unavailable — labs cannot start",
            severity=Severity.MEDIUM, target="docker",
            detail="Lab orchestration depends on Docker or a hypervisor. Neither is available.",
            tags=["lab", "gap"],
            remediation="Install Docker Desktop (WSL2 backend) or VirtualBox/VMware.",
        ))
    for name, spec in LABS.items():
        running = False
        if _docker_ok() and spec.get("image"):
            try:
                p = subprocess.run(["docker", "ps", "--filter", f"ancestor={spec['image']}",
                                    "--format", "{{.Names}}"], capture_output=True, text=True, timeout=20)
                running = bool((p.stdout or "").strip())
            except Exception:
                running = False
        out.append(Finding(
            capability="s08_lab.vuln_lab_control", title=f"Lab: {name}",
            severity=Severity.INFO, target=name,
            detail=(f"{spec['desc']} — {'RUNNING' if running else 'stopped'}"
                    + (f"; ports {spec['ports']}" if spec.get("ports") else "")),
            tags=["lab", "training"],
            refs=spec.get("refs", []),
            remediation="Keep practice environments disposable and network-isolated from "
                        "production and from your corporate network.",
        ))
    return out


def range_orchestrate(ctx: RunContext) -> list[Finding]:
    """Bring up the requested lab(s)."""
    if not _docker_ok():
        return [Finding(capability="s08_lab.range_orchestrate",
                        title="Cannot orchestrate: Docker not available", severity=Severity.MEDIUM,
                        target="docker", detail="Install Docker Desktop.", tags=["lab", "gap"])]
    want = ctx.opt("lab") or "aegis-native"
    if isinstance(want, str):
        want = [w.strip() for w in want.split(",") if w.strip()]
    out = []
    for name in want[:4]:
        spec = LABS.get(name)
        if not spec:
            out.append(Finding(capability="s08_lab.range_orchestrate",
                               title=f"Unknown lab: {name}", severity=Severity.LOW,
                               target=name, detail=f"Known labs: {', '.join(LABS)}",
                               tags=["lab"]))
            continue
        if not spec.get("image"):
            out.append(Finding(
                capability="s08_lab.range_orchestrate", title=f"Lab {name} needs a VM, not a container",
                severity=Severity.INFO, target=name,
                detail=f"{spec['desc']}. Provision per the reference and pass --lab-endpoint.",
                tags=["lab"], refs=spec.get("refs", []),
            ))
            continue
        pname = f"aegis-lab-{name}"
        try:
            subprocess.run(["docker", "rm", "-f", pname], capture_output=True, timeout=30)
            args = ["docker", "run", "-d", "--name", pname]
            for port in spec.get("ports", []):
                args += ["-p", f"{port}:{port}"]
            args += [spec["image"]]
            r = subprocess.run(args, capture_output=True, text=True, timeout=300)
            ok = r.returncode == 0
            out.append(Finding(
                capability="s08_lab.range_orchestrate",
                title=f"Lab {'started' if ok else 'failed to start'}: {name}",
                severity=Severity.OK if ok else Severity.MEDIUM, target=pname,
                detail=("Endpoints: " + ", ".join(f"localhost:{p}" for p in spec["ports"])
                        if ok else (r.stderr or "")[:300]),
                tags=["lab", "emulation"],
                evidence=[Evidence(kind="output", summary="docker run", locator=pname,
                                   excerpt=(r.stdout or r.stderr or "")[:400])],
                remediation="Tear down when finished: `aegis scan s08_lab.lab_lifecycle`",
            ))
        except Exception as e:  # noqa: BLE001
            out.append(Finding(capability="s08_lab.range_orchestrate",
                               title=f"Lab {name}: {type(e).__name__}", severity=Severity.LOW,
                               target=name, detail=str(e)[:200], tags=["lab"]))
    return out


def lab_teardown(ctx: RunContext) -> list[Finding]:
    """Destroy lab containers and verify nothing is left reachable."""
    if not _docker_ok():
        return [Finding(capability="s08_lab.lab_lifecycle", title="No Docker — nothing to tear down",
                        severity=Severity.INFO, target="docker", tags=["lab"])]
    out = []
    try:
        p = subprocess.run(["docker", "ps", "-a", "--filter", "name=aegis-lab-",
                            "--format", "{{.Names}}"], capture_output=True, text=True, timeout=30)
        names = [n for n in (p.stdout or "").splitlines() if n.strip()]
    except Exception:
        names = []
    for n in names:
        subprocess.run(["docker", "rm", "-f", n], capture_output=True, timeout=60)
        out.append(Finding(capability="s08_lab.lab_lifecycle", title=f"Removed: {n}",
                           severity=Severity.INFO, target=n, tags=["lab", "teardown"]))
    if not names:
        out.append(Finding(capability="s08_lab.lab_lifecycle", title="No AEGIS labs running",
                           severity=Severity.OK, target="docker", tags=["lab", "teardown"]))
    return out


# ══════════════════════════════════════════════════════════════════ emulation
def atomic_run(ctx: RunContext) -> list[Finding]:
    """Execute a safe subset of atomic tests and report the observable signal."""
    tid = (ctx.opt("technique") or "").upper()
    if not tid:
        return [Finding(
            capability="s08_lab.atomic_emulation",
            title=f"{len(SAFE_ATOMICS)} safe atomic techniques available",
            severity=Severity.INFO, target="emulation",
            detail=", ".join(sorted(SAFE_ATOMICS)),
            tags=["lab", "emulation", "purple"],
            remediation="Run on an isolated practice host only. Pass --technique T1057 etc.",
        )]
    spec = SAFE_ATOMICS.get(tid)
    if not spec:
        return [Finding(
            capability="s08_lab.atomic_emulation", title=f"{tid} is not in the safe subset",
            severity=Severity.LOW, target=tid,
            detail=("Only non-destructive discovery techniques run automatically. For the rest, "
                    "use Invoke-AtomicRedTeam or Caldera on a disposable range."),
            tags=["lab", "emulation"],
            refs=["https://www.atomicredteam.io"],
        )]
    if not ctx.active:
        return [Finding(
            capability="s08_lab.atomic_emulation", title=f"{tid} ready (skipped in passive mode)",
            severity=Severity.INFO, target=tid, detail=spec["desc"], tags=["lab", "emulation"])]
    try:
        t0 = time.time()
        r = subprocess.run(spec["cmd"], shell=True, capture_output=True, text=True, timeout=60)
        elapsed = time.time() - t0
        outp = (r.stdout or "")[:600]
        ctx.emit(Finding(
            capability="s08_lab.atomic_emulation", title=f"Executed {tid} {spec['name']}",
            severity=Severity.INFO, target=f"local:{tid}",
            detail=f"Command: {spec['cmd']} · rc={r.returncode} · {elapsed:.2f}s",
            attack_ids=[tid], tags=["lab", "emulation", "purple"], confidence="confirmed",
            evidence=[Evidence(kind="output", summary="atomic output", locator="local",
                               excerpt=outp)],
            remediation=("This command should now appear in your telemetry. If it does not, "
                         "you have a detection gap — that is the entire point of running it."),
        ))
        return ctx.findings[-1:]
    except Exception as e:  # noqa: BLE001
        return [Finding(capability="s08_lab.atomic_emulation",
                        title=f"{tid} failed: {type(e).__name__}", severity=Severity.LOW,
                        target=tid, detail=str(e)[:200], tags=["lab"])]


def purple_campaign(ctx: RunContext) -> list[Finding]:
    """Chain safe atomics into a campaign and map each step to a detection check."""
    tids = ctx.opt("campaign") or ["T1082", "T1057", "T1083", "T1016", "T1049"]
    if isinstance(tids, str):
        tids = [t.strip().upper() for t in tids.split(",") if t.strip()]
    runnable = [t for t in tids if t in SAFE_ATOMICS]
    out = [Finding(
        capability="s08_lab.purple_team_runner",
        title=f"Campaign: {len(tids)} technique(s), {len(runnable)} auto-runnable",
        severity=Severity.INFO, target="purple",
        detail="; ".join(f"{t}={SAFE_ATOMICS[t]['name']}" for t in runnable) or
        "None of the requested techniques are in the safe subset.",
        attack_ids=runnable, tags=["lab", "purple", "campaign"],
        remediation="After the campaign, re-run `aegis scan s05_detection.attack_coverage_map` "
                    "and confirm every step produced an alert.",
    )]
    if ctx.active:
        for t in runnable:
            spec = SAFE_ATOMICS[t]
            try:
                subprocess.run(spec["cmd"], shell=True, capture_output=True, timeout=45)
                out.append(Finding(
                    capability="s08_lab.purple_team_runner", title=f"Step executed: {t}",
                    severity=Severity.INFO, target=f"local:{t}", detail=spec["desc"],
                    attack_ids=[t], tags=["purple", "emulation"],
                ))
            except Exception:
                pass
    return out


# ══════════════════════════════════════════════════════════════════ c2 hygiene
_C2_ARTIFACTS = [
    ("malleable profile", re.compile(r"malleable| malleable_instruction", re.I)),
    ("beacon config", re.compile(r"beacon_config|BeaconType|CobaltStrike", re.I)),
    ("empire profile", re.compile(r"EmpireProfile|EmpireAgent|launcher_type", re.I)),
    ("cobalt strike watermark", re.compile(r"[0-9a-f]{16}\.[a-z0-9]{6}\.(?:malleable|beacon)", re.I)),
    ("sliver artifacts", re.compile(r"\.sliver\b|sliverpb", re.I)),
    ("known malleable name", re.compile(r"\b(?:InternetExplorer_download|HTTPS_Beac|raw_uris|stage_uri)\b")),
]
_C2_FILES = re.compile(r"(?i)(malleable|beacon|cobalt|empire|sliver|mythic|havoc|listener|profile|redirector|c2)")


def c2_sanitise(ctx: RunContext) -> list[Finding]:
    """Scrub operator artefacts from test infrastructure so detection isn't contaminated."""
    from ..core.util import read_text, walk_files, write_text
    root = Path(ctx.opt("dir") or ctx.workdir)
    changed = 0
    hits: list[str] = []
    for f in walk_files(root, limit=20_000):
        if not f.is_file() or f.suffix.lower() not in (".json", ".yaml", ".yml", ".ini",
                                                       ".conf", ".cfg", ".txt", ".md", ".py"):
            continue
        body = read_text(f, 1_500_000)
        if not body or not _C2_FILES.search(f.name):
            continue
        orig = body
        for _, rx in _C2_ARTIFACTS:
            body = rx.sub("[redacted-c2-artifact]", body)
        if body != orig:
            write_text(f, body)
            changed += 1
            hits.append(str(f))
    return [Finding(
        capability="s08_lab.c2_sanitise",
        title=f"C2 artefact scrub: {changed} file(s) sanitised",
        severity=Severity.INFO if changed else Severity.OK,
        target=str(root),
        detail=("Files: " + ", ".join(hits[:10])) if hits else
        "No operator C2 artefacts found in the tree.",
        tags=["lab", "opsec", "c2"],
        evidence=[Evidence(kind="file", summary="sanitised", locator=str(root),
                           excerpt="\n".join(hits))],
        remediation="Contaminated test infrastructure produces detections that only work in a lab.",
    )]


# ══════════════════════════════════════════════════════════════════ harness
def detection_harness(ctx: RunContext) -> list[Finding]:
    """Assert that a given event SHOULD produce an alert in your SIEM."""
    tests = ctx.opt("assertions") or []
    if isinstance(tests, str):
        tests = [t.strip() for t in tests.split(",") if t.strip()]
    if not tests:
        return [Finding(
            capability="s08_lab.detection_test_harness",
            title="No detection assertions supplied", severity=Severity.INFO,
            target="harness",
            detail=("Pass --assertions as technique ids, e.g. "
                    "'T1059.001,T1070.001'. The harness reports which have a rule, which have "
                    "a rule that has ever fired, and which have neither."),
            tags=["lab", "detection", "ci"],
            remediation="Three states matter: no rule, rule-never-fired, rule-fired. Only the "
                        "last is a control.",
        )]
    out = []
    for t in tests:
        has_rule = bool(ctx.opt(f"rule_{t}"))
        fired = bool(ctx.opt(f"fired_{t}"))
        sev = Severity.OK if fired else (Severity.MEDIUM if has_rule else Severity.HIGH)
        out.append(Finding(
            capability="s08_lab.detection_test_harness",
            title=f"{t}: {'FIRED' if fired else ('rule exists, never fired' if has_rule else 'NO RULE')}",
            severity=sev, target=t,
            detail=("Detection is proven." if fired else
                    "A rule that has never fired is an assumption, not a control."
                    if has_rule else "No detection rule exists for this technique."),
            attack_ids=[t], tags=["detection", "ci", "harness"],
            remediation="Fix in this order: add the rule, then prove it fires under emulation.",
        ))
    return out


def benchmark(ctx: RunContext) -> list[Finding]:
    """Metrics over the current run: coverage, timing, provider usage."""
    sev_count: dict[str, int] = {}
    for f in ctx.findings:
        sev_count[f.severity.value] = sev_count.get(f.severity.value, 0) + 1
    caps = {f.capability for f in ctx.findings}
    techniques = {a for f in ctx.findings for a in f.attack_ids}
    return [Finding(
        capability="s08_lab.benchmark_run",
        title=f"Benchmark: {len(ctx.findings)} findings across {len(caps)} capabilities",
        severity=Severity.INFO, target="benchmark",
        detail=("; ".join(f"{k}={v}" for k, v in sorted(sev_count.items())) +
                f" · {len(techniques)} distinct ATT&CK techniques represented"),
        tags=["metrics", "assure"],
        meta={"severity": sev_count, "capabilities": sorted(caps),
              "techniques": sorted(techniques), "notes": ctx.notes[:20]},
        remediation="Track these numbers over time. Falling coverage is a leading indicator of "
                    "coverage loss, not a quiet period.",
    )]
