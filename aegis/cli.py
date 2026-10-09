"""AEGIS command-line interface."""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from .core import deps, render
from .core.config import Config
from .core.http import HttpClient
from .core.ledger import Ledger
from .core.models import RunContext, Scope, Severity
from .core.store import Store
from .core.util import colour, pmap, stamp, write_text

BANNER = r"""
   _    ___  ____  ___ _   _   ___
  /_\  | _ \/ ___|/ _ \ | | | / __|
 / _ \ |   / (_) | (_) || |_| \__ \
/_/ \_\|_|_\____/\___/ \___/|___/
      Automated Exposure · Gap · Intelligence Suite
"""


# ══════════════════════════════════════════════════════════════════ helpers
def _scope_from(args: argparse.Namespace) -> Scope:
    s = Scope()
    s.domains = [d.strip() for d in (args.domain or "").split(",") if d.strip()]
    s.hosts = [h.strip() for h in (args.host or "").split(",") if h.strip()]
    s.cidrs = [c.strip() for c in (args.cidr or "").split(",") if c.strip()]
    s.repos = [r.strip() for r in (args.repo or "").split(",") if r.strip()]
    s.cloud = [c.strip() for c in (args.cloud or "").split(",") if c.strip()]
    s.authorised_by = args.authorised_by or ""
    s.reference = args.reference or ""
    s.expires = args.expires or ""
    s.allow_active = bool(args.active)
    return s


def _split_opts(pairs: list[str] | None) -> dict[str, Any]:
    """Parse repeated --opt key=value into a typed dict."""
    out: dict[str, Any] = {}
    for p in (pairs or []):
        k, _, v = p.partition("=")
        k = k.strip()
        if not k:
            continue
        v = v.strip()
        if v.lower() in ("true", "yes", "on"):
            out[k] = True
        elif v.lower() in ("false", "no", "off"):
            out[k] = False
        elif "," in v:
            out[k] = [x.strip() for x in v.split(",") if x.strip()]
        elif v.startswith(("{", "[")):
            try:
                out[k] = json.loads(v)
            except Exception:
                out[k] = v
        elif v.isdigit():
            out[k] = int(v)
        elif re_float(v):
            out[k] = float(v)
        else:
            out[k] = v
    return out


def re_float(v: str) -> bool:
    try:
        float(v)
        return True
    except Exception:
        return False


def _ctx(args: argparse.Namespace, cfg: Config, ledger: Ledger) -> RunContext:
    scope = _scope_from(args)
    store = Store(cfg.data / "aegis.db")
    run_id = args.run_id or stamp()
    wd = Path(args.workdir) if args.workdir else (cfg.runs / run_id)
    wd.mkdir(parents=True, exist_ok=True)

    # Active is the default. `--passive` is the opt-in for quiet mode.
    if getattr(args, "passive", False):
        active = False
    elif getattr(args, "active", False):
        active = True
    else:
        active = bool(cfg.allow_active_by_default)

    http = HttpClient(cfg, scope, cache_dir=cfg.cache,
                      enforce_scope=bool(cfg.guardrails.get("block_nonlocal_targets")))
    providers = {c.id: p for c, p in ledger.active_plan()}
    ctx = RunContext(scope=scope, profile=args.profile, active=active, run_id=run_id,
                     workdir=wd, config=cfg, http=http, store=store,
                     opts=_split_opts(args.opt))
    ctx.opts["_providers"] = providers

    # Enforcement is opt-in. When off, out-of-scope work is noted, not blocked.
    gr = cfg.guardrails or {}
    if active and scope.is_empty():
        if gr.get("require_scope_for_active"):
            print(colour("  require_scope_for_active is enabled and no scope was given "
                         "(--domain/--host/--cidr/--repo)\n", "red"))
            raise SystemExit(2)
        ctx.note("no scope declared — targets are unrestricted for this run")
    if gr.get("require_authorisation_record") and not (scope.authorised_by and scope.reference):
        print(colour("  require_authorisation_record is enabled "
                     "(need --authorised-by and --reference)\n", "red"))
        raise SystemExit(2)
    return ctx


def _load_handler(ref: str):
    mod_path, _, fn = ref.partition(":")
    mod = importlib.import_module(mod_path)
    return getattr(mod, fn)


# ══════════════════════════════════════════════════════════════════ commands
def cmd_doctor(args: argparse.Namespace, cfg: Config) -> int:
    led = Ledger.build(cfg)
    print(colour(BANNER, "cyan"))
    print("  ENVIRONMENT")
    print(f"    python        {sys.version.split()[0]}")
    print(f"    config home   {cfg.home}")
    print(f"    docker        {'available' if _docker() else 'NOT available'}")
    print(f"    parallel      {cfg.parallel}   timeout {cfg.timeout}s   rate {cfg.rate_limit}/s")

    # Dependency availability is probed via aegis.core.deps, which maps
    # distribution names to the module names they actually install. The previous
    # inline probe imported distribution names and reported dnspython:missing for
    # a package that was installed and importable as `dns`.
    probes = deps.probe_all()
    cells = []
    for r in probes:
        label = r.dependency.distribution
        if r.available:
            cells.append(f"{label}:ok({r.version})" if r.version else f"{label}:ok")
        else:
            cells.append(f"{label}:missing")
    print("    deps          " + "  ".join(cells))
    if args.verbose:
        for r in probes:
            kind = "required" if r.dependency.required else "optional"
            state = "ok" if r.available else "MISSING"
            print(f"      [{state:>7}] {r.dependency.distribution:<10} {kind:<8} "
                  f"imports={','.join(r.dependency.imports)}")
            if r.dependency.provides:
                print(f"                provides: {r.dependency.provides}")
            if not r.available and r.import_error:
                detail = r.import_error if not r.distribution_installed else \
                    f"{r.import_error} (distribution IS installed - module broken)"
                print(f"                error: {detail}")
    missing_req = [r for r in probes if r.dependency.required and not r.available]
    if missing_req:
        print(colour(f"    {len(missing_req)} REQUIRED dependency/dependencies missing: "
                     + ", ".join(r.dependency.distribution for r in missing_req), "red"))
    print()
    print(render.console_coverage(led, show_providers=args.verbose))
    return 0 if (led.complete() and not missing_req) else 1


def _docker() -> bool:
    from .core.runner import docker_available
    return docker_available()


def cmd_coverage(args: argparse.Namespace, cfg: Config) -> int:
    led = Ledger.build(cfg)
    if args.json:
        print(render.to_json(led.to_dict(include_gaps=not args.no_gaps)))
        return 0 if led.complete() or args.no_gaps else 1
    print(colour(BANNER, "cyan"))
    print(render.console_coverage(led, show_providers=args.verbose))
    if args.domain:
        for dom, entries in sorted(led.by_domain().items()):
            if args.domain not in dom:
                continue
            print(colour(f"  {dom}", "bold"))
            for e in entries:
                mark = {"covered": colour("ok  ", "green"),
                        "degraded": colour("gap ", "yellow"),
                        "manual": colour("man ", "mag"),
                        "uncovered": colour("GAP ", "red")}[e.coverage.value]
                best = e.best
                via = (f"{best.provider.kind.value}:{best.resolved_ref[:44]}" if best
                       else (e.providers[0].reason[:60] if e.providers else "no provider"))
                print(f"    {mark} {e.capability.id:<28} {via}")
            print()
    if cfg.data and not args.no_record:
        st = Store(cfg.data / "aegis.db")
        st.record_coverage(led.coverage_pct(), len(led.entries),
                           led.counts()["covered"],
                           [g.to_dict() for g in led.gaps()])
        st.close()
    if led.complete():
        dead = led.dead_natives()
        if dead:
            print(colour(f"  {len(dead)} dead native handler(s) — coverage is 100% but this "
                         "code never runs.\n", "yellow", "bold"))
            return 2
        print(colour("  LEDGER COMPLETE — no gaps, no dead handlers.\n", "green", "bold"))
        return 0
    hard = len(led.hard_gaps())
    print(colour(f"  {len(led.gaps())} gap(s) outstanding, {hard} of them design gaps.\n",
                 "yellow", "bold"))
    return 1


def cmd_catalog(args: argparse.Namespace, cfg: Config) -> int:
    led = Ledger.build(cfg)
    if args.json:
        print(render.to_json([e.to_dict() for e in led.entries]))
        return 0
    for dom, entries in sorted(led.by_domain().items()):
        if args.domain and args.domain not in dom:
            continue
        print(colour(f"\n  {dom}", "bold", "cyan"))
        for e in entries:
            best = e.best
            tag = colour("OK ", "green") if best else colour(
                {"degraded": "GAP", "manual": "MAN", "uncovered": "GAP!"}.get(e.coverage.value, "?"),
                {"degraded": "yellow", "manual": "mag", "uncovered": "red"}.get(e.coverage.value, "grey"))
            print(f"    {tag} {e.capability.id:<30} {e.capability.title[:56]}")
            if args.verbose:
                for p in e.providers:
                    st = colour("✓", "green") if p.runnable else colour("·", "grey")
                    print(f"        {st} {p.provider.kind.value:<7} {p.provider.ref[:50]}"
                          + (f"  — {p.reason}" if not p.runnable and p.reason else ""))
                if e.capability.attack_ids:
                    print(colour(f"        attack: {', '.join(e.capability.attack_ids)}", "grey"))
    return 0


def cmd_install(args: argparse.Namespace, cfg: Config) -> int:
    led = Ledger.build(cfg)
    e = led.get(args.capability)
    if not e:
        print(colour(f"  unknown capability: {args.capability}", "red"))
        return 2
    print(colour(f"  {e.capability.key} — {e.capability.title}", "bold"))
    installed = False
    for p in e.providers:
        st = colour("runnable", "green") if p.runnable else colour("blocked ", "yellow")
        print(f"    [{st}] {p.provider.kind.value:<7} {p.provider.ref}")
        if p.provider.install:
            print(colour(f"            install: {p.provider.install}", "grey"))
        if p.reason and not p.runnable:
            print(colour(f"            reason : {p.reason}", "grey"))
        if p.runnable and p.provider.kind.value in ("docker", "local"):
            installed = True
    if args.run and installed and e.best:
        kind = e.best.provider.kind.value
        if kind == "docker":
            print(colour(f"  pulling {e.best.provider.ref} ...", "cyan"))
            ok = _pull(e.best.provider.ref)
            print(colour("  pulled" if ok else "  pull failed", "green" if ok else "red"))
            return 0 if ok else 1
        if kind == "local" and e.best.provider.install:
            print(colour(f"  run: {e.best.provider.install}", "yellow"))
            return 3
    return 0 if installed else 1


def _pull(ref: str) -> bool:
    from .core.util import run
    rc, _, _ = run(["docker", "pull", "-q", ref], timeout=900)
    return rc == 0


def cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    led = Ledger.build(cfg)
    ctx = _ctx(args, cfg, led)
    t0 = time.time()

    if args.suite in ("all", "*"):
        plan = led.active_plan()
        # Passive mode: drop capabilities that would send packets to a target.
        if not ctx.active:
            plan = [(c, p) for c, p in plan if not c.default_active]
    else:
        wanted = [s.strip() for s in args.suite.split(",")]
        plan = []
        for c, p in led.active_plan():
            if c.id in wanted or c.domain.value in wanted or c.key in wanted:
                plan.append((c, p))

    if not plan:
        print(colour("  nothing runnable for that selection.\n", "yellow"))
        _print_gaps(led, args)
        return 1

    ctx.store.start_run(ctx.run_id, ctx.profile, ctx.active, args.suite,
                        (ctx.scope.domains + ctx.scope.hosts + ctx.scope.cidrs) or ["local"],
                        provider="aegis")
    print(colour(f"  run {ctx.run_id} · {args.suite} · profile {args.profile} · "
                 f"{'ACTIVE' if ctx.active else 'passive'} · {len(plan)} capability/capabilities",
                 "bold"))
    print(colour(f"  workdir {ctx.workdir}\n", "grey"))

    errors: list[tuple[str, str]] = []

    def run_one(item):
        cap, entry = item
        total = 0
        # Only native providers are dispatched to Python handlers. Remote / local /
        # docker providers are invoked by the check itself via
        # ctx.opt("_providers"), because only the check knows the correct argv and
        # scope constraints.
        # A capability may declare several native implementations that each
        # contribute findings, so fan out across all of them.
        if not entry.is_native:
            return (cap.id, 0, None)
        for ref in entry.native_refs:
            try:
                fn = _load_handler(ref)
                res = fn(ctx) or []
                for f in res:
                    if not f.attack_ids:
                        f.attack_ids = cap.attack_ids
                    if not f.suite_run:
                        f.suite_run = ctx.run_id
                ctx.findings.extend(res)
                total += len(res)
            except SystemExit:
                raise
            except BaseException as e:  # noqa: BLE001
                errors.append((f"{cap.id}:{ref.rsplit(':', 1)[-1]}",
                               f"{type(e).__name__}: {e}"))
        return (cap.id, total, None)

    results = pmap(run_one, plan, workers=1)  # sequential: many checks share state
    for cap_id, n, err in results:
        if err:
            print(colour(f"  [ERR ] {cap_id:<34} {err[:70]}", "red"))
        else:
            mark = colour("[ok  ]", "green") if n else colour("[none]", "grey")
            print(f"  {mark} {cap_id:<34} {n} finding(s)")

    # scoring + rollup that depend on the full finding set
    for cid in ("s02_surface.score_exposure", "s09_assure.rollup",
                "s09_assure.evidence_package"):
        cap = next((c for c, _ in plan if c.id == cid), None)
        if cap and cap.domain.value in args.suite if args.suite != "all" else False:
            pass
    if args.suite in ("all", "*", "s02_surface", "s09_assure", "assure", "surface"):
        for cid in ("score_exposure", "rollup"):
            e = led.get(cid)
            if e and e.best:
                try:
                    ctx.findings.extend(_load_handler(e.best.provider.ref)(ctx) or [])
                except BaseException as exc:  # noqa: BLE001
                    ctx.note(f"{cid}: {exc}")

    if args.report:
        _write_reports(ctx)

    elapsed = time.time() - t0

    # Every run persists its findings — persistence must not depend on which
    # suite happened to be selected.
    try:
        new, updated = ctx.store.upsert_findings(ctx.run_id, ctx.findings)
    except Exception as e:  # noqa: BLE001
        new = updated = 0
        ctx.note(f"store: {e}")

    if not args.quiet:
        print(render.console_summary(ctx.findings, elapsed))
    if args.format and args.format != "console":
        print(render.findings_json(ctx.findings))
    ctx.store.finish_run(ctx.run_id, f"{len(ctx.findings)} findings ({new} new), "
                                    f"{len(errors)} errors")
    if args.record_coverage:
        st = Store(cfg.data / "aegis.db")
        st.record_coverage(led.coverage_pct(), len(led.entries), led.counts()["covered"],
                           [g.to_dict() for g in led.gaps()])
    ctx.http.close()
    ctx.store.close()
    print(colour(f"  run_id={ctx.run_id}  findings={len(ctx.findings)}  "
                 f"({new} new / {updated} known)  errors={len(errors)}", "grey"))
    if errors:
        print(colour("  errors:", "red"))
        for cap_id, err in errors[:15]:
            print(colour(f"    {cap_id}: {err[:90]}", "red"))
    return 0 if not errors else 1


def _write_reports(ctx: RunContext) -> None:
    from .core import render
    meta = {"run_id": ctx.run_id, "profile": ctx.profile, "active": ctx.active,
            "authorised_by": ctx.scope.authorised_by, "reference": ctx.scope.reference}
    base = Path(ctx.workdir)
    (base / "report.md").write_text(render.to_markdown(ctx.findings, meta), encoding="utf-8")
    (base / "report.sarif").write_text(render.to_sarif(ctx.findings), encoding="utf-8")
    (base / "report.csv").write_text(render.to_csv(ctx.findings), encoding="utf-8")
    (base / "report.html").write_text(render.to_html(ctx.findings, meta), encoding="utf-8")
    (base / "report.json").write_text(render.findings_json(ctx.findings), encoding="utf-8")
    print(colour(f"  reports written to {base}", "grey"))


def _print_gaps(led: Ledger, args: argparse.Namespace) -> None:
    gaps = led.gaps()
    if not gaps:
        return
    print(colour("  related gaps:", "yellow"))
    for g in gaps[:15]:
        print(colour(f"    {g.key:<32} {g.reason[:60]}", "grey"))
        print(colour(f"        fix: {g.remedy[:90]}", "grey"))


def cmd_report(args: argparse.Namespace, cfg: Config) -> int:
    st = Store(cfg.data / "aegis.db")
    rows = st.findings(run_id=args.run_id, severity=args.severity,
                       capability=args.capability, limit=args.limit)
    from .core.models import Finding
    findings = []
    for r in rows:
        f = Finding(capability=r["capability"], title=r["title"],
                    severity=Severity(r.get("severity", "info")), target=r.get("target", ""),
                    detail=r.get("detail", ""), remediation=r.get("remediation", ""),
                    attack_ids=r.get("attack_ids") or [], tags=r.get("tags") or [],
                    refs=[], confidence=r.get("confidence", "medium"),
                    cwe=r.get("cwe", ""), cvss=r.get("cvss"), suite_run=r.get("run_id", ""))
        f.ts = r.get("last_seen", 0)
        findings.append(f)
    meta = {"run_id": args.run_id or "all", "profile": "-", "active": False}
    if args.format == "md":
        text = render.to_markdown(findings, meta)
    elif args.format == "json":
        text = render.findings_json(findings)
    elif args.format == "sarif":
        text = render.to_sarif(findings)
    elif args.format == "csv":
        text = render.to_csv(findings)
    elif args.format == "html":
        text = render.to_html(findings, meta)
    else:
        print(render.console_findings(findings, f"findings ({len(findings)})", args.limit))
        st.close()
        return 0

    # `--out` was previously honoured for html only, so `--format json --out x.json`
    # silently printed to stdout and wrote nothing. It now applies to every
    # file-producing format. html keeps its report.html default because it is the
    # one format whose output is not meant for a terminal.
    if args.out:
        write_text(Path(args.out), text)
        print(colour(f"  wrote {args.out}", "green"))
    elif args.format == "html":
        write_text(Path("report.html"), text)
        print(colour("  wrote report.html", "green"))
    else:
        print(text)
    st.close()
    return 0


def cmd_baseline(args: argparse.Namespace, cfg: Config) -> int:
    st = Store(cfg.data / "aegis.db")
    if args.action == "set":
        rows = st.findings(limit=100000)
        payload = sorted({r["target"] for r in rows if r.get("target")})
        st.put_baseline(args.name, "targets", payload)
        print(colour(f"  baseline '{args.name}' stored: {len(payload)} targets", "green"))
    else:
        p = st.get_baseline(args.name) or []
        print(render.to_json({"name": args.name, "targets": p}))
    st.close()
    return 0


def cmd_gap(args: argparse.Namespace, cfg: Config) -> int:
    led = Ledger.build(cfg)
    gaps = led.gaps()
    if args.json:
        print(render.to_json([g.to_dict() for g in gaps]))
    else:
        print(colour(f"  {len(gaps)} gap(s)\n", "bold"))
        for g in gaps:
            prio = colour("[HIGH]", "red") if g.priority == "high" else colour("[norm]", "grey")
            print(f"  {prio} {colour(g.key, 'cyan')}")
            print(f"          {g.reason}")
            print(colour(f"          fix: {g.remedy}", "grey"))
    return 1 if gaps else 0


def cmd_inventory(args: argparse.Namespace, cfg: Config) -> int:
    led = Ledger.build(cfg)
    rows = []
    for cap, entry in led.active_plan():
        # entry.resolved is the primary ResolvedProvider; resolved_ref is its
        # field. Reading it off the plan object was the original type mismatch.
        r = entry.resolved
        rows.append({
            "capability": cap.key,
            "title": cap.title,
            "domain": cap.domain.value,
            "phase": cap.phase.value,
            "provider_kind": r.provider.kind.value,
            "provider_ref": r.provider.ref,
            "resolved_ref": r.resolved_ref,
            "runnable": r.runnable,
            "coverage": next((e.coverage.value for e in led.entries
                              if e.capability.key == cap.key), None),
            "default_active": cap.default_active,
            "attack_ids": cap.attack_ids,
            "controls": cap.controls,
            "native_handlers": entry.native_refs,
        })
    print(render.to_json(rows))
    return 0


# ══════════════════════════════════════════════════════════════════ parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis", description="AEGIS — Automated Exposure · Gap · Intelligence Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  aegis doctor                        environment + provider resolution
  aegis coverage --verbose            the gap report (exit 1 while gaps exist)
  aegis gap                           actionable gap list only
  aegis catalog --domain s05          what exists and what runs
  aegis install dependency_vuln --run resolve a capability and install it
  aegis scan s01_recon --domain acme.test
  aegis scan s04_supplychain --repo . --active --report
  aegis scan all --profile deep --active --domain acme.test
  aegis report --format sarif --run-id 20260101-120000
  aegis baseline set prod
""")
    p.add_argument("--config", help="path to config.json")
    p.add_argument("--version", action="version", version="AEGIS 1.0.0")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="environment and provider resolution")
    d.add_argument("-v", "--verbose", action="store_true")
    d.set_defaults(fn=cmd_doctor)

    c = sub.add_parser("coverage", help="the gap report — exits 1 while gaps exist")
    c.add_argument("--json", action="store_true")
    c.add_argument("-v", "--verbose", action="store_true")
    c.add_argument("--domain", help="filter to one suite (s05_detection)")
    c.add_argument("--no-gaps", action="store_true", help="omit the gap list from --json")
    c.add_argument("--no-record", action="store_true")
    c.set_defaults(fn=cmd_coverage)

    g = sub.add_parser("gap", help="actionable gaps only")
    g.add_argument("--json", action="store_true")
    g.set_defaults(fn=cmd_gap)

    k = sub.add_parser("catalog", help="list capabilities and provider resolution")
    k.add_argument("--domain")
    k.add_argument("--json", action="store_true")
    k.add_argument("-v", "--verbose", action="store_true")
    k.set_defaults(fn=cmd_catalog)

    i = sub.add_parser("install", help="resolve a capability and show/install how to enable it")
    i.add_argument("capability")
    i.add_argument("--run", action="store_true", help="actually pull the image")
    i.set_defaults(fn=cmd_install)

    s = sub.add_parser("scan", help="run one or more capabilities")
    s.add_argument("suite", help="capability id, domain (s05_detection), or 'all'")
    s.add_argument("--domain", help="comma-separated domains in scope")
    s.add_argument("--host", help="comma-separated hosts in scope")
    s.add_argument("--cidr", help="comma-separated CIDRs in scope")
    s.add_argument("--repo", help="comma-separated repository roots in scope")
    s.add_argument("--cloud", help="comma-separated cloud accounts in scope")
    s.add_argument("--active", action="store_true",
                   help="explicitly allow active testing (this is already the default)")
    s.add_argument("--passive", action="store_true",
                   help="quiet mode: skip anything that sends packets to a target")
    s.add_argument("--profile", default="quick", choices=["quick", "standard", "deep"])
    s.add_argument("--authorised-by", default="")
    s.add_argument("--reference", default="")
    s.add_argument("--expires", default="")
    s.add_argument("--workdir")
    s.add_argument("--run-id")
    s.add_argument("--opt", action="append",
                   help="capability option key=value (repeatable), e.g. --opt technique=T1689")
    s.add_argument("--format", default="console",
                   choices=["console", "json", "md", "sarif", "csv", "html"])
    s.add_argument("--limit", type=int, default=0)
    s.add_argument("--report", action="store_true", help="write all report formats")
    s.add_argument("--record-coverage", action="store_true")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("report", help="render stored findings")
    r.add_argument("--format", default="console",
                   choices=["console", "json", "md", "sarif", "csv", "html"])
    r.add_argument("--run-id")
    r.add_argument("--severity", choices=[s.value for s in Severity])
    r.add_argument("--capability")
    r.add_argument("--limit", type=int, default=60)
    r.add_argument("--out")
    r.set_defaults(fn=cmd_report)

    b = sub.add_parser("baseline", help="store or show an asset baseline")
    b.add_argument("action", choices=["set", "show"])
    b.add_argument("name", nargs="?", default="default")
    b.set_defaults(fn=cmd_baseline)

    v = sub.add_parser("inventory", help="machine-readable list of runnable capabilities")
    v.set_defaults(fn=cmd_inventory)
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to a legacy code page; force UTF-8 for the box drawing
    # and severity glyphs, and degrade gracefully if the terminal cannot render them.
    for stream in (sys.stdout, sys.stderr):
        # reconfigure exists on TextIOWrapper, not on a plain TextIO or a
        # pytest capture object; absence is normal, not an error.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config.load(args.config)
    try:
        return args.fn(args, cfg)
    except KeyboardInterrupt:
        print(colour("\n  interrupted\n", "yellow"))
        return 130
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001
        if args.cmd in ("scan", "doctor", "coverage", "catalog", "gap", "inventory"):
            import traceback
            if getattr(args, "traceback", False):
                traceback.print_exc()
        print(colour(f"\n  {type(e).__name__}: {e}\n", "red"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
