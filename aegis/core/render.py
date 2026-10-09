"""Renderers: console, JSON, SARIF, Markdown, CSV, HTML."""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from typing import Any
from collections.abc import Iterable

from .models import Finding, Severity
from .util import colour, sev_colour, slug, stamp

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
             Severity.LOW, Severity.INFO, Severity.OK]

SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note", Severity.OK: "none"}


# ------------------------------------------------------------------ console
def console_findings(findings: list[Finding], title: str = "", limit: int = 0) -> str:
    out = io.StringIO()
    if title:
        out.write(f"\n{colour(title, 'bold')}\n")
    if not findings:
        out.write(colour("  no findings\n", "green"))
        return out.getvalue()
    ordered = sorted(findings, key=lambda f: -f.severity.rank)
    shown = ordered[:limit] if limit else ordered
    cur_sev = None
    for f in shown:
        if f.severity is not cur_sev:
            cur_sev = f.severity
            out.write(f"\n  {sev_colour(f.severity.value)}\n")
        loc = colour(f.target[:70], "cyan") if f.target else " ".ljust(70)
        out.write(f"    {loc}  {f.title}\n")
        if f.detail:
            d = f.detail.strip().replace("\n", " ")
            out.write(colour(f"      {d[:150]}", "grey") + "\n")
    if limit and len(ordered) > limit:
        out.write(colour(f"\n  … {len(ordered) - limit} more (raise --limit)\n", "grey"))
    return out.getvalue()


def console_summary(findings: list[Finding], elapsed: float = 0.0) -> str:
    out = io.StringIO()
    c = Counter(f.severity for f in findings)
    total = len(findings)
    out.write("\n  " + colour("SEVERITY", "bold") + "\n")
    for s in SEV_ORDER:
        if c.get(s):
            n = c[s]
            bar = "█" * min(40, n)
            out.write(f"    {sev_colour(s.value, s.value.ljust(8))} {n:>5}  {colour(bar, 'grey')}\n")
    risk = round(sum(f.severity.score for f in findings), 1)
    out.write(f"\n    {colour('total findings', 'bold')}: {total}    "
              f"{colour('weighted risk', 'bold')}: {risk}    "
              f"{colour('elapsed', 'bold')}: {elapsed:.1f}s\n")
    return out.getvalue()


def console_coverage(ledger: Any, show_providers: bool = False) -> str:
    out = io.StringIO()
    counts = ledger.counts()
    total = len(ledger.entries)
    pct = ledger.coverage_pct()
    bar_w = 34
    filled = int(bar_w * pct / 100)
    bar = colour("█" * filled, "green") + colour("░" * (bar_w - filled), "grey")
    out.write(f"\n  {colour('COVERAGE', 'bold')}  {bar}  {colour(f'{pct:.1f}%', 'bold', 'green')}\n")
    out.write(colour(
        f"  covered {counts['covered']}  ·  degraded {counts['degraded']}  ·  "
        f"manual {counts['manual']}  ·  UNCOVERED {colour(str(counts['uncovered']), 'red' if counts['uncovered'] else 'grey')}"
        f"   of {total}\n", "grey"))
    out.write("\n")
    for dom, entries in sorted(ledger.by_domain().items()):
        cov = sum(1 for e in entries if e.coverage.value == "covered")
        tot = len(entries)
        label = f"  {dom.replace('s0','S').replace('_',' '):<20}"
        mini = "█" * int(20 * cov / tot) if tot else ""
        flag = "" if cov == tot else colour(f"  ({tot - cov} blocked)", "yellow")
        out.write(f"{label} {colour(mini, 'green')}{' ' * (20 - len(mini))} {cov:>2}/{tot:<2}{flag}\n")
    gaps = ledger.gaps()
    if gaps:
        out.write("\n  " + colour("GAPS", "bold", "red") + f"  ({len(gaps)})\n")
        for g in gaps[:60]:
            prio = colour("!", "red") if g.priority == "high" else " "
            out.write(f"    {prio} {colour(g.key.ljust(30), 'cyan')} {g.reason[:70]}\n")
            if g.remedy:
                out.write(colour(f"        fix: {g.remedy[:100]}", "grey") + "\n")
        if len(gaps) > 60:
            out.write(colour(f"    … {len(gaps) - 60} more gaps\n", "grey"))
    else:
        out.write("\n  " + colour("✓ no gaps — every declared capability has a runnable provider", "green", "bold") + "\n")

    dead = ledger.dead_natives() if hasattr(ledger, "dead_natives") else []
    if dead:
        out.write("\n  " + colour("DEAD NATIVE HANDLERS", "bold", "yellow")
                  + f"  ({len(dead)})  — masked by a working fallback, but never runs\n")
        for d in dead[:30]:
            out.write(colour(f"    {d['capability']:<30} {d['ref']}\n", "grey"))
            out.write(colour(f"        masked_by={d['masked_by']}  {d['reason']}\n", "grey"))
        out.write(colour("  fix the handler name, or delete the provider entry.\n", "grey"))

    if show_providers:
        out.write("\n  " + colour("PROVIDER RESOLUTION", "bold") + "\n")
        for e in ledger.entries:
            best = e.best
            if best:
                out.write(f"    {colour('OK', 'green')}  {e.capability.key.ljust(32)} "
                          f"{colour(best.provider.kind.value.ljust(7), 'grey')} {best.resolved_ref[:60]}\n")
            else:
                rp = e.providers[0] if e.providers else None
                out.write(f"    {colour('--', 'yellow')}  {e.capability.key.ljust(32)} "
                          f"{colour((rp.reason if rp else 'none')[:70], 'grey')}\n")
    out.write("\n")
    return out.getvalue()


# ------------------------------------------------------------------ json
def to_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, default=str)


def findings_json(findings: Iterable[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, default=str)


# ------------------------------------------------------------------ sarif
def to_sarif(findings: list[Finding], tool: str = "AEGIS", version: str = "1.0.0") -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in findings:
        rid = slug(f.capability) or "finding"
        rules.setdefault(rid, {
            "id": rid,
            "name": f.capability,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.detail or f.title},
            "helpUri": f.refs[0] if f.refs else "",
            "properties": {"tags": f.tags, "attackIds": f.attack_ids,
                           "cwe": f.cwe, "severity": f.severity.value},
        })
        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f.detail or f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target or "unknown"},
                    "region": {"startLine": 1},
                }
            }],
            "partialFingerprints": {"aegisFingerprint": f.fingerprint},
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "remediation": f.remediation,
                "attackIds": f.attack_ids,
                "cvss": f.cvss,
            },
        })
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "version": version,
                                "informationUri": "https://github.com/", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, default=str)


# ------------------------------------------------------------------ csv
def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["fingerprint", "severity", "capability", "title", "target",
                "detail", "remediation", "attack_ids", "cwe", "cvss",
                "confidence", "status", "first_seen"])
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        w.writerow([f.fingerprint, f.severity.value, f.capability, f.title, f.target,
                    f.detail.replace("\n", " "), f.remediation,
                    ";".join(f.attack_ids), f.cwe, f.cvss or "", f.confidence,
                    "open", stamp()])
    return buf.getvalue()


# ------------------------------------------------------------------ markdown
def to_markdown(findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    m: list[str] = []
    m.append("# AEGIS Security Assessment Report")
    m.append("")
    m.append(f"**Generated:** {stamp()} UTC  ")
    m.append(f"**Run:** `{meta.get('run_id','-')}`  ·  "
             f"**Profile:** {meta.get('profile','-')}  ·  "
             f"**Active testing:** {'YES' if meta.get('active') else 'no (passive only)'}  ")
    if meta.get("authorised_by"):
        m.append(f"**Authorised by:** {meta['authorised_by']}  ·  **Reference:** {meta.get('reference','-')}")
    m.append("")

    c = Counter(f.severity for f in findings)
    risk = round(sum(f.severity.score for f in findings), 1)
    m.append("## Executive summary")
    m.append("")
    m.append("| Severity | Count |")
    m.append("|---|---:|")
    for s in SEV_ORDER:
        m.append(f"| {s.value.upper()} | {c.get(s,0)} |")
    m.append(f"| **Total** | **{len(findings)}** |")
    m.append("")
    m.append(f"**Weighted risk score:** {risk}  ")
    m.append(f"**Attack techniques represented:** {len({a for f in findings for a in f.attack_ids})}")
    m.append("")

    top = sorted(findings, key=lambda f: -f.severity.score)[:10]
    if top:
        m.append("### Top priorities")
        m.append("")
        for i, f in enumerate(top, 1):
            m.append(f"{i}. **[{f.severity.value.upper()}]** {f.title} — `{f.target or 'n/a'}`")
            if f.attack_ids:
                m.append(f"   - ATT&CK: {', '.join(f.attack_ids)}")
        m.append("")

    m.append("## Findings")
    m.append("")
    by_cap: dict[str, list[Finding]] = {}
    for f in findings:
        by_cap.setdefault(f.capability, []).append(f)
    for cap, fs in sorted(by_cap.items(), key=lambda kv: -max(f.severity.score for f in kv[1])):
        m.append(f"### {cap}")
        m.append("")
        for f in sorted(fs, key=lambda x: -x.severity.rank):
            m.append(f"#### [{f.severity.value.upper()}] {f.title}")
            m.append("")
            m.append(f"- **Target:** `{f.target or 'n/a'}`")
            if f.attack_ids:
                m.append(f"- **ATT&CK:** {', '.join(f.attack_ids)}")
            if f.cwe:
                m.append(f"- **CWE:** {f.cwe}")
            if f.cvss:
                m.append(f"- **CVSS:** {f.cvss}")
            m.append(f"- **Confidence:** {f.confidence}")
            m.append(f"- **Fingerprint:** `{f.fingerprint}`")
            m.append("")
            if f.detail:
                m.append(f"{f.detail}")
                m.append("")
            for e in f.evidence[:6]:
                m.append(f"- Evidence ({e.kind}): {e.summary}"
                         + (f" — `{e.locator}`" if e.locator else ""))
            if f.evidence:
                m.append("")
            if f.remediation:
                m.append(f"**Remediation:** {f.remediation}")
                m.append("")
            if f.refs:
                m.append("**References:** " + " · ".join(f.refs))
                m.append("")

    m.append("---")
    m.append("")
    m.append("Generated by AEGIS. Findings are for systems you own or are authorised to assess.")
    return "\n".join(m)


# ------------------------------------------------------------------ html
_CSS = """
:root{--bg:#07090f;--card:#111725;--line:#1e2942;--tx:#e6edf9;--tx2:#93a6c6;--tx3:#61748f;
--c:#ff5c7a;--h:#ff8c42;--m:#ffb020;--l:#3ba3ff;--i:#61748f;--ok:#39d98a}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--tx);font:15px/1.6 "Segoe UI",system-ui,sans-serif;padding:32px}
h1{font-size:26px;margin-bottom:4px}h2{margin:28px 0 10px;font-size:19px}
.sub{color:var(--tx3);font-size:13px;margin-bottom:22px}
table{width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--tx3);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.crit{color:var(--c);font-weight:700}.high{color:var(--h);font-weight:700}
.med{color:var(--m);font-weight:600}.low{color:var(--l)}.info{color:var(--i)}.ok{color:var(--ok)}
.badge{display:inline-block;padding:2px 8px;border-radius:5px;font-size:10.5px;font-weight:700;letter-spacing:.04em}
.b-crit{background:rgba(255,92,122,.15);color:var(--c)}
.b-high{background:rgba(255,140,66,.15);color:var(--h)}
.b-med{background:rgba(255,176,32,.15);color:var(--m)}
.b-low{background:rgba(59,163,255,.15);color:var(--l)}
.b-info{background:rgba(97,116,143,.15);color:var(--i)}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px;background:#0d1420;padding:1px 5px;border-radius:4px}
a{color:var(--l)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card b{display:block;font-size:26px}.card span{font-size:11px;color:var(--tx3);text-transform:uppercase;letter-spacing:.08em}
.remed{color:var(--ok);font-size:12.5px;margin-top:6px}
.foot{color:var(--tx3);font-size:12px;margin-top:34px;border-top:1px solid var(--line);padding-top:16px}
"""


def to_html(findings: list[Finding], meta: dict[str, Any] | None = None) -> str:
    meta = meta or {}
    c = Counter(f.severity for f in findings)
    risk = round(sum(f.severity.score for f in findings), 1)
    h: list[str] = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
                   f"<title>AEGIS report {meta.get('run_id','')}</title>",
                   f"<style>{_CSS}</style></head><body>"]
    h.append("<h1>AEGIS Security Assessment</h1>")
    h.append(f"<div class='sub'>Run <code>{meta.get('run_id','-')}</code> · {stamp()} UTC · "
             f"profile {meta.get('profile','-')} · "
             f"{'<b style=color:#ff5c7a>ACTIVE</b>' if meta.get('active') else 'passive only'}</div>")
    h.append("<div class='cards'>")
    for s in SEV_ORDER:
        h.append(f"<div class='card'><b class='{s.value}'>{c.get(s,0)}</b><span>{s.value}</span></div>")
    h.append(f"<div class='card'><b>{risk}</b><span>risk</span></div>")
    h.append(f"<div class='card'><b>{len({a for f in findings for a in f.attack_ids})}</b><span>techniques</span></div>")
    h.append("</div>")
    h.append("<table><tr><th>Severity</th><th>Finding</th><th>Target</th><th>ATT&CK</th><th>Remediation</th></tr>")
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        h.append(f"<tr><td><span class='badge b-{f.severity.value}'>{f.severity.value.upper()}</span></td>"
                 f"<td><b>{_esc(f.title)}</b><br><span style='color:#93a6c6;font-size:12px'>{_esc(f.detail[:220])}</span></td>"
                 f"<td><code>{_esc((f.target or 'n/a')[:44])}</code></td>"
                 f"<td><code>{_esc(','.join(f.attack_ids[:3]))}</code></td>"
                 f"<td class='remed'>{_esc(f.remediation[:160])}</td></tr>")
    h.append("</table>")
    h.append(f"<div class='foot'>Generated by AEGIS · authorised use only · "
             f"{len(findings)} findings · fingerprints enable dedup across runs</div>")
    h.append("</body></html>")
    return "".join(h)


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
