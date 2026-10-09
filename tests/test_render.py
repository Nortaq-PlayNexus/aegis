"""E. Reporting — JSON, SARIF, CSV, Markdown, HTML, and secret redaction."""
from __future__ import annotations

import json

import pytest

from aegis.core import render
from aegis.core.models import Evidence, Finding, Severity
from aegis.core.util import redact, human_bytes, slug


@pytest.fixture
def findings() -> list[Finding]:
    return [
        Finding(capability="s04_supplychain.secret_scan",
                title="AWS access key in app.py", severity=Severity.CRITICAL,
                target="app.py", detail="Key found at line 11",
                remediation="Rotate immediately", attack_ids=["T1552.001"],
                tags=["secrets"], confidence="high", cwe="CWE-798", cvss=9.1,
                evidence=[Evidence(kind="file", summary="aws_access_key",
                                   locator="app.py", excerpt="AKIA****WVB3")]),
        Finding(capability="s05_detection.defense_impairment_gap",
                title="No detection for T1685.001", severity=Severity.HIGH,
                target="ATT&CK:T1685.001", detail="Nothing references the signals",
                remediation="Write a rule", attack_ids=["T1685.001"], tags=["detection"]),
        Finding(capability="s01_recon.http_probe", title="example.com -> HTTP 200",
                severity=Severity.INFO, target="example.com", detail="status=200"),
    ]


# ── JSON ──────────────────────────────────────────────────────────────────────
def test_findings_json_round_trips(findings):
    doc = json.loads(render.findings_json(findings))
    assert len(doc) == 3
    assert doc[0]["severity"] == "critical"


# ── SARIF ─────────────────────────────────────────────────────────────────────
def test_sarif_structure(findings):
    doc = json.loads(render.to_sarif(findings))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "AEGIS"
    assert len(run["results"]) == 3


def test_sarif_maps_severity_to_levels(findings):
    doc = json.loads(render.to_sarif(findings))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert "error" in levels.values()       # critical/high
    assert "note" in levels.values()        # info


def test_sarif_carries_partial_fingerprints(findings):
    doc = json.loads(render.to_sarif(findings))
    for r in doc["runs"][0]["results"]:
        assert r["partialFingerprints"]["aegisFingerprint"]


def test_sarif_preserves_remediation_and_attack_ids(findings):
    doc = json.loads(render.to_sarif(findings))
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["remediation"] == "Rotate immediately"
    assert props["attackIds"] == ["T1552.001"]


def test_sarif_handles_empty():
    doc = json.loads(render.to_sarif([]))
    assert doc["runs"][0]["results"] == []


# ── CSV ───────────────────────────────────────────────────────────────────────
def test_csv_header_and_row_count(findings):
    out = render.to_csv(findings)
    lines = out.strip().splitlines()
    assert lines[0].startswith("fingerprint,severity")
    assert len(lines) == 4  # header + 3


def test_csv_sorted_by_severity(findings):
    lines = render.to_csv(findings).strip().splitlines()[1:]
    sevs = [l.split(",")[1] for l in lines]
    assert sevs[0] == "critical"
    assert sevs[-1] == "info"


# ── Markdown ──────────────────────────────────────────────────────────────────
def test_markdown_has_summary_and_priorities(findings):
    md = render.to_markdown(findings, {"run_id": "R1", "active": False})
    assert "# AEGIS Security Assessment Report" in md
    assert "## Executive summary" in md
    assert "### Top priorities" in md
    assert "R1" in md


def test_markdown_marks_active_testing(findings):
    md = render.to_markdown(findings, {"run_id": "R1", "active": True})
    assert "**Active testing:** YES" in md, (
        "a report must state plainly whether active testing was performed")


def test_markdown_handles_empty():
    md = render.to_markdown([], {"run_id": "R0"})
    assert "Executive summary" in md
    assert "**Total** | **0**" in md


# ── HTML ──────────────────────────────────────────────────────────────────────
def test_html_is_self_contained(findings):
    html = render.to_html(findings, {"run_id": "R1"})
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "AWS access key" in html
    assert "<style>" in html


def test_html_escapes_markup(findings):
    hostile = [Finding(capability="c", title="<script>alert(1)</script>",
                       severity=Severity.HIGH, target="x")]
    html = render.to_html(hostile, {})
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ── redaction ─────────────────────────────────────────────────────────────────
def test_redact_keeps_prefix_and_suffix():
    r = redact("AKIA4T7M2ZK9XQPLWVB3")
    assert r.startswith("AKIA")
    assert r.endswith("WVB3")
    assert "4T7M2ZK9XQPL" not in r


def test_redact_hides_short_values_entirely():
    assert set(redact("abcd")) == {"*"}


def test_redact_empty():
    assert redact("") == ""


# ── small helpers ─────────────────────────────────────────────────────────────
def test_slug():
    assert slug("Hello, World!") == "hello-world"
    assert slug("") == ""
    assert len(slug("x" * 200)) <= 64


def test_human_bytes():
    assert human_bytes(512) == "512B"
    assert human_bytes(2048).endswith("KB")
    assert human_bytes(5 * 1024 * 1024).endswith("MB")


def test_console_summary_reports_totals(findings):
    out = render.console_summary(findings, 1.5)
    assert "total findings" in out
    assert "weighted risk" in out
    assert "3" in out


def test_console_summary_handles_empty():
    out = render.console_summary([], 0.0)
    assert "total findings" in out
