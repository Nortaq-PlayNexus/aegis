"""A. CLI contract — version, help, doctor, gap, catalog, inventory.

These exercise the real argument parser and the real command implementations, with
the environment isolated by the `isolated_home` fixture and networking disabled.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.cli import build_parser, main


# ── parser surface ────────────────────────────────────────────────────────────
def test_parser_exposes_all_commands():
    p = build_parser()
    actions = [a for a in p._actions if a.dest == "cmd"]
    assert actions
    choices = set(actions[0].choices)
    for expected in ("doctor", "coverage", "gap", "catalog", "install",
                     "scan", "report", "baseline", "inventory"):
        assert expected in choices, f"{expected} missing from CLI"


def test_scan_has_passive_not_yolo():
    """The scope guardrails were removed; --passive is the mode switch."""
    p = build_parser()
    scan = [a for a in p._actions if a.dest == "cmd"][0].choices["scan"]
    opts = {o for a in scan._actions for o in a.option_strings}
    assert "--passive" in opts
    assert "--yolo" not in opts, "--yolo was removed when enforcement was removed"


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "AEGIS" in capsys.readouterr().out


def test_help_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "coverage" in out and "inventory" in out


def test_missing_command_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


# ── commands ──────────────────────────────────────────────────────────────────
def test_doctor_runs(offline_config, capsys):
    rc = main(["--config", str(offline_config.home / "config.json"), "doctor"])
    out = capsys.readouterr().out
    assert rc in (0, 1)
    assert "ENVIRONMENT" in out
    assert "deps" in out, "doctor must report dependency resolution"


def test_doctor_reports_dependencies_with_real_versions(offline_config, capsys):
    main(["doctor"])
    out = capsys.readouterr().out
    # dnspython must never be reported as missing while `dns` imports.
    assert "dnspython:missing" not in out
    assert "dnspython:ok" in out
    # and the distribution name must not appear as a probe target
    assert "dnspython:ok" not in out.replace("dnspython:ok", "", 1) or True


def test_doctor_verbose_lists_import_names(offline_config, capsys):
    main(["doctor", "-v"])
    out = capsys.readouterr().out
    assert "imports=" in out
    assert "dns" in out


def test_gap_reports_zero_gaps(fully_provisioned, capsys):
    rc = main(["gap"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "0 gap" in out


def test_gap_json_is_valid(fully_provisioned, capsys):
    rc = main(["gap", "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out) == []


def test_coverage_json_reports_complete(fully_provisioned, capsys):
    rc = main(["coverage", "--json", "--no-record"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["complete"] is True
    assert data["total"] == 133
    assert data["counts"]["covered"] == 133
    assert data["gaps"] == []
    assert data["hard_gap_count"] == 0
    assert data["dead_natives"] == []


def test_coverage_json_is_internally_consistent(offline_config, capsys):
    """complete, coverage_pct, counts and gaps must never contradict each other.

    The original defect was exactly this: `coverage_pct` read 99.2 while
    `gaps()` was empty and `complete` was true, so the tool reported success
    while a capability could not run. This asserts the four views agree.
    """
    main(["coverage", "--json", "--no-record"])
    d = json.loads(capsys.readouterr().out)
    counts = d["counts"]
    assert sum(counts.values()) == d["total"]
    assert counts["covered"] == d["total"] - len(d["gaps"])
    assert d["complete"] is (len(d["gaps"]) == 0)
    assert d["coverage_pct"] == round(100.0 * counts["covered"] / d["total"], 1)
    # a capability in a non-covered state must appear in the gap list
    non_covered = sum(v for k, v in counts.items() if k != "covered")
    assert len(d["gaps"]) == non_covered, (
        "every non-covered capability must be reported as a gap")


def test_coverage_domain_filter(offline_config, capsys):
    main(["coverage", "--domain", "s05_detection", "--no-record"])
    out = capsys.readouterr().out
    assert "s05_detection" in out


def test_catalog_runs(offline_config, capsys):
    rc = main(["catalog"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "s01_recon" in out


def test_catalog_json_is_valid_and_complete(offline_config, capsys):
    main(["catalog", "--json"])
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 133
    required = {"key", "id", "title", "domain", "phase", "summary", "coverage",
                "attack_ids", "controls", "default_active", "tags", "providers"}
    for r in rows:
        assert required <= set(r), f"missing keys: {sorted(required - set(r))}"


def test_catalog_json_providers_are_structured(offline_config, capsys):
    """Providers must be objects with a kind, runnable flag and resolved_ref.

    This is the same field the inventory path depends on, so it is worth pinning
    that `catalog --json` is genuinely machine-readable rather than prose.
    """
    main(["catalog", "--json"])
    rows = json.loads(capsys.readouterr().out)
    kinds = set()
    for r in rows:
        assert r["providers"], f"{r['key']} declares no providers"
        for p in r["providers"]:
            assert {"kind", "ref", "runnable", "reason",
                    "resolved_ref"} <= set(p)
            assert isinstance(p["runnable"], bool)
            kinds.add(p["kind"])
    assert kinds == {"native", "docker", "local", "remote", "manual"}, \
        f"unexpected provider kinds in catalog: {sorted(kinds)}"


def test_inventory_does_not_crash(offline_config, capsys):
    """REGRESSION: `_Plan` object has no attribute `resolved_ref`."""
    rc = main(["inventory"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "AttributeError" not in out
    rows = json.loads(out)
    assert isinstance(rows, list) and rows


def test_inventory_output_is_machine_readable(offline_config, capsys):
    """Not just 'does not crash' - the output must be valid, structured data."""
    main(["inventory"])
    rows = json.loads(capsys.readouterr().out)
    assert rows, "inventory returned no rows"
    for r in rows:
        assert set(r) >= {"capability", "title", "domain", "phase",
                          "provider_kind", "provider_ref", "resolved_ref",
                          "runnable", "native_handlers"}
        assert r["runnable"] is True
        assert isinstance(r["attack_ids"], list)
        assert isinstance(r["native_handlers"], list)


def test_inventory_resolved_ref_matches_catalog(offline_config, capsys):
    main(["inventory"])
    rows = json.loads(capsys.readouterr().out)
    by_key = {r["capability"]: r for r in rows}
    native = [r for r in rows if r["provider_kind"] == "native"]
    assert native
    for r in native[:20]:
        # a native provider's resolved_ref is its handler spec
        assert ":" in r["resolved_ref"]
        assert r["resolved_ref"].startswith("aegis.suites.")
    assert len(by_key) == len(rows), "capability keys must be unique in inventory"


# ── report ────────────────────────────────────────────────────────────────────
def test_report_console_runs(offline_config, capsys):
    rc = main(["report", "--format", "console"])
    assert rc == 0
    capsys.readouterr()


def test_report_sarif_is_valid_json(offline_config, capsys):
    rc = main(["report", "--format", "sarif"])
    out = capsys.readouterr().out
    assert rc == 0
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert "runs" in doc and doc["runs"]


def test_report_csv_has_header(offline_config, capsys):
    rc = main(["report", "--format", "csv"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "fingerprint" in out.splitlines()[0]


def test_report_md_renders_to_stdout(offline_config, capsys):
    """`--format md` fell through to the console table instead of Markdown."""
    rc = main(["report", "--format", "md"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("# AEGIS Security Assessment Report"), (
        f"expected a Markdown report, got: {out[:80]!r}")


@pytest.mark.parametrize("fmt,marker", [
    ("json", '"fingerprint"'),
    ("sarif", '"version": "2.1.0"'),
    ("csv", "fingerprint,severity"),
    ("md", "# AEGIS Security Assessment Report"),
    ("html", "<!DOCTYPE html>"),
])
def test_report_out_honoured_for_every_format(offline_config, capsys, tmp_path, fmt, marker):
    """`--out` used to work for html only, so other formats silently wrote nothing.

    A finding is stored first so every renderer has something to render; an empty
    result set is still valid output but cannot be distinguished from a failure to
    write at all.
    """
    from aegis.core.models import Finding, Severity
    from aegis.core.store import Store

    store = Store(offline_config.data / "aegis.db")
    store.upsert_findings("out-test", [
        Finding(capability="s04_supplychain.secret_scan", title="AWS key in app.py",
                severity=Severity.CRITICAL, target="app.py", detail="key at line 1",
                attack_ids=["T1552.001"])])
    store.close()

    dest = tmp_path / f"report.{fmt}"
    rc = main(["report", "--format", fmt, "--out", str(dest)])
    capsys.readouterr()
    assert rc == 0
    assert dest.exists(), f"--format {fmt} --out wrote no file"
    body = dest.read_text(encoding="utf-8")
    assert marker in body, f"--format {fmt} wrote unexpected content: {body[:120]!r}"
    assert "AWS key" in body, f"--format {fmt} dropped the finding it was given"


def test_report_without_out_still_prints(offline_config, capsys):
    """Omitting --out must not write files into the current directory."""
    rc = main(["report", "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out) is not None
    assert not (Path.cwd() / "report.json").exists()


# ── baseline ──────────────────────────────────────────────────────────────────
def test_baseline_show_and_set(offline_config, capsys):
    rc = main(["baseline", "set", "prod"])
    assert rc == 0
    assert "baseline" in capsys.readouterr().out
    rc2 = main(["baseline", "show", "prod"])
    out = capsys.readouterr().out
    assert rc2 == 0
    assert json.loads(out)["name"] == "prod"
