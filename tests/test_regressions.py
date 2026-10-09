"""F. Regression tests — one per defect found in the audit.

Each test here failed before the remediation and must keep failing if the
underlying mistake is reintroduced.
"""
from __future__ import annotations

import json

import pytest

from aegis.core import deps
from aegis.core.catalog import CATALOG
from aegis.core.ledger import Ledger, PlanEntry
from aegis.core.models import Provider, ProviderKind, ResolvedCapability


# ═══════════════════════════════════════════════════════ 1. inventory crash
def test_plan_entry_exposes_resolved_provider_not_a_bare_provider(offline_config):
    """`cmd_inventory` read `rp.resolved_ref` off the plan object.

    The old nested `_Plan` class only carried `.provider` (a `Provider`, which has
    no `resolved_ref`) and `.rps`. The fix is a typed `PlanEntry` whose `.resolved`
    returns the real `ResolvedProvider` — not a duplicated dummy field.
    """
    led = Ledger.build(offline_config)
    cap, entry = led.active_plan()[0]
    # this is what crashed with AttributeError
    assert entry.resolved.resolved_ref == entry.resolved.resolved_ref
    assert entry.resolved.runnable is True
    # and it must be the same object as the ledger's, not a copy that could drift
    assert entry.resolved is led.get(cap.id).best


def test_plan_entry_resolved_ref_is_populated_for_every_capability(offline_config):
    """Every capability the inventory reports must carry a real resolved_ref.

    This is the assertion that would have caught the original crash: `inventory`
    reads this field for all 133 rows, so an empty one anywhere is a latent bug.
    """
    led = Ledger.build(offline_config)
    for cap, entry in led.active_plan():
        assert entry.resolved.resolved_ref, f"{cap.key} resolved to an empty ref"


def test_resolved_ref_is_not_a_field_on_provider_itself():
    """Guard against 'fixing' it by bolting a resolved_ref onto Provider."""
    p = Provider(kind=ProviderKind.NATIVE, ref="aegis.suites.s01_recon:check_dns")
    assert not hasattr(p, "resolved_ref"), (
        "resolved_ref belongs to ResolvedProvider; adding it to Provider would "
        "hide the type mismatch rather than fix it")


def test_inventory_command_runs_end_to_end(offline_config, capsys):
    from aegis.cli import main
    rc = main(["inventory"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "AttributeError" not in out
    rows = json.loads(out)
    assert all("resolved_ref" in r for r in rows)


def test_active_plan_consumers_agree_on_the_type(offline_config):
    """Everything handed out by active_plan must expose the same accessor."""
    led = Ledger.build(offline_config)
    for _cap, entry in led.active_plan():
        assert isinstance(entry, PlanEntry)
        assert hasattr(entry, "resolved")
        assert hasattr(entry, "native_refs")
        assert hasattr(entry, "is_native")


# ═══════════════════════════════════════════════════════ 2. dnspython false neg
def test_dnspython_is_reported_available_when_dns_imports():
    """The original probe imported `dnspython`, which is not a module."""
    r = deps.probe(deps.by_distribution("dnspython"))
    import importlib
    try:
        importlib.import_module("dns")
        dns_importable = True
    except Exception:  # noqa: BLE001
        dns_importable = False
    if dns_importable:
        assert r.available is True, (
            "dns imports but dnspython probes as missing — the distribution name "
            "is being used as the import name")
        assert r.version


def test_doctor_output_never_contains_dnspython_missing(monkeypatch, capsys):
    from aegis.cli import main
    import importlib
    try:
        importlib.import_module("dns")
    except Exception:  # noqa: BLE001
        pytest.skip("dns is not importable in this environment")
    main(["doctor"])
    out = capsys.readouterr().out
    assert "dnspython:missing" not in out


def test_dependency_table_is_actually_used_by_doctor():
    """doctor must not reintroduce a hard-coded module list."""
    from pathlib import Path
    src = Path("aegis/cli.py").read_text(encoding="utf-8")
    assert "deps.probe_all()" in src
    # the old hard-coded tuple of module names must be gone
    assert '"dnspython", "dns"' not in src
    assert "dnspython:ok" not in src, "do not hard-code a green dependency"


# ═══════════════════════════════════════════════════════ 3. dead native handlers
def test_every_declared_native_handler_name_matches_a_real_function(offline_config):
    """Catches a catalog handler-name typo that a fallback provider would mask.

    This is the defect class that produced `check_historical` vs `check_history`:
    the capability still resolved through a remote provider, so coverage stayed
    100% and the broken native handler was invisible until `dead_natives()` was
    added. Checking the declared name resolves statically, without a ledger.
    """
    import importlib
    broken = []
    for cap in CATALOG:
        for p in cap.providers:          # p is a Provider, not a ResolvedProvider
            if p.kind is not ProviderKind.NATIVE:
                continue
            mod_path, _, fn = p.ref.partition(":")
            if not mod_path or not fn:
                broken.append(f"{p.ref} (malformed native ref, expected 'module:function')")
                continue
            try:
                mod = importlib.import_module(mod_path)
            except Exception as e:  # noqa: BLE001
                broken.append(f"{p.ref} (module: {e})")
                continue
            if not callable(getattr(mod, fn, None)):
                broken.append(f"{p.ref} (no callable '{fn}' in {mod_path})")
    assert not broken, "catalog references handlers that do not exist: " + \
                       "; ".join(broken)


def test_dead_natives_detection_works(offline_config):
    """The dead-handler detector must actually fire when a handler is broken.

    This is the negative control for the whole class of bug: a capability whose
    only native handler is a typo still reports COVERED if a remote provider is
    runnable, so coverage stays 100% while the native code never executes. The
    detector is what makes that visible, so it has to be proven to work.
    """
    from aegis.core.ledger import Ledger as _L
    from aegis.core.models import Capability, Coverage, ResolvedProvider

    bad_provider = Provider(kind=ProviderKind.NATIVE, ref="aegis.nope:nope")
    cap = Capability(id="x", title="X", domain=CATALOG[0].domain,
                     phase=CATALOG[0].phase, summary="x", providers=[bad_provider])
    entry = ResolvedCapability(
        capability=cap, coverage=Coverage.COVERED,
        providers=[
            ResolvedProvider(provider=bad_provider, runnable=False,
                             reason="handler not importable"),
            ResolvedProvider(provider=Provider(kind=ProviderKind.REMOTE, ref="x"),
                             runnable=True, resolved_ref="x"),
        ])
    led = _L(config=offline_config, entries=[entry])
    # it is COVERED, so this is NOT a gap
    assert led.gaps() == []
    # but the dead handler must still be reported, and attributed to its masker
    dead = led.dead_natives()
    assert len(dead) == 1
    assert dead[0]["ref"] == "aegis.nope:nope"
    assert dead[0]["masked_by"] == "remote", "must report what is masking it"


def test_real_ledger_has_no_dead_natives(offline_config):
    assert Ledger.build(offline_config).dead_natives() == []


# ═══════════════════════════════════════════════════════ 4. capability integrity
def test_capability_count_unchanged_by_remediation():
    assert len(CATALOG) == 133


def test_no_capability_was_removed_by_remediation():
    """Spot-check representative capabilities across all nine suites.

    Every id here was verified to exist in the catalog as part of this
    remediation, so this is a regression guard against silent deletion, not a
    guess. `rollup` was originally in this list and had to be removed: no such
    capability exists, so asserting it would have been a fabricated expectation.
    """
    ids = {c.id for c in CATALOG}
    expected = (
        # s01 recon
        "subdomain_enum", "ct_log_mining", "dns_records", "http_probe",
        "port_scan", "bgp_asn_map", "bgp_hijack_detect", "tls_inventory",
        # s02 surface
        "dangling_dns", "subdomain_takeover",
        # s03 identity
        "ad_attack_path", "ad_delegation", "adcs_abuse", "kerberos_weakness",
        # s04 supply chain
        "ai_key_exposure", "secret_scan", "sbom_generate", "dependency_vuln",
        "container_scan", "iac_scan", "cicd_audit", "provenance_verify",
        # s05 detection
        "attack_coverage_map", "defense_impairment_gap", "stealth_gap",
        "sigma_authoring",
        # s06 response
        "ioc_enrich", "triage_automation", "pcap_analysis", "log_analysis",
        # s07 ai security
        "prompt_injection_test", "agent_permission_audit", "rag_poisoning_surface",
        # s08 lab
        "range_orchestrate", "atomic_emulation",
        # s09 assurance
        "control_mapping", "pqc_inventory", "ics_control_check", "evidence_package",
    )
    missing = sorted(set(expected) - ids)
    assert not missing, f"capabilities removed by remediation: {missing}"


def test_defense_impairment_knowledge_base_is_intact():
    """The ATT&CK v19 TA0112 technique table must not have been trimmed."""
    from aegis.suites.s05_detection import DEFENSE_IMPAIRMENT
    assert len(DEFENSE_IMPAIRMENT) >= 18
    for tid in ("T1685.001", "T1685.003", "T1686.003", "T1687", "T1689",
                "T1690", "T1688", "T1027.018"):
        assert tid in DEFENSE_IMPAIRMENT, f"{tid} removed from the knowledge base"



