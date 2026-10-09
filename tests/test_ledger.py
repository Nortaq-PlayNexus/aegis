"""B. Ledger — capability registration, provider resolution, active plan, gaps."""
from __future__ import annotations

import pytest

from aegis.core import runner
from aegis.core.catalog import CATALOG
from aegis.core.ledger import Ledger, PlanEntry
from aegis.core.models import Coverage, Domain, Phase, Provider, ProviderKind


# ── B1. capability registration ──────────────────────────────────────────────
def test_catalog_is_not_empty_and_is_unique():
    assert len(CATALOG) > 100
    keys = [c.key for c in CATALOG]
    assert len(keys) == len(set(keys)), "duplicate capability keys in catalog"


def test_every_capability_declares_providers():
    missing = [c.key for c in CATALOG if not c.providers]
    assert not missing, f"capabilities with no providers: {missing}"


def test_every_capability_has_a_domain_and_phase():
    for c in CATALOG:
        assert isinstance(c.domain, Domain)
        assert isinstance(c.phase, Phase)
        assert c.summary, f"{c.key} has no summary"


def test_all_nine_domains_are_populated():
    doms = {c.domain for c in CATALOG}
    assert len(doms) == 9, f"expected 9 suites, found {len(doms)}: {doms}"


def test_known_capabilities_are_present():
    ids = {c.id for c in CATALOG}
    for required in ("secret_scan", "defense_impairment_gap", "ai_key_exposure",
                     "subdomain_takeover", "attack_coverage_map", "prompt_injection_test"):
        assert required in ids, f"{required} missing from catalog"


def test_capability_count_has_not_been_altered_by_remediation():
    """Pinned so a future 'make the numbers look better' change is visible."""
    assert len(CATALOG) == 133, (
        f"catalog size changed to {len(CATALOG)}; the audit baseline was 133. "
        "Adding is fine, removing or merging is not.")


# ── B2. provider resolution ───────────────────────────────────────────────────
def test_ledger_builds_offline_without_network(offline_config):
    led = Ledger.build(offline_config)
    assert len(led.entries) == len(CATALOG)


def test_every_entry_is_resolved(offline_config):
    led = Ledger.build(offline_config)
    for e in led.entries:
        assert e.providers, f"{e.capability.key} resolved to zero providers"
        assert e.coverage in set(Coverage)


def test_native_handlers_are_importable(offline_config):
    """Level 3 of the provider ladder: the handler module must import."""
    led = Ledger.build(offline_config)
    broken = []
    for e in led.entries:
        for p in e.providers:
            if p.provider.kind is ProviderKind.NATIVE and not p.runnable:
                broken.append(p.provider.ref)
    assert not broken, f"native handlers that do not import: {broken}"


def test_no_dead_native_handlers(offline_config):
    led = Ledger.build(offline_config)
    dead = led.dead_natives()
    assert not dead, f"dead native handlers: {[d['ref'] for d in dead]}"


def test_docker_provider_unavailable_when_docker_disabled(offline_config):
    offline_config.use_docker = False
    led = Ledger.build(offline_config)
    docker_only = [e for e in led.entries
                   if e.providers and all(p.provider.kind is ProviderKind.DOCKER
                                          for p in e.providers)]
    for e in docker_only:
        assert e.coverage is Coverage.DEGRADED
        assert not e.best


def test_local_provider_resolution_reflects_path(offline_config, monkeypatch):
    """A local provider on PATH resolves; one absent does not."""
    monkeypatch.setattr(runner, "which", lambda name: "C:/fake/tool.exe")
    p = Provider(kind=ProviderKind.LOCAL, ref="definitely-not-real")
    r = runner.resolve(p, offline_config)
    assert r.runnable is True
    assert r.resolved_ref == "C:/fake/tool.exe"

    monkeypatch.setattr(runner, "which", lambda name: None)
    r2 = runner.resolve(p, offline_config)
    assert r2.runnable is False
    assert "PATH" in r2.reason


def test_remote_provider_blocked_when_offline(offline_config):
    offline_config.offline = True
    p = Provider(kind=ProviderKind.REMOTE, ref="crt.sh")
    r = runner.resolve(p, offline_config)
    assert r.runnable is False
    assert "offline" in r.reason


def test_manual_provider_is_never_runnable(offline_config):
    p = Provider(kind=ProviderKind.MANUAL, ref="licence-required")
    r = runner.resolve(p, offline_config)
    assert r.runnable is False


def test_remote_provider_requires_its_env(offline_config, monkeypatch):
    """Env gating applies once offline mode is out of the way.

    `resolve` checks offline *before* environment, so this test must run with
    offline disabled or it would only ever observe the "offline mode" reason.
    """
    offline_config.offline = False
    monkeypatch.delenv("AEGIS_TEST_NEEDED", raising=False)
    p = Provider(kind=ProviderKind.REMOTE, ref="x", env={"AEGIS_TEST_NEEDED": "1"})
    r = runner.resolve(p, offline_config)
    assert r.runnable is False
    assert "missing env" in r.reason


def test_remote_provider_runnable_when_env_present(offline_config, monkeypatch):
    offline_config.offline = False
    monkeypatch.setenv("AEGIS_TEST_NEEDED", "1")
    p = Provider(kind=ProviderKind.REMOTE, ref="x", env={"AEGIS_TEST_NEEDED": "1"})
    r = runner.resolve(p, offline_config)
    assert r.runnable is True


# ── B3. active plan ───────────────────────────────────────────────────────────
def test_active_plan_only_contains_runnable_capabilities(offline_config):
    led = Ledger.build(offline_config)
    plan = led.active_plan()
    assert plan
    for cap, entry in plan:
        assert entry.resolved.runnable is True
        assert cap.key == entry.capability.key


def test_active_plan_is_ordered_by_phase(offline_config):
    led = Ledger.build(offline_config)
    order = {p: i for i, p in enumerate(Phase)}
    phases = [order[c.phase] for c, _ in led.active_plan()]
    assert phases == sorted(phases), "active plan must run in kill-chain phase order"


def test_plan_entry_exposes_native_refs(offline_config):
    led = Ledger.build(offline_config)
    seen = 0
    for _cap, entry in led.active_plan():
        if entry.native_refs:
            seen += 1
            for ref in entry.native_refs:
                mod, _, fn = ref.partition(":")
                assert mod.startswith("aegis.suites.")
                assert fn
    assert seen > 50, "most capabilities should have at least one native handler"


def test_plan_entry_without_runnable_provider_raises(offline_config):
    cap = CATALOG[0]
    entry = PlanEntry(cap, [])
    with pytest.raises(LookupError):
        _ = entry.resolved


# ── B4. zero-gap calculation ──────────────────────────────────────────────────
def test_gap_calculation_is_consistent(offline_config):
    led = Ledger.build(offline_config)
    counts = led.counts()
    assert sum(counts.values()) == len(led.entries)
    assert led.coverage_pct() == round(
        100.0 * counts["covered"] / len(led.entries), 1)


def test_no_capability_is_unimplemented(offline_config):
    """The baseline the project is built on: every capability has an implementation.

    This holds in ANY environment, including fully offline with docker disabled.
    A hard gap means a capability declares no provider at all, which would mean
    the catalog is incomplete rather than merely unprovisioned.
    """
    led = Ledger.build(offline_config)
    assert led.hard_gaps() == [], "a capability has no implementation at all"
    for e in led.entries:
        assert e.providers, f"{e.capability.key} declares no providers"


def test_ledger_reports_zero_gaps_when_fully_provisioned(fully_provisioned):
    """With providers available, coverage is 100% and there are zero gaps."""
    led = Ledger.build(fully_provisioned)
    gaps = led.gaps()
    assert not gaps, "unexpected gaps: " + ", ".join(
        f"{g.key} [{g.reason_kind}] ({g.reason})" for g in gaps[:5])
    assert led.complete() is True
    assert led.coverage_pct() == 100.0


def test_hard_gaps_mean_no_implementation(offline_config):
    led = Ledger.build(offline_config)
    assert not led.hard_gaps(), "a hard gap means a capability has no provider at all"


def test_ledger_serialises(offline_config):
    d = Ledger.build(offline_config).to_dict()
    assert d["total"] == len(CATALOG)
    assert "domains" in d and len(d["domains"]) == 9
    assert "gaps" in d and "dead_natives" in d
    # complete must agree with the gap list, whatever this environment resolves
    assert d["complete"] is (len(d["gaps"]) == 0)
    assert d["coverage_pct"] == round(
        100.0 * d["counts"]["covered"] / d["total"], 1)


def test_get_by_id_and_by_key(offline_config):
    led = Ledger.build(offline_config)
    cap = CATALOG[0]
    assert led.get(cap.id) is not None
    assert led.get(cap.key) is not None
    assert led.get("definitely-not-a-capability") is None


def test_by_domain_partitions_all_entries(offline_config):
    led = Ledger.build(offline_config)
    grouped = led.by_domain()
    total = sum(len(v) for v in grouped.values())
    assert total == len(led.entries)
