"""C. Models — Provider, ResolvedProvider, ResolvedCapability, Finding, Scope."""
from __future__ import annotations

import json


from aegis.core.models import (Capability, Coverage, Domain, Evidence, Finding, Phase,
                               Provider, ProviderKind, ResolvedCapability,
                               ResolvedProvider, Scope, Severity)


# ── Provider ──────────────────────────────────────────────────────────────────
def test_provider_defaults():
    p = Provider(kind=ProviderKind.NATIVE, ref="aegis.suites.s01_recon:check_dns")
    assert p.requires == []
    assert p.env == {}
    assert p.privileged is False
    assert p.install == ""


def test_provider_serialises():
    p = Provider(kind=ProviderKind.DOCKER, ref="aquasec/trivy:latest",
                 install="docker pull aquasec/trivy:latest", privileged=True)
    d = p.to_dict()
    assert d["kind"] == "docker"
    assert d["ref"] == "aquasec/trivy:latest"
    assert d["privileged"] is True


def test_provider_kinds_are_distinct():
    kinds = {k.value for k in ProviderKind}
    assert kinds == {"native", "docker", "local", "remote", "manual"}


# ── ResolvedProvider ──────────────────────────────────────────────────────────
def test_resolved_provider_carries_resolved_ref():
    """The attribute cmd_inventory was wrongly reading off the plan object."""
    rp = ResolvedProvider(
        provider=Provider(kind=ProviderKind.LOCAL, ref="nmap"),
        runnable=True, reason="", resolved_ref="C:/tools/nmap.exe")
    assert rp.resolved_ref == "C:/tools/nmap.exe"
    d = rp.to_dict()
    assert d["runnable"] is True
    assert d["resolved_ref"] == "C:/tools/nmap.exe"


def test_resolved_provider_defaults_resolved_ref_to_empty():
    rp = ResolvedProvider(provider=Provider(kind=ProviderKind.NATIVE, ref="x"),
                          runnable=False, reason="broken")
    assert rp.resolved_ref == ""
    assert rp.to_dict()["reason"] == "broken"


# ── ResolvedCapability ────────────────────────────────────────────────────────
def _cap(cid="demo"):
    return Capability(id=cid, title="Demo", domain=Domain.RECON, phase=Phase.RECON,
                      summary="demo capability",
                      providers=[Provider(kind=ProviderKind.NATIVE, ref="a:b")])


def test_resolved_capability_best_returns_first_runnable():
    cap = _cap()
    rp_bad = ResolvedProvider(provider=cap.providers[0], runnable=False, reason="no")
    rp_good = ResolvedProvider(provider=Provider(kind=ProviderKind.LOCAL, ref="nmap"),
                               runnable=True, resolved_ref="C:/nmap.exe")
    rc = ResolvedCapability(capability=cap, coverage=Coverage.COVERED,
                            providers=[rp_bad, rp_good])
    assert rc.best is rp_good
    assert len(rc.runnable_providers) == 1


def test_resolved_capability_best_is_none_when_nothing_runnable():
    cap = _cap()
    rc = ResolvedCapability(
        capability=cap, coverage=Coverage.DEGRADED,
        providers=[ResolvedProvider(provider=cap.providers[0], runnable=False,
                                    reason="nope")])
    assert rc.best is None
    assert rc.runnable_providers == []


def test_resolved_capability_serialises():
    cap = _cap()
    rc = ResolvedCapability(
        capability=cap, coverage=Coverage.COVERED,
        providers=[ResolvedProvider(provider=cap.providers[0], runnable=True,
                                    resolved_ref="a:b")])
    d = rc.to_dict()
    assert d["key"] == "s01_recon.demo"
    assert d["coverage"] == "covered"
    assert d["providers"][0]["runnable"] is True
    json.dumps(d)  # must be JSON-serialisable


# ── Severity ──────────────────────────────────────────────────────────────────
def test_severity_ordering():
    """Severity is a plain str enum, so it does NOT support `>`.

    Ordering is defined by the numeric `score` field, which is what renderers and
    sorting use. This test pins that contract rather than the comparison operators.
    """
    assert Severity.CRITICAL.score > Severity.HIGH.score > Severity.MEDIUM.score
    assert Severity.MEDIUM.score > Severity.LOW.score > Severity.INFO.score
    by_score = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM],
                      key=lambda s: -s.score)
    assert by_score == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_severity_scores_increase():
    assert Severity.CRITICAL.score > Severity.HIGH.score > Severity.LOW.score
    assert Severity.OK.score == 0


# ── Finding ───────────────────────────────────────────────────────────────────
def test_finding_fingerprint_is_stable():
    a = Finding(capability="c", title="T", severity=Severity.HIGH, target="h")
    b = Finding(capability="c", title="T", severity=Severity.HIGH, target="h")
    assert a.fingerprint == b.fingerprint
    assert len(a.fingerprint) == 16


def test_finding_fingerprint_varies_with_substance():
    a = Finding(capability="c", title="T", severity=Severity.HIGH, target="h")
    b = Finding(capability="c", title="Different", severity=Severity.HIGH, target="h")
    assert a.fingerprint != b.fingerprint


def test_finding_serialises_with_evidence():
    f = Finding(capability="c", title="T", severity=Severity.CRITICAL, target="h",
                detail="d", attack_ids=["T1190"],
                evidence=[Evidence(kind="file", summary="s", locator="l",
                                   excerpt="e")])
    d = f.to_dict()
    assert d["severity"] == "critical"
    assert d["attack_ids"] == ["T1190"]
    assert d["evidence"][0]["kind"] == "file"
    json.dumps(d)


# ── Scope ─────────────────────────────────────────────────────────────────────
def test_scope_starts_empty():
    assert Scope().is_empty() is True


def test_scope_domain_suffix_matching():
    s = Scope(domains=["example.com"])
    assert s.allows_host("example.com")
    assert s.allows_host("api.example.com")
    assert s.allows_host("*.example.com")
    assert not s.allows_host("notexample.com")
    assert not s.allows_host("example.com.evil.net")


def test_scope_wildcard_prefix_is_stripped():
    s = Scope(domains=["*.example.com"])
    assert s.allows_host("api.example.com")
    assert not s.allows_host("example.org")


def test_scope_cidr_matching():
    s = Scope(cidrs=["10.0.0.0/24"])
    assert s.allows_host("10.0.0.5")
    assert not s.allows_host("10.0.1.5")
    assert not s.allows_host("garbage")


def test_scope_explicit_hosts():
    s = Scope(hosts=["build01.corp.local"])
    assert s.allows_host("build01.corp.local")
    assert not s.allows_host("build02.corp.local")


def test_scope_rejects_empty_host():
    assert Scope(domains=["example.com"]).allows_host("") is False


def test_scope_serialises():
    s = Scope(domains=["example.com"], authorised_by="CISO", reference="REF-1")
    d = s.to_dict()
    assert d["authorised_by"] == "CISO"
    assert d["reference"] == "REF-1"


# ── RunContext ────────────────────────────────────────────────────────────────
def test_run_context_emit_and_notes(context):
    from aegis.core.models import RunContext
    f = context.emit(Finding(capability="c", title="T", severity=Severity.LOW))
    assert f in context.findings
    assert f.suite_run == "test-run"
    context.note("hello")
    assert "hello" in context.notes
    assert isinstance(context, RunContext)


def test_run_context_opt_defaults(context):
    assert context.opt("missing", "fallback") == "fallback"
    assert context.opt("missing") is None
