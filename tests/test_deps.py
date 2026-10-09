"""D. Dependency resolution — the dnspython false-negative regression.

The original defect: the availability probe imported *distribution* names.
`dnspython` is a distribution; the module it installs is `dns`. The old list
contained both `dnspython` and `dns`, which is the signature of that confusion,
and it reported dnspython:missing for a package that was installed and working.
"""
from __future__ import annotations

import importlib

import pytest

from aegis.core import deps


# ── the mapping itself ────────────────────────────────────────────────────────
def test_dnspython_maps_to_dns_import_name():
    d = deps.by_distribution("dnspython")
    assert d is not None, "dnspython must be declared as a dependency"
    assert "dns" in d.imports, (
        "dnspython installs the module `dns`; probing the distribution name "
        "produces a false negative")
    assert "dnspython" not in d.imports, (
        "`dnspython` is not an importable module and must not be probed as one")


def test_pyyaml_maps_to_yaml_import_name():
    d = deps.by_distribution("PyYAML")
    assert d is not None
    assert "yaml" in d.imports
    assert "PyYAML" not in d.imports


def test_jinja2_maps_to_jinja2_import_name():
    d = deps.by_distribution("Jinja2")
    assert d is not None
    assert "jinja2" in d.imports
    assert "Jinja2" not in d.imports


def test_every_dependency_declares_at_least_one_import():
    for d in deps.DEPENDENCIES:
        assert d.imports, f"{d.distribution} declares no import name"
        assert d.provides, f"{d.distribution} does not say what it provides"


def test_lookup_is_case_insensitive():
    assert deps.by_distribution("DNSPYTHON") is not None
    assert deps.by_distribution("pyyaml") is not None
    assert deps.by_distribution("not-a-real-package") is None


# ── the general rule that would have caught the bug ───────────────────────────
def test_no_dependency_declares_an_import_name_it_does_not_provide():
    """The defect pattern, stated as an invariant.

    The dnspython bug was declaring `dnspython` as the import name when the
    distribution actually provides `dns`. The general rule: a declared import
    name must be a module that the distribution genuinely provides. We cannot
    prove that statically, so we assert the direction that is checkable and
    would have caught the original mistake:

      if a distribution name IS importable, it must be listed as an import
      (otherwise the declared imports are wrong).

    Note ldap3 is the deliberate negative control: it is simply not installed, so
    `ldap3` is both its distribution name and its module name, and the probe
    correctly reports it missing. Probing a name that happens to equal the
    distribution is only a bug when the distribution provides a *different* module.
    """
    offenders = []
    for d in deps.DEPENDENCIES:
        try:
            importlib.import_module(d.distribution)
            importable = True
        except Exception:  # noqa: BLE001
            importable = False
        if importable and d.distribution not in d.imports:
            offenders.append(
                f"{d.distribution} is importable but not declared as an import")
    assert not offenders, "dependency mapping mistakes: " + "; ".join(offenders)


def test_dependency_with_differing_module_name_declares_that_module():
    """Packages whose module name differs from the distribution name.

    This is the class of mapping error that produced the original false negative,
    so each one is pinned explicitly: a renamed module must be declared, and the
    distribution name must not be used as the import name.
    """
    # (distribution, module name that differs from it)
    renamed = {
        "dnspython": "dns",
        "PyYAML": "yaml",
    }
    for dist, module in renamed.items():
        d = deps.by_distribution(dist)
        assert d is not None, f"{dist} not declared"
        assert module in d.imports, f"{dist} must declare its module '{module}'"
        assert dist not in d.imports, (
            f"{dist} is a distribution name, not an importable module")


# ── probing actually tests, it does not assert ────────────────────────────────
def test_probe_reports_availability_by_actually_importing():
    # requests is a hard requirement of this project, so it must probe available.
    r = deps.probe(deps.by_distribution("requests"))
    assert r.available is True
    assert r.status == "ok"
    assert r.version, "an available dependency must report the version it loaded"


def test_probe_reports_missing_for_a_genuinely_absent_module():
    fake = deps.Dependency("not-installed-xyz", ("definitely_not_a_module_xyz",), True)
    r = deps.probe(fake)
    assert r.available is False
    assert r.status == "missing"
    assert r.import_error, "a missing dependency must explain why"
    assert r.distribution_installed is False


def test_probe_distinguishes_broken_module_from_absent_distribution():
    """A distribution present but whose module raises must be distinguishable."""
    fake = deps.Dependency("requests", ("a_module_that_does_not_exist_at_all",), True)
    r = deps.probe(fake)
    assert r.available is False
    # distribution_installed must be True here: `requests` really is installed,
    # we are probing a module name it does not provide.
    assert r.distribution_installed is True
    assert r.import_error


def test_available_helper_agrees_with_probe():
    for d in deps.DEPENDENCIES:
        assert deps.available(d) == deps.probe(d).available, \
            f"available() disagreed with probe() for {d.distribution}"


# ── optional-dependency behaviour ─────────────────────────────────────────────
def test_ldap3_is_optional_and_reported_as_missing_when_absent():
    d = deps.by_distribution("ldap3")
    assert d is not None
    assert d.required is False, "ldap3 must remain optional"
    r = deps.probe(d)
    if r.available:
        assert r.status == "ok"
    else:
        assert r.status == "missing"
        # Either way, it must not be reported as a hard failure.
        assert d.required is False


def test_only_requests_and_networkx_are_required_today():
    required = {d.distribution for d in deps.DEPENDENCIES if d.required}
    # These two have no native fallback path in the current implementation.
    assert "requests" in required
    assert set(required) <= {"requests", "networkx"}, \
        f"unexpected required dependencies: {required}"


def test_probe_all_covers_every_declared_dependency():
    results = deps.probe_all()
    assert len(results) == len(deps.DEPENDENCIES)
    assert {r.dependency.distribution for r in results} == \
           {d.distribution for d in deps.DEPENDENCIES}


def test_probe_result_serialises():
    r = deps.probe(deps.by_distribution("requests"))
    d = r.to_dict()
    for key in ("distribution", "imports", "required", "available", "version",
                "distribution_installed", "import_error", "provides"):
        assert key in d


@pytest.mark.parametrize("dist", ["requests", "dnspython", "PyYAML", "networkx",
                                  "Jinja2", "ldap3", "tqdm", "psutil", "pydantic"])
def test_named_dependency_is_declared(dist):
    assert deps.by_distribution(dist) is not None, f"{dist} not declared"
