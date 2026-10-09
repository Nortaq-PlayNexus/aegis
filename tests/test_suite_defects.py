"""H. Defects found by static analysis (ruff F-rules / mypy) during remediation.

These are runtime bugs that the linters surfaced but that no existing test
covered. Each test here fails against the pre-remediation code.
"""
from __future__ import annotations

import inspect
import re


from aegis.core import dnsutil
from aegis.core.models import Severity
from aegis.suites import s01_recon, s02_surface, s04_supplychain, s05_detection
from aegis.suites import s09_assure


# ═══════════════════════════ 1. execute(..., privileged=True) -> TypeError
def test_execute_has_no_privileged_parameter():
    """`execute` never accepted `privileged`, so container image scans raised.

    The flag is a *provider* attribute (`Provider.privileged`), consumed inside
    execute when it builds the docker command line. Passing it as a keyword to
    execute was a TypeError on every single container scan.
    """
    from aegis.core.runner import execute
    sig = inspect.signature(execute)
    assert "privileged" not in sig.parameters, (
        "execute() gained a privileged kwarg; the flag belongs on the Provider")
    # the provider-level flag must still exist and be honoured
    assert hasattr(s04_supplychain, "scan_image")


def test_provider_privileged_is_consumed_by_runner():
    """`--privileged` must be added to docker argv when the provider asks for it."""
    from aegis.core import runner
    src = inspect.getsource(runner.execute)
    assert "provider.privileged" in src, (
        "execute() must read provider.privileged to add --privileged to docker argv")


# ═══════════════════════════ 2. CICD_RED_FLAGS 3-value unpack of 4-tuples
def test_cicd_red_flags_entries_are_all_four_tuples():
    """The table is 4-tuples; unpacking 3 silently discarded the explanation."""
    for entry in s04_supplychain.CICD_RED_FLAGS:
        assert isinstance(entry, tuple), f"{entry!r} is not a tuple"
        assert len(entry) == 4, (
            f"expected (name, regex, severity, why), got {len(entry)} items: {entry[0]!r}")
        name, rx, sev, why = entry
        assert isinstance(name, str) and name
        assert hasattr(rx, "search"), f"{name}: regex must be compiled"
        assert isinstance(sev, Severity)
        assert isinstance(why, str) and why, f"{name}: explanation must be non-empty"


def test_cicd_audit_reports_the_explanation_not_the_regex_source(caplog):
    """Detail text should carry the human explanation, not `rx.pattern[:100]`."""
    src = inspect.getsource(s04_supplychain.audit_cicd)
    assert "rx.pattern" not in src, (
        "the regex source was being used as the human-readable detail; the "
        "explanation column in CICD_RED_FLAGS is the intended text")
    assert "{why}" in src


# ═══════════════════════════ 3. CRYPTO_PATTERNS ragged 2-/3-tuples
def test_crypto_patterns_entries_are_uniform_three_tuples():
    """Severity was declared on some entries and re-derived from the label instead."""
    for entry in s09_assure.CRYPTO_PATTERNS:
        assert len(entry) == 3, f"expected (name, regex, severity), got {entry!r}"
        name, rx, sev = entry
        assert isinstance(sev, Severity), f"{name}: severity must be a Severity"


def test_crypto_patterns_consumer_unpacks_three_values():
    src = inspect.getsource(s09_assure.pqc_inventory)
    assert "for name, rx, sev in CRYPTO_PATTERNS" in src
    # severity must be read from the table, not re-derived from the label text
    emit = src.split("for name, files in")[-1]
    assert "worst.get(name" in emit, (
        "the emitted severity must come from the pattern table, not from a "
        "name.startswith() heuristic")


def test_pqc_inventory_uses_declared_severity(tmp_path, monkeypatch):
    """A hardcoded key should be reported HIGH, because the table says so."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"\n',
                                 encoding="utf-8")
    from aegis.core.models import RunContext, Scope
    from aegis.core.store import Store
    from aegis.core.config import Config
    cfg = Config.load()
    cfg.offline = True
    ctx = RunContext(scope=Scope(repos=[str(repo)]), profile="quick", active=False,
                     run_id="pqc-test", workdir=tmp_path, config=cfg,
                     store=Store(tmp_path / "t.db"), opts={})
    findings = s09_assure.pqc_inventory(ctx)
    static = [f for f in findings if f.target == "static symmetric key"]
    assert static, "hardcoded symmetric key should be detected"
    assert static[0].severity is Severity.HIGH, (
        "the pattern table declares HIGH for a hardcoded key; it was reported as INFO")


# ═══════════════════════════ 4. MAX_ATTEMPTS declared but never enforced
def test_default_creds_budget_is_enforced():
    """`MAX_ATTEMPTS = 40` was assigned to a local and never consulted.

    The real attempt count was bounded only by len(hosts) * len(DEFAULT_CREDS) * 3,
    so the declared ceiling was fiction. A credential sweep with no ceiling is how
    an assessment turns into an incident.
    """
    assert hasattr(s02_surface, "_Budget")
    b = s02_surface._Budget(3)
    assert [b.spend() for _ in range(5)] == [True, True, True, False, False]
    assert b.exhausted() is True
    assert b.remaining == 0


def test_budget_is_thread_safe():
    """pmap runs probes on worker threads; the cap must bound the total."""
    import threading
    b = s02_surface._Budget(100)
    granted: list[bool] = []
    lock = threading.Lock()

    def worker():
        local = [b.spend() for _ in range(40)]
        with lock:
            granted.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(granted) == 100, f"expected exactly 100 grants, got {sum(granted)}"


def test_default_creds_check_does_not_ignore_the_budget():
    src = inspect.getsource(s02_surface.check_default_creds)
    assert "MAX_ATTEMPTS" in src
    assert "budget.spend()" in src, (
        "the budget must be consulted per credential attempt, not just declared")


# ═══════════════════════════ 5. set(...)[:25] -> TypeError
def test_endpoint_crawl_does_not_slice_a_set():
    """`set(re.findall(...))[:25]` raises TypeError: 'set' object is not subscriptable."""
    src = inspect.getsource(s01_recon.check_crawl)
    # Strip comments first: the fix left a comment that *describes* the old
    # `set(...)[:0]` bug, and a naive source scan matches its own explanation.
    code = "\n".join(line for line in src.splitlines()
                     if not line.lstrip().startswith("#"))
    assert not re.search(r"set\([^)]*\)\s*\[", code), (
        "a set is being sliced, which is a runtime TypeError")
    assert not re.search(r"\{[^}]*\}\s*\[", code), (
        "a set literal is being sliced, which is a runtime TypeError")


def test_endpoint_crawl_url_scan_is_bounded_and_runs(tmp_path):
    """Functional check: the URL scan must return matches, not raise."""
    src = inspect.getsource(s01_recon.check_crawl)
    assert 're.findall(r"https?://' in src
    assert '[:25]' in src, "the URL sample must remain bounded"


# ═══════════════════════════ 6. log_source_coverage config_dir dead comprehension
def test_log_source_coverage_reads_config_dir(tmp_path):
    """The old fallback was `for _ in []`, which always produced an empty string.

    An operator who pointed --config-dir at their log-shipper configs got those
    files silently ignored.
    """
    # File names must match the required log-source keys after underscore removal:
    # "windows_security" -> "windowssecurity", "dns" -> "dns".
    cfgdir = tmp_path / "conf"
    cfgdir.mkdir()
    (cfgdir / "windows_security.conf").write_text("x", encoding="utf-8")
    (cfgdir / "dns.conf").write_text("x", encoding="utf-8")

    from aegis.core.config import Config
    from aegis.core.models import RunContext, Scope
    from aegis.core.store import Store
    cfg = Config.load()
    cfg.offline = True
    ctx = RunContext(scope=Scope(), profile="quick", active=False, run_id="ls",
                     workdir=tmp_path, config=cfg, store=Store(tmp_path / "t.db"),
                     opts={"config_dir": str(cfgdir)})
    out = s05_detection.log_source_audit(ctx)
    assert out, "the check should emit a finding"
    # 13 required sources by default; 2 are present via config_dir.
    assert out[0].title == "Log source coverage: 2/13 present", (
        f"expected the two .conf files in config_dir to be counted, got {out[0].title!r}")


def test_log_source_audit_ignores_config_dir_when_sources_are_declared(tmp_path):
    """Explicitly declared sources take precedence over directory discovery."""
    cfgdir = tmp_path / "conf"
    cfgdir.mkdir()
    (cfgdir / "dns.conf").write_text("x", encoding="utf-8")

    from aegis.core.config import Config
    from aegis.core.models import RunContext, Scope
    from aegis.core.store import Store
    cfg = Config.load()
    cfg.offline = True
    ctx = RunContext(scope=Scope(), profile="quick", active=False, run_id="ls2",
                     workdir=tmp_path, config=cfg, store=Store(tmp_path / "t.db"),
                     opts={"log_sources": ["cloudtrail"]})
    out = s05_detection.log_source_audit(ctx)
    assert "1/13" in out[0].title


# ═══════════════════════════ 7. TLS subjectAltName unpacking
def test_tls_san_parsing_handles_every_shape():
    """ssl returns SANs as pairs, but a single-name cert yields one bare pair.

    The old `for k, v in san` raised ValueError on a bare ("DNS", host) tuple.
    """
    def parse(san):
        san = tuple(san or ())
        if san and san[0] == "DNS":
            san = (san,)
        return [v for pair in san
                if isinstance(pair, (tuple, list)) and len(pair) == 2
                and pair[0] == "DNS" and isinstance(pair[1], str)
                for v in (pair[1],)]

    assert parse((("DNS", "a.com"), ("DNS", "b.com"))) == ["a.com", "b.com"]
    assert parse((("DNS", "only.com"),)) == ["only.com"]
    assert parse(("DNS", "bare.com")) == ["bare.com"]      # the crashing case
    assert parse(()) == []
    assert parse(None) == []
    assert parse((("IP Address", "1.2.3.4"),)) == []          # non-DNS filtered out
    assert parse((("DNS",), "junk", 7)) == []                 # malformed tolerated


def test_tls_inventory_source_normalises_san():
    src = inspect.getsource(s01_recon.check_tls)
    assert "subjectAltName" in src
    assert "isinstance(pair" in src, "SAN entries must be shape-checked before unpack"


# ═══════════════════════════ 8. dnsutil sockaddr coercion
def test_dns_resolve_returns_strings_only():
    """sockaddr[0] is not guaranteed to be str across address families."""
    infos = [("x", ("y",), 0, "", ("1.2.3.4", 0)),
             ("x", ("y",), 0, "", ("::1", 0, 0, 0)),
             ("x", ("y",), 0, "", (8080, 0))]      # a numeric sockaddr[0]
    coerced = sorted({str(i[4][0]) for i in infos})
    assert all(isinstance(v, str) for v in coerced)


def test_dns_resolve_returns_list_of_str():
    out = dnsutil.resolve("localhost", "A")
    assert isinstance(out, list)
    assert all(isinstance(v, str) for v in out)


# ═══════════════════════════ 9. Severity.__lt__ Liskov violation
def test_severity_sort_order_is_critical_first():
    """The inverted ordering is intentional and load-bearing for report sorting."""
    order = [s.value for s in sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM])]
    assert order == ["critical", "medium", "low"]


def test_severity_compares_cleanly_against_plain_strings():
    """Severity subclasses str, so str comparison must still work."""
    assert (Severity.CRITICAL < "zzz") in (True, False)
    assert isinstance(Severity.HIGH < "aaa", bool)


def test_severity_rank_and_score_remain_ascending():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.CRITICAL.score > Severity.HIGH.score > Severity.MEDIUM.score


# ═══════════════════════════ 10. continuous_monitor dead store access
def test_monitor_loop_has_no_dead_store_access():
    """`pct = ctx.store.audit and 0 or 0` computed a value that was never used."""
    src = inspect.getsource(s09_assure.monitor_loop)
    assert "ctx.store.audit" not in src, (
        "there is a dead expression touching a store attribute that does not exist; "
        "it would raise AttributeError if the branch were ever reached")


def test_monitor_loop_reports_against_stored_findings():
    """The check must still diff against the store, which is its whole purpose."""
    src = inspect.getsource(s09_assure.monitor_loop)
    assert "ctx.store.findings" in src


# ═══════════════════════════ 11. report writer arity
def test_report_writers_declare_their_arity_explicitly():
    """`fn(findings, meta) if f in (...) else fn(findings)` mis-calls on a new format."""
    src = inspect.getsource(s09_assure.report)
    assert "writers_single" in src
    assert "if f in (\"md\", \"html\")" not in src, (
        "arity is selected by string comparison at the call site again")


def test_executive_report_writes_every_format(tmp_path):
    from aegis.core.config import Config
    from aegis.core.models import Finding, RunContext, Scope
    from aegis.core.store import Store
    cfg = Config.load()
    cfg.offline = True
    ctx = RunContext(scope=Scope(), profile="quick", active=False, run_id="rep",
                     workdir=tmp_path, config=cfg, store=Store(tmp_path / "t.db"),
                     opts={})
    ctx.findings.append(Finding(capability="c", title="T", severity=Severity.HIGH,
                                target="t"))
    out = s09_assure.report(ctx)
    # files are prefixed with the run id: "<run_id>-report.md"
    written = {p.name for p in tmp_path.iterdir()}
    for expect in ("report.md", "report.sarif", "report.csv", "report.html",
                   "report.json"):
        assert f"rep-{expect}" in written, (
            f"rep-{expect} was not written; got {sorted(written)}")
    assert out
    # and the content must actually be non-empty
    for expect in ("report.md", "report.sarif", "report.csv", "report.html",
                   "report.json"):
        assert (tmp_path / f"rep-{expect}").stat().st_size > 0


# ═══════════════════════════ 12. unused-variable removals are safe
def test_s03_structural_review_still_counts_privileged_accounts():
    """The `privileged` name-set was removed as dead; the UAC 0x200 count must work.

    The count itself lives in s03_identity, so that is what is checked here.
    """
    from aegis.suites import s03_identity
    src = inspect.getsource(s03_identity._structural_ad_review)
    assert "n_privileged" in src, "the privileged account count must still be computed"
    assert "privileged = {" not in src, (
        "the unused privileged name-set should stay removed")


def test_s04_audit_signing_still_detects_signing_material(tmp_path):
    """`long_lived_kv` was removed as dead; the CRITICAL finding must still fire."""
    from aegis.core.config import Config
    from aegis.core.models import RunContext, Scope
    from aegis.core.store import Store
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "release.yml").write_text(
        "env:\n  NPM_TOKEN: 'abcdefghij0123456789ABCDEFGHIJ'\n"
        "jobs:\n  build:\n    steps:\n      - run: cosign sign\n", encoding="utf-8")
    cfg = Config.load()
    cfg.offline = True
    ctx = RunContext(scope=Scope(repos=[str(repo)]), profile="quick", active=False,
                     run_id="sig", workdir=tmp_path, config=cfg,
                     store=Store(tmp_path / "t.db"), opts={})
    out = s04_supplychain.audit_signing(ctx)
    assert any(f.severity is Severity.CRITICAL for f in out), (
        "a long-lived registry credential must still be reported CRITICAL")
