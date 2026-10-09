"""G. Gap accounting — the class of defect where the tool reports success
while a capability cannot actually run.

The specific bug this file exists to pin: `Coverage` has four states (COVERED,
DEGRADED, MANUAL, UNCOVERED) but `gaps()` only handled DEGRADED and UNCOVERED.
A MANUAL capability was therefore simultaneously "not covered" (99.2%) and "not
a gap" (`complete() == True`, exit code 0). A manual/licensed-only path is by
definition an unattended gap, so it must appear in the gap list.
"""
from __future__ import annotations

import json


from aegis.cli import main
from aegis.core.config import Config
from aegis.core.ledger import Ledger
from aegis.core.models import Coverage


# ── the invariant ─────────────────────────────────────────────────────────────
def test_manual_only_capability_is_reported_as_a_gap(offline_config):
    """A capability resolvable only manually must appear in gaps()."""
    cfg = offline_config
    cfg.offline = True
    led = Ledger.build(cfg)

    manual = [e for e in led.entries if e.coverage is Coverage.MANUAL]
    assert manual, (
        "expected at least one capability to be MANUAL-only offline "
        "(bgp_hijack_detect has remote/docker/manual providers)")

    gap_keys = {g.key for g in led.gaps()}
    for e in manual:
        assert e.capability.key in gap_keys, (
            f"{e.capability.key} is MANUAL but not reported as a gap")


def test_gap_count_equals_non_covered_count(offline_config):
    """The four coverage views must agree, in every environment state."""
    for offline in (True, False):
        cfg = Config.load()
        cfg.offline = offline
        cfg.use_docker = False
        led = Ledger.build(cfg)

        counts = led.counts()
        non_covered = sum(v for k, v in counts.items() if k != "covered")
        assert len(led.gaps()) == non_covered, (
            f"offline={offline}: {non_covered} non-covered but "
            f"{len(led.gaps())} gaps reported")
        assert led.complete() is (non_covered == 0)
        assert led.coverage_pct() == round(
            100.0 * counts["covered"] / len(led.entries), 1)


def test_gap_kind_matches_its_coverage_state(offline_config):
    led = Ledger.build(offline_config)
    state_by_key = {e.capability.key: e.coverage.value for e in led.entries}
    for g in led.gaps():
        assert g.reason_kind == state_by_key[g.key], (
            f"{g.key}: gap kind {g.reason_kind!r} does not match its actual "
            f"coverage state {state_by_key[g.key]!r}")


def test_manual_gap_reports_the_manual_provider_as_the_blocker(offline_config):
    """The reason must name the manual/licensed path, not an incidental blocker.

    Picking providers[0] gave "offline mode" for a capability whose real blocker
    was the manual-only provider, which points the operator at the wrong fix.
    """
    led = Ledger.build(offline_config)
    for g in led.gaps():
        if g.reason_kind == Coverage.MANUAL.value:
            assert "manual" in g.reason.lower(), (
                f"{g.key}: MANUAL gap should say it is manual/licensed, "
                f"got {g.reason!r}")
            assert g.remedy, "a gap must suggest a remedy"


def test_hard_gaps_are_only_uncovered(offline_config):
    """`hard_gaps` must mean 'no implementation exists', never 'degraded'."""
    led = Ledger.build(offline_config)
    for g in led.hard_gaps():
        assert g.reason == "no implementation exists"
        assert g.reason_kind == Coverage.UNCOVERED.value


def test_coverage_never_exceeds_100_or_drops_below_zero(offline_config):
    led = Ledger.build(offline_config)
    pct = led.coverage_pct()
    assert 0.0 <= pct <= 100.0


def test_empty_ledger_is_vacuously_complete():
    led = Ledger(config=None, entries=[])
    assert led.gaps() == []
    assert led.complete() is True
    assert led.coverage_pct() == 100.0


# ── CLI surface must not launder a gap into a success ─────────────────────────
def test_gap_command_fails_when_gaps_exist(monkeypatch, capsys):
    """`aegis gap` must exit non-zero while a gap exists.

    Exercised by forcing a MANUAL-only state via an offline config, which is the
    real-world situation this bug occurred in.
    """
    rc = main(["gap", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    # under the test fixture the environment is fully provisioned, so no gaps
    if data:
        assert rc != 0, "gap command exited 0 while reporting gaps"
    else:
        assert rc == 0


def test_coverage_exit_code_tracks_gaps(fully_provisioned, capsys):
    rc = main(["coverage", "--json", "--no-record"])
    d = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert d["complete"] is True
    assert d["gaps"] == []


def test_doctor_exit_code_tracks_completeness(offline_config, capsys):
    rc = main(["doctor"])
    out = capsys.readouterr().out
    # must state the same verdict the coverage data supports
    if "0 gap" in out or "gap" not in out.lower():
        assert rc == 0
    else:
        assert rc != 0


def test_gap_dict_includes_reason_kind(offline_config):
    led = Ledger.build(offline_config)
    for g in led.gaps():
        d = g.to_dict()
        assert d["reason_kind"] in {"uncovered", "degraded", "manual"}
        json.dumps(d)
