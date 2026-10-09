"""Shared fixtures for the AEGIS test suite.

Design constraints:
  * no test may depend on the public internet
  * no test may write outside its own temporary AEGIS_HOME
  * no test performs active security testing against anything

`offline_config` disables docker and network providers so `Ledger.build()` is
purely local and fast; provider resolution for docker/local is exercised
separately in test_ledger.py with explicit monkeypatching.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis.core.config import Config  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Redirect AEGIS_HOME so nothing touches the real ~/.aegis."""
    home = tmp_path / "aegis-home"
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AEGIS_HOME", str(home))
    monkeypatch.setenv("AEGIS_OFFLINE", "1")
    monkeypatch.setenv("NO_COLOR", "1")
    yield home


@pytest.fixture
def offline_config(isolated_home) -> Config:
    """A Config with no network and no docker, for deterministic ledger tests.

    Note this environment CANNOT reach full coverage: `s01_recon.bgp_hijack_detect`
    has only remote (RIS), docker (asnmap) and manual (bgpmon) providers, so with
    network and docker both off it resolves to MANUAL. That is a genuine,
    correctly-reported gap - see tests/test_gaps.py. Tests that assert 100% must
    use `provisioned_config` instead.
    """
    cfg = Config.load()
    cfg.offline = True
    cfg.use_docker = False
    return cfg


@pytest.fixture
def provisioned_config(isolated_home, monkeypatch) -> Config:
    """A Config that may use docker and provider env vars.

    Used for the full-coverage assertions. Does not contact the network itself:
    provider *resolution* only inspects PATH, docker image presence and env vars.
    """
    monkeypatch.delenv("AEGIS_OFFLINE", raising=False)
    cfg = Config.load()
    cfg.offline = False
    return cfg


@pytest.fixture
def fully_provisioned(provisioned_config):
    """`provisioned_config`, but only if it actually reaches 100% coverage.

    Reaching full coverage depends on the host having the relevant docker images
    or provider credentials. Where that is not true, tests needing 100% skip with
    an explicit reason rather than asserting something untrue.
    """
    from aegis.core.ledger import Ledger
    led = Ledger.build(provisioned_config)
    if not led.complete():
        unmet = ", ".join(f"{g.key}[{g.reason_kind}]" for g in led.gaps()[:4])
        pytest.skip(f"environment is not fully provisioned: {unmet}")
    return provisioned_config


@pytest.fixture
def vulnerable_repo(tmp_path) -> Path:
    """A deliberately vulnerable repository for scan tests.

    Contains: an AWS key, an LLM provider key, a command-injection sink, a
    public S3 bucket, an IAM wildcard, and invisible-unicode smuggling.
    """
    repo = tmp_path / "vulnrepo"
    (repo / "infra").mkdir(parents=True)
    (repo / "sigma").mkdir(parents=True)

    (repo / "app.py").write_text(
        "import os\n"
        'AWS_ACCESS_KEY = "AKIA4T7M2ZK9XQPLWVB3"\n'
        'LLM_KEY = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n'
        "def run(host):\n"
        '    os.system("ping -n 4 " + host)\n',
        encoding="utf-8")
    (repo / "infra" / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "acme-logs"\n'
        '  acl    = "public-read"\n'
        "}\n"
        'data "aws_iam_policy_document" "wide" {\n'
        '  statement { Action = "*", Resource = "*" }\n'
        "}\n",
        encoding="utf-8")
    # U+202E RIGHT-TO-LEFT OVERRIDE: the Shai-Hulud / GlassWorm smuggling trick.
    (repo / "payload.js").write_text(
        "const cfg = { mode: 'safe' };\u202e// ; eval(atob('cGF5bG9hZA=='))",
        encoding="utf-8")
    (repo / "sigma" / "eventlog.yml").write_text(
        "title: Detect Windows Event Log Cleared\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "status: experimental\n"
        "logsource:\n  product: windows\n  service: security\n"
        "detection:\n  selection:\n    EventID: 1102\n"
        "  condition: selection\n"
        "level: high\n",
        encoding="utf-8")
    return repo


@pytest.fixture
def workdir(tmp_path) -> Path:
    wd = tmp_path / "work"
    wd.mkdir(parents=True, exist_ok=True)
    return wd


@pytest.fixture
def context(offline_config, workdir, vulnerable_repo):
    """A RunContext wired to the vulnerable fixture, offline and non-networked."""
    from aegis.core.models import RunContext, Scope
    from aegis.core.store import Store
    scope = Scope(repos=[str(vulnerable_repo)])
    store = Store(offline_config.data / "test.db")
    return RunContext(
        scope=scope, profile="quick", active=False, run_id="test-run",
        workdir=workdir, config=offline_config, store=store, opts={})


def pytest_report_header(config) -> str:
    """Make it obvious if these tests somehow gained a network dependency."""
    return ("AEGIS test suite — offline enforced via AEGIS_OFFLINE=1 "
            "(no test contacts the public internet)")
