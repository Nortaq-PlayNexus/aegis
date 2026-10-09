"""AEGIS packaging smoke test.

Run against a frozen build to prove the exe is functionally equivalent to the
source tree. The two assertions that matter most:

  * `coverage` reports 100% in BOTH source and frozen form
  * `scan` actually produces findings in frozen form

A frozen build that reports 100% coverage but scans nothing is the exact failure
this test exists to catch, because the capability catalog is a static table and
will happily report full coverage while the suite layer is missing from the bundle.

CLI contract
------------
The positional argument is the AEGIS command to test, and nothing else.
`--help` is handled by argparse and never reaches the subprocess; an unknown
option is rejected with exit code 2 rather than being forwarded to the child
process (which previously produced a bare ``FileNotFoundError: [WinError 2]``).
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

EXIT_OK = 0
EXIT_TEST_FAILURE = 1
EXIT_BAD_USAGE = 2

results: list[tuple[str, bool, str]] = []


# ─────────────────────────────────────────────────────────── CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="smoketest.py",
        description="Verify an AEGIS build behaves correctly (source tree or frozen binary).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python smoketest.py                          test `python -m aegis` in this interpreter
  python smoketest.py dist/aegis/aegis.exe     test a frozen onedir build
  python smoketest.py ./aegis.exe              test a frozen onefile build
  python smoketest.py "aegis.exe" -v           verbose

Exit codes: 0 all checks passed, 1 a check failed, 2 bad usage.
Options belonging to smoketest must appear before the command.
""",
    )
    p.add_argument("command", nargs="?", default=None,
                   help="AEGIS command to test "
                        "(default: this interpreter running `-m aegis`)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="print each subprocess result")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="suppress per-check lines; print only the summary")
    return p


def resolve_command(raw: str | None) -> list[str]:
    """Build the argv prefix handed to subprocess.

    Validates the executable exists so a typo becomes a clean usage error rather
    than an unhandled WinError 2 from deep inside subprocess.
    """
    if not raw:
        return [sys.executable, "-m", "aegis"]
    try:
        argv = shlex.split(raw, posix=(os.name != "nt"))
    except ValueError as e:
        raise ValueError(f"could not parse command {raw!r}: {e}") from e
    if not argv:
        raise ValueError("empty command")
    first = argv[0]
    looks_like_path = ("/" in first) or ("\\" in first) or first.endswith(".exe")
    if looks_like_path and not Path(first).exists():
        raise ValueError(f"command not found: {first}")
    return argv


# ─────────────────────────────────────────────────────────── harness
class Harness:
    def __init__(self, cmd: list[str], verbose: bool = False, quiet: bool = False):
        self.cmd = cmd
        self.verbose = verbose
        self.quiet = quiet

    def run(self, args: list[str], timeout: int = 900) -> tuple[int, str, str]:
        try:
            p = subprocess.run(self.cmd + args, capture_output=True, text=True,
                               timeout=timeout, errors="replace")
        except FileNotFoundError as e:
            return 127, "", f"executable not found: {self.cmd[0]} ({e})"
        except subprocess.TimeoutExpired:
            return 124, "", f"timeout after {timeout}s"
        if self.verbose:
            print(f"    $ {' '.join(self.cmd + args)}  -> rc={p.returncode}")
        return p.returncode, p.stdout or "", p.stderr or ""

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        results.append((name, ok, detail))
        if not self.quiet:
            mark = "PASS" if ok else "FAIL"
            print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))
        return ok


# ─────────────────────────────────────────────────────────── checks
def check_startup(h: Harness) -> None:
    rc, out, err = h.run(["--version"])
    h.check("exe starts and reports a version", "AEGIS" in out,
            f"rc={rc} {out.strip()[:40] or err.strip()[:40]}")


def check_coverage(h: Harness) -> dict:
    rc, out, err = h.run(["coverage", "--json", "--no-record"])
    cov: dict = {}
    ok = rc == 0
    detail = f"rc={rc} {err.strip()[:80]}"
    if ok:
        try:
            cov = json.loads(out)
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"json parse failed: {e}"
    h.check("coverage: 100% and zero gaps", bool(ok and cov.get("complete") is True),
            detail if not ok else
            f"pct={cov.get('coverage_pct')} counts={cov.get('counts')}")

    expected = {f"s0{i}_{n}" for i, n in
                ((1, "recon"), (2, "surface"), (3, "identity"), (4, "supplychain"),
                 (5, "detection"), (6, "response"), (7, "aisec"), (8, "lab"),
                 (9, "assure"))}
    doms = set(cov.get("domains", {}).keys())
    h.check("all 9 suites present in catalog", expected <= doms,
            f"missing={sorted(expected - doms)}" if expected - doms else "")
    return cov


def check_native_importable(h: Harness) -> None:
    rc, out, err = h.run(["catalog", "--json"])
    broken: list[str] = []
    total = 0
    if rc == 0:
        try:
            for e in json.loads(out):
                for p in e.get("providers", []):
                    if p.get("kind") == "native":
                        total += 1
                        if not p.get("runnable"):
                            broken.append(p.get("ref"))
        except Exception as exc:  # noqa: BLE001
            broken.append(f"catalog parse: {exc}")
    h.check(f"all {total} native providers importable in-bundle",
            not broken, f"broken={broken[:5]}" if broken else "")


def check_dead_natives(h: Harness) -> None:
    rc, out, err = h.run(["coverage", "--json", "--no-record"])
    dead: list[dict] = []
    if rc == 0:
        try:
            dead = json.loads(out).get("dead_natives") or []
        except Exception:  # noqa: BLE001
            pass
    h.check("no dead native handlers", not dead,
            f"dead={[d.get('ref') for d in dead[:3]]}" if dead else "")


def check_inventory(h: Harness) -> None:
    """Regression guard for the `_Plan has no attribute resolved_ref` crash."""
    rc, out, err = h.run(["inventory"])
    ok = rc == 0
    rows = None
    if ok:
        try:
            rows = json.loads(out)
        except Exception as e:  # noqa: BLE001
            ok, err = False, f"not valid JSON: {e}"
    h.check("inventory: no crash and valid machine-readable output",
            bool(ok and isinstance(rows, list)),
            f"rows={len(rows) if isinstance(rows, list) else 'n/a'} rc={rc} {err[:70]}")
    if isinstance(rows, list) and rows:
        h.check("inventory rows expose resolved_ref",
                all("resolved_ref" in r for r in rows),
                f"first={sorted(rows[0])[:6]}")


def check_scan(h: Harness) -> None:
    with tempfile.TemporaryDirectory() as td:
        fixture = Path(td) / "fix"
        (fixture / "infra").mkdir(parents=True)
        (fixture / "app.py").write_text(
            'AWS_KEY = "AKIA4T7M2ZK9XQPLWVB3"\n'
            'OPENAI = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n'
            'import os\nos.system("ping -n 4 " + os.environ.get("H",""))\n',
            encoding="utf-8")
        (fixture / "infra" / "main.tf").write_text(
            'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n  acl = "public-read"\n}\n',
            encoding="utf-8")
        rc, out, err = h.run(["scan", "secret_scan,iac_scan", "--repo", str(fixture),
                              "--workdir", str(Path(td) / "out"), "-q"])
        try:
            line = [l for l in out.splitlines() if "findings=" in l][-1]
            n = int(line.split("findings=")[1].split()[0])
        except Exception:  # noqa: BLE001
            n = -1
        h.check("scan produces findings (secrets + IaC)", n >= 3,
                f"findings={n} rc={rc} {err[:70]}")


def check_redaction(h: Harness) -> None:
    rc, out, err = h.run(["report", "--format", "json", "--limit", "30"])
    leaked = "AKIA4T7M2ZK9XQPLWVB3" in out or "sk-proj-AAAAAAAA" in out
    h.check("secrets are redacted in stored findings", rc == 0 and not leaked)


def check_defense_impairment(h: Harness) -> None:
    with tempfile.TemporaryDirectory() as td:
        rc, out, err = h.run(["scan", "defense_impairment_gap",
                              "--workdir", td, "-q"])
        h.check("Defense Impairment gap analysis runs", rc == 0,
                f"rc={rc} {err[:60]}")


def check_sarif(h: Harness) -> None:
    rc, out, err = h.run(["report", "--format", "sarif", "--limit", "5"])
    ok = rc == 0 and '"version": "2.1.0"' in out
    h.check("SARIF report renders", ok, f"rc={rc} {err[:60]}")


CHECKS = (
    check_startup, check_coverage, check_native_importable, check_dead_natives,
    check_inventory, check_scan, check_redaction, check_defense_impairment, check_sarif,
)


# ─────────────────────────────────────────────────────────── main
def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cmd = resolve_command(args.command)
    except ValueError as e:
        print(f"smoketest: {e}", file=sys.stderr)
        print("try: python smoketest.py --help", file=sys.stderr)
        return EXIT_BAD_USAGE

    print(f"AEGIS packaging smoke test\n  cmd: {' '.join(cmd)}\n")
    h = Harness(cmd, verbose=args.verbose, quiet=args.quiet)
    for fn in CHECKS:
        fn(h)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n  {passed}/{total} checks passed")
    return EXIT_OK if passed == total else EXIT_TEST_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
