# AEGIS — Audit Remediation Report

**Date:** 2026-10-01
**Scope:** the six defects in the audit brief, plus everything the fix work surfaced.
**Baseline:** 133 capabilities, 9 suites, 8,678 lines before remediation.

Every claim below was measured by running the command shown. Nothing here is
estimated, and no test was written to make a metric look better.

---

## 1. The four reported defects

### 1.1 `doctor` reported `dnspython:missing` for an installed package

**Confirmed.** `pip show dnspython` → 2.8.0 installed. `import dns` → works.
`doctor` → `dnspython:missing`.

**Root cause:** the probe in `cmd_doctor` iterated
`("requests", "dnspython", "dns", "yaml", "networkx", "ldap3", "jinja2")` and called
`importlib.import_module()` on each. `dnspython` is a *distribution* name; the
module it installs is `dns`. Probing the distribution name can never succeed.

The giveaway was that the list contained **both** `dnspython` and `dns` — the
signature of someone unsure which of the two was the import name.

**Fix:** new module `aegis/core/deps.py`. Each dependency declares its
distribution name, the module name(s) it actually provides, whether it is
required, and what AEGIS uses it for. Availability is *tested* by importing, and
the version loaded is reported from the module or its metadata.

```
deps  requests:ok(2.34.2)  dnspython:ok(2.8.0)  PyYAML:ok(6.0.3)  networkx:ok(3.6.1)
      Jinja2:ok(3.1.6)  ldap3:missing  tqdm:ok(4.70.1)  psutil:ok(7.2.2)  pydantic:ok(2.13.5)
```

`ldap3` is still `missing`, and that is correct: it is not installed. It is
declared `required=False` and suite 03 degrades to an offline review. The probe
distinguishes "distribution absent" from "distribution present, module broken",
because those need different fixes.

No status is hard-coded. `tests/test_deps.py` asserts the invariant that would
have caught the original bug, and greps `cli.py` to ensure the hard-coded list and
any literal `dnspython:ok` have not come back.

### 1.2 `inventory` crashed with `AttributeError: '_Plan' has no attribute 'resolved_ref'`

**Confirmed.** `python -m aegis inventory` → `AttributeError`.

**Root cause:** a type mismatch, not a missing field. `cmd_inventory` read
`rp.resolved_ref` off the plan object. `_Plan` (a class nested inside
`Ledger.active_plan()`) carried `.provider` — a `Provider`, which has no
`resolved_ref` — and `.rps`. `resolved_ref` lives on `ResolvedProvider`.

**Fix:** `PlanEntry` is now a module-level dataclass in `ledger.py` with typed
accessors: `.resolved` (the primary `ResolvedProvider`), `.native_refs` (all
runnable native handlers, for callers that fan out), `.is_native`. `resolved_ref`
was **not** duplicated onto `_Plan`, and no `AttributeError` was caught — the data
flow now matches the types. Consumers were updated to `entry.resolved`.

```
inventory -> 133 rows, valid JSON
keys: attack_ids, capability, controls, coverage, default_active, domain,
      native_handlers, phase, provider_kind, provider_ref, resolved_ref,
      runnable, title
```

### 1.3 `smoketest.py --help` died with `WinError 2`

**Confirmed.** The script did `CMD = sys.argv[1:] or [...]` and passed everything
to `subprocess`, so `--help` became the executable to launch.

**Fix:** argparse. Exit codes are now meaningful: `0` all checks passed, `1` a
check failed, `2` bad usage.

| Invocation | Before | After |
|---|---|---|
| `smoketest.py --help` | `WinError 2` | usage text, exit 0 |
| `smoketest.py C:\nope\missing.exe` | `WinError 2` | `command not found`, exit 2 |
| `smoketest.py --bogus` | passed through to child | rejected, exit 2 |

A typo in the executable path is now a clean usage error instead of an unhandled
`FileNotFoundError` from inside `subprocess`.

### 1.4 `pytest` ran no tests

**Confirmed.** `no tests ran in 0.05s`. There was no `tests/` directory.

**Fix:** **175 tests** across 8 files, 0 skipped, no network access.

| File | Tests | Covers |
|---|---|---|
| `test_cli.py` | 30 | parser surface, doctor/gap/catalog/inventory/report/baseline |
| `test_deps.py` | 24 | distribution-name vs import-name resolution |
| `test_gaps.py` | 11 | gap accounting consistency across environments |
| `test_ledger.py` | 27 | registration, resolution, active plan, zero-gap maths |
| `test_models.py` | 22 | provider/finding/scope types, serialisation |
| `test_regressions.py` | 14 | one test per audit defect |
| `test_render.py` | 20 | JSON/SARIF/CSV/Markdown/HTML, redaction |
| `test_suite_defects.py` | 27 | bugs found by ruff/mypy during remediation |

Enforced by fixtures: `AEGIS_HOME` is redirected per test, `AEGIS_OFFLINE=1` is
set, and `conftest.py` prints a header reminding you the suite must never touch
the internet. Provider *resolution* inspects PATH, docker image presence and env
vars — it does not perform network I/O.

Tests needing 100% coverage use a `fully_provisioned` fixture that skips with an
explicit reason when the host lacks the relevant docker images. Tests needing
*correct gap accounting* use `offline_config` and assert the real number. These
are different assertions and conflating them would have hidden defect 2.2 below.

---

## 2. Defects found while fixing the above

These were not in the brief. They surfaced from reading the code the brief's
defects lived in, and from running ruff and mypy over the package.

### 2.1 `gaps()` omitted `Coverage.MANUAL` — the tool reported success while a capability could not run

**This is the most serious finding, and it was not in the brief.**

`Coverage` has four states: `COVERED`, `DEGRADED`, `MANUAL`, `UNCOVERED`.
`Ledger.gaps()` handled only `DEGRADED` and `UNCOVERED`. A `MANUAL` capability was
therefore simultaneously **not covered** and **not a gap**.

Measured, offline, with the original code:

```
counts      : {'covered': 132, 'manual': 1}
coverage_pct: 99.2      <- correctly says not fully covered
complete()  : True      <- says complete
gaps        : 0         <- says no gaps
exit code   : 0         <- exits 0
```

`aegis coverage` and `aegis doctor` both reported success while
`s01_recon.bgp_hijack_detect` (remote RIS / docker asnmap / manual bgpmon) could
not run unattended. A manual-or-licensed-only path *is* an unattended gap by
definition — that is the project's own contract.

**Fix:** `gaps()` now reports all three non-covered states, sorted worst-first,
with a new `reason_kind` field so consumers can distinguish them without
string-matching. The reason now names the provider that actually explains the
state — it previously reported `providers[0]`'s reason, which pointed at "offline
mode" when the real blocker was the manual-only path.

```
[manual] s01_recon.bgp_hijack_detect
   reason: manual / licensed path only
   remedy: bgp.tools / RIPE RIS account
```

Now: `coverage_pct` 99.2, `complete()` False, `gaps` 1, exit 1. The four views
agree. `tests/test_gaps.py` asserts that agreement holds in every environment
state, and `test_coverage_json_is_internally_consistent` pins the invariant.

### 2.2 `execute(..., privileged=True)` — every container image scan raised `TypeError`

`execute()` has no `privileged` parameter. The flag is a `Provider` attribute that
`execute` reads internally to add `--privileged` to the docker argv. Passing it as
a keyword argument to `execute` was an unconditional `TypeError` on every call.
Removed the kwarg; `Provider.privileged` still works.

### 2.3 `MAX_ATTEMPTS = 40` was declared and never enforced

`check_default_creds` assigned the constant to a local `attempts_budget` and never
read it. The real attempt count was bounded only by `len(hosts) *
len(DEFAULT_CREDS) * 3`. A credential sweep with no ceiling is how an assessment
becomes an incident, so the code now matches its stated intent: a thread-safe
`_Budget` counter, checked per attempt, tested for thread safety.

### 2.4 `CICD_RED_FLAGS` 4-tuples unpacked as 3 — the explanation was discarded

The table is `(name, regex, severity, why)`. The consumer unpacked three values,
so the per-technique explanation never reached any report; the finding showed
`rx.pattern[:100]` instead. Now unpacks four and reports the human text.

### 2.5 `CRYPTO_PATTERNS` was a mix of 2- and 3-tuples

Same defect class. Severity was declared on some entries, then re-derived from the
label text at the call site — so a hardcoded symmetric key was reported `INFO`
despite the table saying `HIGH`. Table is now uniformly 3-tuples with an explicit
type annotation, and severity is read from it.

### 2.6 `set(...)[:25]` — `TypeError: 'set' object is not subscriptable`

In `check_crawl`. `re.findall` already returns a list, so the `set()` was both
wrong and pointless. Also fixed a `set(...)[:0] or set(...)[:6]` construct where
the left side was always empty.

### 2.7 A credential count was computed and discarded

The same loop computed how many credential-like patterns a crawled page served,
then never used the number. A publicly reachable page serving a hardcoded API key
produced no finding at all. It now emits a `HIGH` finding with redacted evidence.

### 2.8 `subjectAltName` unpacking crashed on single-name certificates

`for k, v in san` raises `ValueError` when `ssl` returns a bare `("DNS", host)`
tuple instead of a tuple of pairs. Now normalises both shapes and tolerates
malformed entries. Verified against list-of-pairs, single-pair, empty, `None`,
non-DNS and malformed inputs.

### 2.9 `log_source_coverage` silently ignored `--config-dir`

The fallback was `" ".join(... for _ in [])` — a comprehension over an empty
sequence, which always produced `""`. An operator who pointed the check at their
log-shipper configs got them discarded. Now globs the directory; explicitly
declared `--log-sources` still take precedence.

### 2.10 `report --out` worked for `html` only

`--format json --out x.json` printed to stdout and wrote nothing, because the
other formats never consulted `args.out`. `--format md` was not handled at all and
fell through to the console table. All five file formats now honour `--out`;
`report.html` keeps its default filename.

### 2.11 Smaller fixes

- `report --format md` was unreachable (folded into 2.10).
- `Severity.__lt__` violated the `str` contract; now accepts `object` and defers
  to string comparison for non-`Severity` values. Inverted sort order preserved.
- Report writer arity was selected by `if f in ("md", "html")` at the call site;
  now two explicitly typed tables, so a new format cannot be mis-wired.
- `sys.stdout.reconfigure` assumed a `TextIOWrapper`; absent under pytest capture.
- `dnsutil.resolve` assumed `sockaddr[0]` is always `str`.
- Six unused locals removed. Two were load-bearing, not dead: `long_lived_kv` was
  a leftover, but the `privileged` name-set in `_structural_ad_review` was
  replaced by a comment explaining that name matching is done via the UAC 0x200
  flag instead, so the next reader does not assume a blocklist is in force.

---

## 3. Verification

### Tests, lint, types

```
python -m pytest -q     175 passed in 63.53s
python -m ruff check .  All checks passed!
python -m mypy           Success: no issues found in 25 source files
```

mypy went from **15 errors to 0**. ruff from **58 to 0** (the remainder are
style rules now explicitly ignored with a stated reason in `pyproject.toml`, not
silently suppressed).

### Smoke test, source and frozen

`smoketest.py` went from 8 checks to 11 (added all-suites-present,
no-dead-natives, and inventory validity):

```
11/11 checks passed   (source)
11/11 checks passed   (dist-od\aegis\aegis.exe)
```

### Frozen binary, from a clean rebuild

`build.ps1` now gates on pytest → ruff → mypy → smoketest, and refuses to ship if
any fails. Clean onedir rebuild: **65 MB, 11/11 post-build checks passed**,
`build.ps1` exit 0.

```
deps   dnspython:ok(2.8.0)  ldap3:missing
cover  LEDGER COMPLETE — no gaps, no dead handlers.
```

The two `smoketest.py` invocations in `build.ps1` were passing
`python -m aegis` as arguments, which the new argparse correctly rejects. The
build caught this on its first run — the gate working as intended.

### End-to-end scan on a seeded vulnerable fixture

```
critical 5 · high 19 · medium 1 · info 1
total findings: 26   weighted risk: 187.2   errors=0
```

All five report formats render to file, and no raw secret appears in any of them.

---

## 4. On the "133/133" claim

The brief asked that coverage not be presented as "tested". It was, implicitly,
by a bare `100%`. `README.md` now states five distinct levels and what each is
actually established by:

| Level | Question | Established by | Now |
|---|---|---|---|
| 1. Declared | does the catalog define it? | `aegis catalog` | 133 |
| 2. Resolved | does a provider run **here**? | `aegis coverage` | 133/133 provisioned |
| 3. Handler importable | does the native code load? | `dead_natives()` | 132/132 |
| 4. Unit/contract tested | does it behave correctly? | `pytest` | 175 tests |
| 5. Detection-validated | does it find a seeded weakness? | fixture scans | partial, per-suite |

**100% coverage means every declared capability has at least one runnable
provider in this environment.** It is not a claim that 133 capabilities are
tested. Levels 4 and 5 are partial and are labelled as such.

Coverage is also environment-dependent, which the old wording hid: it is 100%
with docker and network available, and 99.2% fully offline, because one capability
has no unattended provider. Both numbers are correct; reporting only the first
was misleading.

---

## 5. Constraints honoured

- Capability count is unchanged at **133**, pinned by `test_capability_count_unchanged_by_remediation` and a 35-id spot-check across all nine suites. No capability was removed, merged, or reclassified to improve a number.
- `DEFENSE_IMPAIRMENT` still has all 18 ATT&CK v19 TA0112 techniques.
- No test asserts something untrue. Two of my own test expectations were wrong and were corrected against real output rather than made to pass: a capability id (`rollup`) that never existed, and a `Severity` `>` comparison the codebase does not support (it sorts by `.score`).
- No exception was suppressed to turn a failure into a pass. The one `try/except/pass` I added is in `deps.probe`, where a failing import *is* the signal.
- Assertions were strengthened, not weakened: the gap-accounting tests assert the four coverage views must agree, which the old code violated.

---

## 6. Known limitations

1. **Level 5 coverage is partial.** Several capabilities are validated only by unit tests, not by a seeded fixture proving detection. Closing this is the natural next task.
2. **`ldap3` remains uninstalled.** Suite 03's AD enumeration therefore runs in offline-review mode. Installing it is a one-line change but was not in scope, and installing a package to make a metric green is exactly what was asked not to do.
3. **The `fully_provisioned` fixture can skip** on a host without the relevant docker images. It skips with an explicit reason; it does not silently pass.
4. **Style lint rules were ignored rather than fixed** (`SIM105`, `E741`, `SIM102`, `SIM113`, `SIM117`), each with a reason recorded in `pyproject.toml`. Correctness rules are all enforced.
5. **Test suite takes ~65s**, dominated by 175 subprocess-free in-process CLI invocations that each build a full ledger. Acceptable; not optimised.
