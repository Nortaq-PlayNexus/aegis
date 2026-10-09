# AEGIS

**Automated Exposure Â· Gap Â· Intelligence Suite**

A defensive security operations platform. Nine suites, one capability ledger,
**zero silent gaps**.

---

## The idea

Most security "toolkits" are a bin folder. You don't know what you actually have,
and you find out at 3am that a capability you assumed existed was never wired to
anything.

AEGIS inverts that. Every capability is declared once in a **catalog**. Each
capability names its **providers**:

| Provider kind | Meaning | Resolution |
|---|---|---|
| `native` | implemented in this repo | always runnable |
| `docker` | a container image | docker present + image local/pullable |
| `local` | a binary on PATH | binary found |
| `remote` | an HTTP data source | network + optional API key |
| `manual` | human or licensed account | reported as manual-only |

`aegis coverage` resolves every provider **in this environment** and reports
`COVERED` / `DEGRADED` / `MANUAL` / `UNCOVERED`. **It exits non-zero while any gap
remains.** A gap with no implementation is a design gap and cannot be hidden.

Current state: **133 capabilities, 100% covered, 0 gaps** in a provisioned
environment. That figure is *provider resolution*, and it is worth being precise
about what it does and does not mean:

| Level | Question | How it is established | Current |
|---|---|---|---|
| 1. Declared | does the catalog define it? | `aegis catalog` | 133 |
| 2. Resolved | does a provider actually run **here**? | `aegis coverage` | 133/133 provisioned |
| 3. Handler importable | does the native code load? | `dead_natives()` | 132/132 |
| 4. Unit/contract tested | does it behave correctly? | `pytest` | see `tests/` |
| 5. Detection-validated | does it find a seeded weakness? | fixture scans | partial, per-suite |

**100% coverage is not a claim that all 133 capabilities have been tested.** It
means every declared capability currently has at least one runnable provider.
Coverage is computed per environment, so the number legitimately drops when you
turn off docker or go offline — e.g. `s01_recon.bgp_hijack_detect` has only
remote/docker/manual providers and reports `MANUAL` with `AEGIS_OFFLINE=1`. That
is reported as a gap, because a manual/licensed path is by definition not
unattended.

Run `python -m pytest -q` for level 4. `tests/` currently contains 168 tests.

## Modes

**Active is the default.** `--passive` is the opt-in for quiet mode, and it drops
every capability that would send packets to a target (port scanning, zone transfer,
fuzzing, exposure probing, default-credential testing, takeover validation,
prompt-injection probes, emulation).

```powershell
python -m aegis scan all                      # active
python -m aegis scan all --passive            # passive only
```

`--active` still exists and is a no-op-equivalent explicit spelling of the default,
useful in scripts.

## Guardrails (off by default)

Enforcement is opt-in via `config.json`. Flip these on when you want the tool to
*refuse* things rather than *note* them:

```json
{
  "guardrails": {
    "require_scope_for_active": false,
    "block_nonlocal_targets": false,
    "require_authorisation_record": false
  }
}
```

| Flag | Effect when `true` |
|---|---|
| `require_scope_for_active` | active runs with no `--domain/--host/--cidr/--repo` exit 2 |
| `block_nonlocal_targets` | the HTTP client refuses out-of-scope hosts |
| `require_authorisation_record` | requires `--authorised-by` and `--reference` |

Default posture: nothing is blocked. Running without a scope adds a note to the
run record rather than a refusal.

---

## Quick start

```powershell
# no install needed
$env:PYTHONPATH = "C:\Users\natha\projects\aegis"

python -m aegis doctor                 # environment + provider resolution
python -m aegis coverage               # THE gap report (exit 1 while gaps exist)
python -m aegis catalog -v             # every capability and its providers
python -m aegis gap                    # actionable gaps only

# or install it
pip install -e .
aegis coverage
```

## Scan

```powershell
# passive, supply chain + AI security against a repo
python -m aegis scan s04_supplychain,s07_aisec --repo . --report

# detection engineering â€” the ATT&CK v19 Defense Impairment gap analysis
python -m aegis scan defense_impairment_gap --opt rules_dir=./sigma

# scaffold a Sigma rule for a v19 technique
python -m aegis scan sigma_authoring --opt technique=T1689

# everything runnable
python -m aegis scan all --repo . --profile deep
python -m aegis scan all --domain acme.test
python -m aegis scan all --passive          # quiet mode

# reports
python -m aegis report --format sarif
python -m aegis report --severity critical --format html --out board.html
```

## Options

Capability-specific input is passed as `--opt key=value` (repeatable). Values are
type-inferred: `true`/`false`, ints, floats, comma-lists, and JSON for
dicts/arrays.

```powershell
python -m aegis scan airgapped --opt handles=alice,bob
python -m aegis scan pqc_inventory --opt policy='{"block_critical_deps":true}'
```

## Suites

| Suite | Capabilities | Focus |
|---|---|---|
| **S01 recon** | 26 | subdomain enum Â· CT mining Â· DNS/mail posture Â· BGP+ASN Â· RPKI Â· HTTP/TLS fingerprint Â· OOB validation Â· historical infra Â· OSINT |
| **S02 surface** | 12 | asset inventory Â· dangling DNS / subdomain takeover Â· pale-asset favicon clustering Â· cloud storage exposure Â· exposure graph Â· risk scoring Â· drift |
| **S03 identity** | 18 | AD attack paths Â· ADCS/ESC1 Â· Kerberos Â· delegation Â· shadow creds Â· DC hardening Â· Entra Â· **AiTM / device-code / FIDO-downgrade readiness** Â· **AI key exposure** Â· K8s RBAC |
| **S04 supplychain** | 15 | secret scan Â· SBOM gen+policy Â· dependency vuln Â· container scan Â· IaC Â· **CI/CD audit** Â· provenance verify Â· signing hygiene Â· **malicious-package + invisible-unicode (T1027.018)** |
| **S05 detection** | 15 | **Defense Impairment TA0112 gap analysis** Â· Stealth TA0005 Â· ATT&CK coverage Â· Sigma author/validate Â· **DaC CI pipeline** Â· log-source coverage Â· Sysmon audit Â· eBPF rule audit Â· control integrity |
| **S06 response** | 16 | IOC enrich/validate Â· feed sync Â· MISP/OpenCTI Â· triage Â· malware triage Â· YARA Â· PCAP Â· log hunt Â· forensics Â· evidence chain Â· containment/recovery verify Â· MTTD |
| **S07 aisec** | 12 | LLM inventory Â· **prompt-injection suite** Â· agent permission audit Â· indirect-injection surface Â· **AI supply-chain key hygiene** Â· RAG poisoning Â· model provenance Â· shadow AI Â· gateway audit |
| **S08 lab** | 8 | lab orchestration Â· vulnerable-by-design ranges Â· atomic emulation Â· purple campaigns Â· C2 sanitisation Â· detection harness Â· benchmark Â· teardown |
| **S09 assure** | 11 | CIS/NIST CSF/800-53/CMMC mapping Â· **PQC inventory** Â· HNDL review Â· supply-chain policy-as-code Â· drift Â· **SANS 5 ICS** Â· audit trail Â· evidence package Â· metrics Â· reporting |

---

## The headline capability

ATT&CK v19 (April 2026) abolished "Defense Evasion" and split it into **Stealth
(TA0005)** and **Defense Impairment (TA0112)**. TA0112 is four months old.

`defense_impairment_gap` enumerates all 18 techniques, names the telemetry that
should catch each, and reports which have no rule:

```powershell
python -m aegis scan defense_impairment_gap --opt rules_dir=./sigma
```

It covers `T1685.001â€“.006` (disable/modify tools), `T1686.001â€“.003` (firewall),
`T1687` (exploit the security product), `T1689` (downgrade), `T1690` (command
history), `T1688` (safe mode), `T1207` (DCShadow), `T1556.009` (CA policy),
`T1027.018` (invisible Unicode) and more.

It also **scaffolds the missing rules** â€” `sigma_authoring --opt technique=T1689`
emits a valid, referenced Sigma rule into `sigma/aegis/`.

---

## Docker is the leverage

On a box with no Go/Rust toolchain, the real tools are still reachable as
containers. AEGIS prefers a local binary, falls back to Docker, and reports
honestly which path it took:

```powershell
python -m aegis install dependency_vuln --run    # pull aquasec/trivy
python -m aegis install container_scan --run
```

Catalogued container providers include `projectdiscovery/{nuclei,subfinder,
httpx,katana,naabu,dnsx,interactsh,asnmap,tlsx}`, `aquasec/{trivy,kube-bench,
kubescape,tfsec}`, `anchore/{syft,grype}`, `zricethezav/gitleaks`,
`trufflesecurity/trufflehog`, `google/osv-scanner`, `sigstore/cosign`,
`bridgecrew/checkov`, `semgrep/semgrep`, `falcosecurity/falco`.

## Config

`~/.aegis/config.json` (all optional, or `AEGIS_*` env vars):

```json
{
  "rate_limit": 6.0,
  "timeout": 20.0,
  "parallel": 8,
  "use_docker": true,
  "pull_images": false,
  "offline": false
}
```

Set `AEGIS_PULL=1` to auto-pull container images on resolution.

## Storage

SQLite at `~/.aegis/data/aegis.db`: runs, findings (fingerprinted for
cross-run dedup), evidence, coverage history, baselines, audit trail.
Reports land in `~/.aegis/runs/<run-id>/`.

## Layout

```
aegis/
  core/
    catalog.py     the capability catalog â€” 133 declared capabilities
    ledger.py      provider resolution + coverage + gap analysis
    runner.py      native/local/docker execution and resolution
    http.py        polite, cached, rate-limited, scope-enforcing client
    models.py      Finding / Evidence / Capability / Provider / Scope
    store.py       SQLite persistence
    render.py      console, JSON, SARIF, CSV, Markdown, HTML
    dnsutil.py     dnspython helpers with socket fallback
    util.py        plumbing
  suites/          s01..s09 â€” each exposes check_* handlers
  cli.py           aegis <command>
```

## Design rules

1. **Active by default; `--passive` opts out.** Nothing is blocked by default.
2. **No silent failure.** Every provider resolution is recorded and surfaced.
3. **Gaps are features.** An empty gap list is the only acceptable end state.
4. **Hash-chained evidence.** Findings are chained so later tampering is detectable.
5. **Everything is reported, nothing is enforced** â€” unless you turn the guardrails on.

## Adding a capability

1. Add the handler in the right `suites/sNN_*.py` â€” name it `check_<id>` or
   `scan_<id>`, signature `def x(ctx: RunContext) -> list[Finding]`.
2. Declare it in `core/catalog.py` with its providers, ATT&CK ids, and controls.
3. `python -m aegis coverage` â€” it should still be 100% and the new one should
   resolve to `covered`.

That third step is the point: a capability you cannot prove runs is a gap.

---

# Packaging

## Build

```powershell
.\build.ps1                # onedir  (default, recommended)
.\build.ps1 -Onefile       # single .exe
.\build.ps1 -Name aegis-red -SkipTests
```

Verified on **Python 3.14.7 + PyInstaller 6.22.3**. The build script runs
`smoketest.py` twice - once against the source tree, once against the frozen
binary - and refuses to finish if either fails.

## Measured results

Both formats, same spec, same interpreter, same machine:

| Format | Size | Cold start | Smoke test |
|---|---|---|---|
| **onedir** (default) | 54.7 MB / 76 files | **~420 ms** | **8/8** |
| onefile | 32.8 MB | ~4,650 ms | 8/8 |
| source (`python -m aegis`) | - | ~1,560 ms | 8/8 |

**Onedir is the default** and wins on evidence:

- **~11x faster cold start.** Onefile re-extracts the entire 33 MB archive into
  `%TEMP%` on *every* launch. On a tool invoked dozens of times a day, that cost
  is paid constantly.
- **~3.7x faster than running from source** - it loads from a single packed
  archive instead of several hundred `.py` files.
- **Far fewer AV false positives.** An unsigned ~33 MB self-extracting binary is a
  textbook heuristic trigger, which is a genuinely bad property for security
  tooling people need to run.
- No runtime extraction path that can fail.

The only cost is that it is a folder, not a file. Zip it and distribute the folder.

## The one thing that will bite you

AEGIS declares capability providers as **strings**:

```python
N("aegis.suites.s05_detection:defense_impairment_gap", "AEGIS native")
```

and resolves them at runtime via `importlib.import_module()` in
`core/runner.py:resolve_native()`. **PyInstaller analyses imports statically and
cannot see those strings.**

A build without the spec's `hiddenimports` therefore keeps `catalog.py` (a static
table, so coverage still reports 100%) but loses the entire `suites/` layer -
producing a binary that looks healthy and does no work. `aegis.spec` lists all 22
AEGIS modules explicitly to prevent that.

## `smoketest.py`

The regression guard. It asserts the two properties that distinguish a working
frozen build from a plausible-looking broken one:

1. every native provider in the catalog is importable **inside the bundle**
2. a scan against a deliberately vulnerable fixture actually produces findings

```
  [PASS] exe starts and reports a version  - rc=0 AEGIS 1.0.0
  [PASS] coverage: 100% and zero gaps  - pct=100.0 counts={'covered': 133, ...}
  [PASS] all 9 suites present in catalog
  [PASS] all 132 native providers importable in-bundle
  [PASS] no dead native handlers
  [PASS] inventory: no crash and valid machine-readable output  - rows=133 rc=0
  [PASS] inventory rows expose resolved_ref
  [PASS] scan produces findings (secrets + IaC)  - findings=3
  [PASS] secrets are redacted in stored findings
  [PASS] Defense Impairment gap analysis runs
  [PASS] SARIF report renders
  11/11 checks passed
```

Exit codes: `0` all passed, `1` a check failed, `2` bad usage. `--help` is handled
by argparse and never reaches the subprocess; an unknown option or a missing
executable is a clean exit 2 rather than a bare `WinError 2`.

Run it in CI. A packaging change that breaks the suite layer fails the
"native providers importable" check even though `coverage` still reads 100%.

## Build failure modes seen

**`Failed to start embedded python interpreter: failed to get the Python codec of
the filesystem encoding`** - this is *not* a Python 3.14 incompatibility. It is a
corrupt or partial onefile archive, typically from an interrupted build or two
`--clean` onefile builds running concurrently (they contend on the same workpath
and the same `%TEMP%\_MEI*` extraction). `build.ps1` deletes the previous
artifact before building for exactly this reason. If you hit it: delete `dist*/`
and `build*/`, then rebuild serially.

## Dead native handlers

Coverage answers "does this capability have *a* runnable provider". A capability
can have a **broken native handler** and still be COVERED via a healthy
docker/local/remote fallback - coverage stays 100% and the broken code silently
never runs.

This happened for real: the catalog pointed at `check_historical` while the
function was `check_history`. `historical_infra` was covered by its remote
providers, so nothing complained and the native implementation was dead code.

`Ledger.dead_natives()` now reports that case, and `aegis coverage` **exits 2**
when any exist:

```
  DEAD NATIVE HANDLERS  (1)  - masked by a working fallback, but never runs
    s01_recon.historical_infra   aegis.suites.s01_recon:check_historical
        masked_by=remote  native handler not importable
```

## Tests

`python -m pytest -q` - **168 tests, 0 skipped, no network access required.**
The suite enforces offline mode and redirects `AEGIS_HOME` per test, so it never
touches your real state or the public internet.

| File | Tests | Covers |
|---|---|---|
| `test_cli.py` | 23 | parser surface, doctor/gap/catalog/inventory/report/baseline |
| `test_deps.py` | 24 | distribution-name vs import-name resolution |
| `test_gaps.py` | 11 | gap accounting consistency across environments |
| `test_ledger.py` | 27 | registration, resolution, active plan, zero-gap maths |
| `test_models.py` | 22 | provider/finding/scope types and serialisation |
| `test_regressions.py` | 14 | one test per defect found in the audit |
| `test_render.py` | 20 | JSON/SARIF/CSV/Markdown/HTML and redaction |
| `test_suite_defects.py` | 27 | bugs surfaced by ruff/mypy during remediation |

Two notes on how the tests are written:

- Tests that need 100% coverage use the `fully_provisioned` fixture, which skips
  with an explicit reason if the host lacks the relevant docker images. Tests that
  need *correct* gap accounting use `offline_config` and assert the real number.
- Where a test asserts a specific string, that string was read out of the actual
  output rather than assumed. One spot-check list in `test_regressions.py`
  originally asserted a capability id (`rollup`) that never existed; it was
  removed rather than made to pass.

## Notes

- `upx=False` deliberately - UPX-packed binaries trip AV heuristics badly.
- `console=True` - this is a CLI. Use `console=False` in the spec for a GUI build.
- The binary writes to `%USERPROFILE%\.aegis\` (db, runs, reports, cache) exactly
  as the source tree does.
- External tools are still resolved at runtime. The exe does **not** bundle
  nmap/nuclei/trivy - those are `docker`/`local` providers resolved against your
  machine, so `aegis.exe install <capability> --run` behaves identically frozen.
- `experiment_nohidden.spec` is a control experiment that removes the `aegis.*`
  hiddenimports to verify they are load-bearing. Not for shipping.
