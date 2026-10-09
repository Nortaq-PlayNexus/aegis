# AEGIS — Architecture

**Automated Exposure · Gap · Intelligence Suite**
A defensive security operations platform. Authorized-assessment and blue-team oriented.

## The core idea

Ten suites, one **capability ledger**, zero silent gaps.

Most "security toolkits" are a bin folder. You don't know what you actually have, and you
find out at 3am that a capability you assumed existed was never wired to anything.

AEGIS inverts that. Every capability from the research is declared once in a **catalog**.
Each capability names its **providers** — a native Python implementation, a Docker image, a
local binary, or a remote API. At runtime AEGIS resolves which providers are *executable in
this environment* and reports:

- `COVERED` — at least one runnable provider
- `DEGRADED` — provider exists but needs install (AEGIS tells you exactly how)
- `UNCOVERED` — **no implementation exists. This is a real gap. It shows up on the dashboard
  and cannot be hidden.**

`aegis coverage` exits non-zero while any gap remains. That is the "no more unattended" contract:
the suite is only complete when the gap list is empty.

## Suite topology

```
S00 CORE        shared engine: ledger, providers, runner, store, renderers
│
S01 RECON       subdomain enum · DNS · cert transparency · BGP/ASN · BGP hijack
S02 SURFACE     attack surface · dangling DNS / takeover · shadow assets · cloud storage
S03 IDENTITY    AD attack path · ADCS · Kerberos · Entra · AI-key exposure · MFA posture
S04 SUPPLYCHAIN secret scan · SBOM · dependency vuln · CI/CD audit · provenance · signing
S05 DETECTION   ATT&CK coverage · Defense Impairment gaps · Sigma authoring · DaC pipeline
S06 RESPONSE    IOC enrichment · triage · PCAP/log analysis · forensics · containment
S07 AISEC       prompt injection · agent permissions · AI supply chain · LLM config review
S08 LAB         range orchestration · adversary emulation · purple team · lab lifecycle
S09 ASSURE      control mapping (CIS/NIST/CMMC/PQC) · evidence capture · reporting
```

## Provider model

| Kind | Example | Resolution |
|---|---|---|
| `native` | pure-Python implementation in this repo | always runnable |
| `docker` | `ghcr.io/projectdiscovery/nuclei` | `docker` on PATH + image pullable |
| `local` | `gitleaks` on PATH | binary on PATH |
| `remote` | `crtsh`, `hackertarget`, `cloudflare-dns` | network + optional key |
| `manual` | needs a human/paid account | always reported as manual-only |

Docker is the leverage here. On a box with no Go/Rust toolchain, `nuclei`, `trivy`, `gitleaks`,
`grype`, `syft`, `osv-scanner`, `semgrep`, `checkov`, `kubescape`, `prowler`, `cosign` and
`falco` are all still reachable as containers. AEGIS prefers local, falls back to Docker, and
reports honestly which path it took.

## Layout

```
aegis/
  core/       catalog, ledger, providers, runner, http, dns, store, render, models, util
  suites/     s01..s09, one module per suite, each exposing check functions
  adapters/   external tool definitions (docker image, local bin, install command)
  cli.py      aegis <command>
```

## Commands

```
aegis coverage              # the gap report — exits 1 while gaps exist
aegis catalog --domain s04  # what exists, what runs
aegis doctor                # environment + provider resolution
aegis install <capability>  # resolve provider and install/print instructions
aegis scan <suite> --target ... --profile quick|standard|deep
aegis scan all              # everything runnable, respecting scope
aegis report --format md|sarif|json|csv
aegis watch <suite>         # continuous monitoring loop
```

## Design rules

1. **Read-only by default.** Every check is passive unless explicitly passed `--active`.
2. **Scope is mandatory.** Active suites refuse to run without `--scope` or `--target` and
   refuse to run against anything outside the declared scope file.
3. **No silent failure.** Every provider resolution is recorded and surfaced.
4. **Gaps are features.** An empty gap list is the only acceptable end state.
5. **Legal use.** This is for systems you own or are contractually authorised to test.
