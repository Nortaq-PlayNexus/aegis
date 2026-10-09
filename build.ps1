<#
.SYNOPSIS
    Build AEGIS into a Windows executable (onefile or onedir).

.DESCRIPTION
    Verified on Python 3.14.7 + PyInstaller 6.22.3.

    The build is driven by aegis.spec, which exists for one specific reason:
    AEGIS declares its capability providers as strings (e.g.
    "aegis.suites.s05_detection:defense_impairment_gap") and resolves them at
    runtime with importlib. PyInstaller analyses imports statically and cannot see
    those strings, so without the spec's hiddenimports a frozen build keeps the
    catalog (a static table, so coverage still reports 100%) but loses the entire
    suite layer.

    The build script gates on four things and refuses to finish if any fails:
    pytest, ruff (correctness rules), mypy, and smoketest.py - which runs twice,
    once against the source tree and once against the frozen binary.

.PARAMETER Onefile
    Build a single-file exe instead of a folder. Measured on this machine:
        onedir  ~420 ms cold start, 54.7 MB across 76 files
        onefile ~4650 ms cold start, 32.8 MB single file
    Onedir is the default because it is ~11x faster (no %TEMP% extraction per
    launch) and triggers far fewer AV false positives on an unsigned binary.
    Use -Onefile only when you need a single artifact to drop somewhere.

.PARAMETER Name
    Output binary name (default: aegis)

.PARAMETER SkipTests
    Skip the smoke tests. Do not use in CI.

.EXAMPLE
    .\build.ps1                    # onedir (recommended)
    .\build.ps1 -Onefile           # single file
    .\build.ps1 -Name aegis-red -SkipTests
#>
[CmdletBinding()]
param(
    [string]$Name = "aegis",
    [switch]$Onefile,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }

# ─────────────────────────────────────────────────────────── preflight
Step "Environment"
python --version
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "python not found on PATH" }
Write-Host "pyinstaller $(python -m PyInstaller --version 2>&1)"

$env:PYTHONPATH = $root
$env:PYTHONIOENCODING = "utf-8"

Step "Source tree must be clean before we freeze it"
python -m compileall -q aegis
if ($LASTEXITCODE -ne 0) { throw "compileall failed" }

if (-not $SkipTests) {
    # Unit/contract tests first. The smoke test proves the *package* works; pytest
    # proves the *code* does. A build that only ran the smoke test would happily
    # ship a regression that no packaging change touched.
    Write-Host "  pytest"
    python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "pytest failed - fix before packaging" }

    Write-Host "  ruff (correctness rules)"
    python -m ruff check . --select=E9,F --ignore=F401,F541,F403,F405
    if ($LASTEXITCODE -ne 0) { throw "ruff found correctness errors - fix before packaging" }

    Write-Host "  mypy"
    python -m mypy
    if ($LASTEXITCODE -ne 0) { throw "mypy failed - fix before packaging" }

    Write-Host "  source-tree smoke test"
    # No command argument: smoketest.py defaults to this interpreter running
    # `-m aegis`. Passing `python -m aegis` used to work only because the old
    # script forwarded every argv straight to subprocess; the argparse CLI now
    # rejects it as an unknown option, which is the behaviour we want.
    python smoketest.py
    if ($LASTEXITCODE -ne 0) { throw "source tree failed the smoke test - fix before packaging" }
}

# ─────────────────────────────────────────────────────────── build
$format = if ($Onefile) { "onefile" } else { "onedir" }
Step "Building $format -> $Name"
if ($Onefile) { Remove-Item Env:\AEGIS_ONEDIR -ErrorAction SilentlyContinue }
else { $env:AEGIS_ONEDIR = "1" }

$dist = if ($Onefile) { "dist" } else { "dist-od" }
$work = if ($Onefile) { "build" } else { "build-od" }

# Clean the previous artefact first. A onefile bundle left half-written by an
# interrupted build fails at launch with:
#   Failed to start embedded python interpreter:
#   failed to get the Python codec of the filesystem encoding
# which looks like a Python 3.14 incompatibility but is really a corrupt archive.
Remove-Item -Recurse -Force $dist -ErrorAction SilentlyContinue

python -m PyInstaller aegis.spec --noconfirm --clean --distpath $dist --workpath $work
if ($LASTEXITCODE -ne 0) { throw "pyinstaller failed" }

$exe = if ($Onefile) { "dist\$Name.exe" } else { "dist-od\$Name\$Name.exe" }
if (-not (Test-Path $exe)) { throw "expected $exe but it does not exist" }
if ($Onefile) {
    Write-Host "  built $exe  ($([math]::Round((Get-Item $exe).Length/1MB,1)) MB, $format)" -ForegroundColor Green
} else {
    $sz = (Get-ChildItem "dist-od\$Name" -Recurse -File | Measure-Object Length -Sum).Sum
    Write-Host "  built $exe  ($([math]::Round($sz/1MB,1)) MB on disk, $format)" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────── verify
if (-not $SkipTests) {
    Step "Post-build smoke test (frozen binary)"
    python smoketest.py $exe
    if ($LASTEXITCODE -ne 0) {
        throw "FROZEN BINARY FAILED THE SMOKE TEST - do not ship this build"
    }
}

Step "Done"
Write-Host "  $exe" -ForegroundColor Green
Write-Host "  Try:  .\$Name.exe coverage" -ForegroundColor Gray
Write-Host "        .\$Name.exe doctor" -ForegroundColor Gray
Write-Host "        .\$Name.exe scan all --repo ." -ForegroundColor Gray
