# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for AEGIS.

The important part of this file is `hiddenimports`. AEGIS declares its capability
providers as *strings* in aegis/core/catalog.py, e.g.
    "aegis.suites.s05_detection:defense_impairment_gap"
and resolves them at runtime with importlib.import_module() in
aegis/core/runner.py:resolve_native().

PyInstaller analyses imports statically, so it cannot see those string references.
Without the explicit hiddenimports below, a frozen build keeps catalog.py (a static
table) but loses every `aegis.suites.*` module, because resolve_native() actually
imports the handler to test it.

Measured with experiment_nohidden.spec (this spec minus the aegis.* hiddenimports,
single file, everything else identical):

    with hiddenimports    100.0% coverage, 133 runnable, 8/8 smoke test
    without hiddenimports   9.8% coverage,  13 runnable, scans nothing
                          102 capabilities report "native handler not importable"

The binary still starts and still prints a coverage report, so this fails quietly
to a human who only looks at the exit code. The coverage engine does surface it —
loudly — which is exactly the behaviour the ledger was designed for.

Build:
    pyinstaller aegis.spec --noconfirm --clean
Output:
    dist/aegis.exe
"""
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve()
sys.path.insert(0, str(ROOT))

# ── AEGIS's own modules ───────────────────────────────────────────────────────
# Every suite and core module, listed explicitly. Do not rely on static analysis.
aegis_hidden = [
    "aegis",
    "aegis.cli",
    "aegis.core",
    "aegis.core.catalog",
    "aegis.core.config",
    "aegis.core.deps",
    "aegis.core.dnsutil",
    "aegis.core.http",
    "aegis.core.ledger",
    "aegis.core.models",
    "aegis.core.render",
    "aegis.core.runner",
    "aegis.core.store",
    "aegis.core.util",
    "aegis.suites",
    "aegis.suites.s01_recon",
    "aegis.suites.s02_surface",
    "aegis.suites.s03_identity",
    "aegis.suites.s04_supplychain",
    "aegis.suites.s05_detection",
    "aegis.suites.s06_response",
    "aegis.suites.s07_aisec",
    "aegis.suites.s08_lab",
    "aegis.suites.s09_assure",
]

# ── Optional third-party dependencies ─────────────────────────────────────────
# These are imported inside functions with try/except, so PyInstaller will not see
# them. Bundle the ones that are cheap and useful; skip the heavy/optional ones.
# Remove any from this list and AEGIS degrades to its native fallbacks gracefully
# (every optional dep in this project has a working native path).
# IMPORTANT: these are *import* names, not distribution names. `dnspython` is a
# distribution that installs the module `dns`; bundling the distribution name
# produces a missing module inside the bundle.
#
# The list is read from aegis.core.deps, which is the single source of truth for
# the distribution -> import-name mapping. A second hand-maintained copy here is
# exactly how the dnspython/dns confusion reappears, so there is only one list.
opt_hidden = []
try:
    from aegis.core.deps import DEPENDENCIES
    _declared = sorted({m for d in DEPENDENCIES for m in d.imports})
except Exception:
    # Spec must still work if the package is not importable at build time.
    _declared = ["dns", "dns.resolver", "dns.reversename", "dns.query", "dns.zone",
                 "networkx", "yaml", "ldap3", "jinja2"]
for mod in _declared:
    try:
        __import__(mod)
        opt_hidden.append(mod)
    except Exception:
        pass

hiddenimports = aegis_hidden + opt_hidden + collect_submodules("requests")

# ── Data files ────────────────────────────────────────────────────────────────
datas = []
for pattern in ("sigma/**/*.yml", "templates/**/*"):
    for p in ROOT.glob(pattern):
        if p.is_file():
            datas.append((str(p.relative_to(ROOT)), str(p.relative_to(ROOT))))

analysis = Analysis(
    ["aegis_launcher.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Trim the bundle: these are large and unused by AEGIS.
    excludes=[
        "tkinter", "matplotlib", "numpy", "pandas", "scipy", "PIL",
        "IPython", "jupyter", "notebook", "pytest", "setuptools", "pip",
        "sqlite3.test", "test", "unittest", "pydoc_data",
        "lib2to3", "distutils", "curses", "asyncio.windows_events",
    ],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

# Output format. Onedir is the default and the recommended shipping format:
#
#   AEGIS_ONEDIR=1 (set by build.ps1)  ->  dist/aegis/aegis.exe  (+ _internal\)
#   otherwise                          ->  dist/aegis.exe       (single file)
#
# Measured on this machine, same spec, same interpreter:
#   onedir    ~420 ms cold start, 54.7 MB across 76 files
#   onefile  ~4650 ms cold start, 32.8 MB single file
#
# Onedir wins because onefile re-extracts the whole archive into %TEMP% on every
# launch, and because an unsigned ~33 MB self-extracting binary is a reliable way
# to get flagged by AV heuristics - a bad property for security tooling.
ONEDIR = os.environ.get("AEGIS_ONEDIR") == "1"

if ONEDIR:
    exe = EXE(
        pyz, analysis.scripts, [],
        exclude_binaries=True,
        name="aegis",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe, analysis.binaries, analysis.datas,
        strip=False, upx=False, upx_exclude=[],
        name="aegis",
    )
else:
    exe = EXE(
        pyz,
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        name="aegis",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,                 # UPX trips AV heuristics on security tooling
        upx_exclude=[],
        runtime_tmpdir=None,
        console=True,              # this is a CLI
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
        # icon=None,
    )

