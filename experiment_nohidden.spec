# -*- mode: python ; coding: utf-8 -*-
"""CONTROL EXPERIMENT - do not ship this.

Identical to aegis.spec EXCEPT the AEGIS hiddenimports are removed. Its only
purpose is to answer one question with evidence rather than assertion:

    Does a onefile build without hiddenimports start, report 100% coverage,
    and then scan nothing?

If yes, the hiddenimports in aegis.spec are load-bearing and the spec is
justified. If the binary fails identically to a clean naive build, then
the earlier failure was bundle corruption and the spec's real value is only
its `excludes` list (size, not correctness).

Everything else - excludes, binaries, datas, options - is byte-identical to
aegis.spec so the only variable is the hiddenimports.
"""
import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).resolve()
sys.path.insert(0, str(ROOT))

# The variable under test: NO aegis.* hiddenimports at all.
opt_hidden = []
for mod in ("dns", "dns.resolver", "dns.reversename", "dns.query", "dns.zone",
            "networkx", "yaml", "ldap3", "jinja2"):
    try:
        __import__(mod)
        opt_hidden.append(mod)
    except Exception:
        pass

hiddenimports = opt_hidden + collect_submodules("requests")

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
    hiddenimports=hiddenimports,          # <-- aegis.* deliberately absent
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter", "matplotlib", "numpy", "pandas", "scipy", "PIL",
        "IPython", "jupyter", "notebook", "pytest", "setuptools", "pip",
        "sqlite3.test", "test", "unittest", "pydoc_data",
        "lib2to3", "distutils", "curses", "asyncio.windows_events",
    ],
    noarchive=False,
)

pyz = PYZ(analysis.pure)
exe = EXE(
    pyz, analysis.scripts, analysis.binaries, analysis.datas, [],
    name="aegis-nohidden",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=True, disable_windowed_traceback=False, argv_emulation=False,
    target_arch=None, codesign_identity=None, entitlements_file=None,
)
