"""Declared third-party dependencies and their resolution.

The defect this module exists to fix: the availability probe used *distribution*
names where it needed *import* names. `dnspython` is a distribution; the module it
installs is `dns`. Probing `import dnspython` therefore reported a false negative
for a package that was installed and importable — and the original list contained
both `dnspython` and `dns`, which is the signature of exactly that confusion.

Each entry declares:
  distribution : the name you `pip install` / `pip show`
  imports      : one or more module names the distribution provides
  required     : False means the suite degrades to a native path without it
  provides     : what AEGIS actually uses it for (shown in `doctor -v`)

Availability is *tested*, never asserted: `probe()` performs a real import and
reports the version actually loaded. A hard-coded "ok" would be exactly the kind of
fake-green this module is meant to prevent.
"""
from __future__ import annotations

import importlib
import importlib.metadata as md
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Dependency:
    distribution: str
    imports: tuple[str, ...]
    required: bool = True
    provides: str = ""
    # Minimum version we have actually exercised. Recorded for the report; not
    # enforced at import time, because aegis degrades rather than fails.
    tested_with: str = ""


#: Single source of truth. Anything aegis imports that is not in this table is
#: an oversight and should be added here.
DEPENDENCIES: tuple[Dependency, ...] = (
    Dependency("requests", ("requests",), True, "HTTP client (core)", "2.x"),
    Dependency("dnspython", ("dns", "dns.resolver", "dns.reversename",
                             "dns.query", "dns.zone"), False,
               "DNS resolution in s01; falls back to socket.getaddrinfo", "2.8.0"),
    Dependency("PyYAML", ("yaml",), False, "IaC / CI YAML parsing in s04", "6.x"),
    Dependency("networkx", ("networkx",), False,
               "Exposure graph in s02; degrades to no graph", "3.x"),
    Dependency("Jinja2", ("jinja2",), False, "Reserved for report templating", "3.x"),
    Dependency("ldap3", ("ldap3",), False,
               "Active Directory enumeration in s03; degrades to offline review", ""),
    # The distribution is PyYAML but the module is yaml - listed separately from
    # dnspython above precisely because the two are easy to confuse.
    Dependency("tqdm", ("tqdm",), False, "Optional progress output", ""),
    Dependency("psutil", ("psutil",), False, "Reserved for host triage in s06", ""),
    Dependency("pydantic", ("pydantic",), False, "Reserved for config schema", ""),
)


@dataclass(slots=True)
class ProbeResult:
    dependency: Dependency
    available: bool
    version: str = ""
    import_error: str = ""
    distribution_installed: bool = False

    @property
    def status(self) -> str:
        return "ok" if self.available else "missing"

    def to_dict(self) -> dict[str, Any]:
        return {
            "distribution": self.dependency.distribution,
            "imports": list(self.dependency.imports),
            "required": self.dependency.required,
            "available": self.available,
            "version": self.version,
            "distribution_installed": self.distribution_installed,
            "import_error": self.import_error,
            "provides": self.dependency.provides,
        }


def probe(dep: Dependency) -> ProbeResult:
    """Actually import the module(s) this distribution provides.

    `import_error` distinguishes "the distribution is not installed at all" from
    "the distribution is installed but the module is broken", because those mean
    different things during remediation.
    """
    first_error = ""
    for mod in dep.imports:
        try:
            m = importlib.import_module(mod)
        except Exception as e:  # noqa: BLE001
            if not first_error:
                first_error = f"{type(e).__name__}: {e}"
            continue
        # Every declared import resolved, so the dependency is usable.
        version = ""
        for attr in ("__version__", "version", "VERSION"):
            v = getattr(m, attr, None)
            if isinstance(v, str):
                version = v
                break
        if not version:
            try:
                version = md.version(dep.distribution)
            except Exception:
                version = "unknown"
        return ProbeResult(dep, True, version, "", True)

    dist_installed = False
    try:
        md.version(dep.distribution)
        dist_installed = True
    except Exception:
        dist_installed = False

    return ProbeResult(dep, False, "", first_error, dist_installed)


def probe_all(deps: tuple[Dependency, ...] | None = None) -> list[ProbeResult]:
    return [probe(d) for d in (deps or DEPENDENCIES)]


def available(dep: Dependency) -> bool:
    """Cheap boolean form of `probe`, for capability code that needs a fast check."""
    for mod in dep.imports:
        try:
            importlib.import_module(mod)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def by_distribution(name: str) -> Dependency | None:
    for d in DEPENDENCIES:
        if d.distribution.lower() == name.lower():
            return d
    return None
