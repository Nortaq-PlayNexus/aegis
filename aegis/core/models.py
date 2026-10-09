"""AEGIS — data models.

Everything that crosses a module boundary is one of these types. Findings are the
currency; providers are the mechanism; the ledger is the map.
"""
from __future__ import annotations

import dataclasses
import enum
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------- enums
class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    OK = "ok"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]

    @property
    def score(self) -> float:
        """CVSS-ish weight used for risk rollups."""
        return _SEV_SCORE[self]

    def __lt__(self, other: object) -> bool:
        """Sort support: ordering is INVERTED, so CRITICAL sorts first.

        Severity subclasses str, so `str.__lt__` is part of the contract and mypy
        correctly flags a `Severity`-only annotation as a Liskov violation. This
        accepts `object` and defers to the inherited string comparison for
        anything that is not a Severity, so comparing against a plain string still
        behaves as a string comparison rather than raising.

        Callers that want rank order use `.rank` or `.score` explicitly; this
        ordering exists for `sorted(findings, key=...)` conveniences.
        """
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented


_SEV_RANK = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
             Severity.LOW: 2, Severity.INFO: 1, Severity.OK: 0}
_SEV_SCORE = {Severity.CRITICAL: 10.0, Severity.HIGH: 7.0, Severity.MEDIUM: 4.0,
              Severity.LOW: 1.5, Severity.INFO: 0.2, Severity.OK: 0.0}


class Domain(str, enum.Enum):
    """Suite domain keys. One per suite module."""
    RECON = "s01_recon"
    SURFACE = "s02_surface"
    IDENTITY = "s03_identity"
    SUPPLYCHAIN = "s04_supplychain"
    DETECTION = "s05_detection"
    RESPONSE = "s06_response"
    AISEC = "s07_aisec"
    LAB = "s08_lab"
    ASSURE = "s09_assure"
    CORE = "s00_core"


class Phase(str, enum.Enum):
    """Kill-chain phase a capability supports."""
    PREPARE = "prepare"
    RECON = "recon"
    ENUMERATE = "enumerate"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    PERSIST = "persist"
    DETECT = "detect"
    RESPOND = "respond"
    RECOVER = "recover"
    ASSURE = "assure"


class ProviderKind(str, enum.Enum):
    NATIVE = "native"    # implemented in this repo
    DOCKER = "docker"    # run via container image
    LOCAL = "local"      # run local binary
    REMOTE = "remote"    # HTTP API / data source
    MANUAL = "manual"    # human or licensed account required


class Coverage(str, enum.Enum):
    COVERED = "covered"        # >=1 runnable provider now
    DEGRADED = "degraded"      # provider declared but not currently runnable
    MANUAL = "manual"          # only manual/licensed path exists
    UNCOVERED = "uncovered"    # no implementation at all -> a real gap


class Status(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    SKIP = "skip"
    INFO = "info"


# --------------------------------------------------------------------------- providers
@dataclass(slots=True)
class Provider:
    """One way to satisfy a capability."""
    kind: ProviderKind
    ref: str                       # image ref, binary name, API id, or function path
    summary: str = ""
    install: str = ""              # human command that makes this runnable
    version: str = ""
    requires: list[str] = field(default_factory=list)   # capability ids this depends on
    env: dict[str, str] = field(default_factory=dict)   # required env keys
    privileged: bool = False        # needs docker --privileged / root
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------- capabilities
@dataclass(slots=True)
class Capability:
    """A declared capability in the catalog. One row = one gap candidate."""
    id: str
    title: str
    domain: Domain
    phase: Phase
    summary: str = ""
    providers: list[Provider] = field(default_factory=list)
    attack_ids: list[str] = field(default_factory=list)   # MITRE ATT&CK technique ids
    controls: list[str] = field(default_factory=list)    # CIS / NIST / CMMC refs
    default_active: bool = False     # requires explicit opt-in to run actively
    inputs: list[str] = field(default_factory=list)      # accepted input kinds
    outputs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.domain.value}.{self.id}"


@dataclass(slots=True)
class ResolvedProvider:
    """A provider after environment resolution."""
    provider: Provider
    runnable: bool
    reason: str = ""
    resolved_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = self.provider.to_dict()
        d["runnable"] = self.runnable
        d["reason"] = self.reason
        d["resolved_ref"] = self.resolved_ref
        return d


@dataclass(slots=True)
class ResolvedCapability:
    capability: Capability
    coverage: Coverage
    providers: list[ResolvedProvider] = field(default_factory=list)
    notes: str = ""

    @property
    def runnable_providers(self) -> list[ResolvedProvider]:
        return [p for p in self.providers if p.runnable]

    @property
    def best(self) -> ResolvedProvider | None:
        rp = self.runnable_providers
        return rp[0] if rp else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.capability.key,
            "id": self.capability.id,
            "title": self.capability.title,
            "domain": self.capability.domain.value,
            "phase": self.capability.phase.value,
            "summary": self.capability.summary,
            "coverage": self.coverage.value,
            "attack_ids": self.capability.attack_ids,
            "controls": self.capability.controls,
            "default_active": self.capability.default_active,
            "tags": self.capability.tags,
            "references": self.capability.references,
            "providers": [p.to_dict() for p in self.providers],
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- findings
@dataclass(slots=True)
class Evidence:
    """A single piece of proof. Keeps findings auditable."""
    kind: str            # http | dns | cert | banner | file | pcap | log | config | output
    summary: str
    locator: str = ""    # url, ip, path, fqdn
    excerpt: str = ""
    raw: str = ""        # optional raw payload, truncated on write

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(slots=True)
class Finding:
    """The unit of output. Deduped on fingerprint."""
    capability: str                 # capability key
    title: str
    severity: Severity
    target: str = ""
    detail: str = ""
    remediation: str = ""
    attack_ids: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    confidence: str = "medium"     # low | medium | high | confirmed
    cwe: str = ""
    cvss: float | None = None
    suite_run: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    @property
    def fingerprint(self) -> str:
        raw = "|".join([
            self.capability, self.title.lower().strip(), self.target.lower().strip(),
            str(sorted(self.tags)), self.detail[:160].lower(),
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "capability": self.capability,
            "title": self.title,
            "severity": self.severity.value,
            "target": self.target,
            "detail": self.detail,
            "remediation": self.remediation,
            "attack_ids": self.attack_ids,
            "evidence": [e.to_dict() for e in self.evidence],
            "tags": self.tags,
            "refs": self.refs,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "suite_run": self.suite_run,
            "meta": self.meta,
            "ts": self.ts,
        }


# --------------------------------------------------------------------------- run context
@dataclass(slots=True)
class Scope:
    """Authorised target boundary. Active checks validate against this."""
    domains: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    cloud: list[str] = field(default_factory=list)
    authorised_by: str = ""
    reference: str = ""
    expires: str = ""
    allow_active: bool = False

    def allows_host(self, host: str) -> bool:
        import ipaddress
        h = (host or "").strip().lower()
        if not h:
            return False
        for d in self.domains:
            d = d.lstrip("*.").lower()
            if h == d or h.endswith("." + d):
                return True
        for hh in self.hosts:
            if h == hh.lower():
                return True
        for cidr in self.cidrs:
            try:
                if ipaddress.ip_address(h) in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def is_empty(self) -> bool:
        return not (self.domains or self.hosts or self.cidrs or self.repos or self.cloud)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(slots=True)
class RunContext:
    """Everything a check needs, passed explicitly. No globals."""
    scope: Scope
    profile: str = "standard"        # quick | standard | deep
    active: bool = False
    run_id: str = ""
    workdir: Any = None              # Path
    config: Any = None               # Config
    opts: dict[str, Any] = field(default_factory=dict)
    http: Any = None                 # HttpClient
    store: Any = None                # Store
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def emit(self, f: Finding) -> Finding:
        f.suite_run = self.run_id
        if not f.attack_ids:
            f.attack_ids = self.opts.get("_attack_ids", [])
        self.findings.append(f)
        return f

    def note(self, msg: str) -> None:
        self.notes.append(msg)

    def opt(self, key: str, default: Any = None) -> Any:
        return self.opts.get(key, default)
