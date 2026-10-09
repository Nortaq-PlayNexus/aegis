"""The coverage ledger.

Resolves every catalogued capability against the current environment and
computes COVERED / DEGRADED / MANUAL / UNCOVERED. The UNCOVERED list is the
contract: it is a real gap and `aegis coverage` fails while it is non-empty.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Iterable

from .catalog import CATALOG
from .config import Config
from .models import (Capability, Coverage, Phase, Provider, ProviderKind,
                     ResolvedCapability, ResolvedProvider)
from .runner import resolve


@dataclass(slots=True)
class Gap:
    key: str
    title: str
    domain: str
    phase: str
    reason: str
    remedy: str
    priority: str = "normal"
    #: The Coverage state that produced this gap: "uncovered", "degraded" or
    #: "manual". Lets consumers distinguish "no implementation exists" from
    #: "a manual/licensed path is the only one" without string-matching `reason`.
    reason_kind: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key, "title": self.title, "domain": self.domain,
            "phase": self.phase, "reason": self.reason, "remedy": self.remedy,
            "priority": self.priority, "reason_kind": self.reason_kind,
        }


@dataclass(slots=True)
class PlanEntry:
    """One runnable capability, with the provider information callers need.

    This was previously a class nested inside `Ledger.active_plan()`. It is now a
    proper module-level type because callers need to consume it: `cmd_inventory`
    reads `resolved_ref`, which lives on `ResolvedProvider` and therefore belongs
    behind `entry.resolved` rather than being duplicated as a dummy field here.
    """

    capability: Capability
    providers: list[ResolvedProvider] = field(default_factory=list)

    @property
    def resolved(self) -> ResolvedProvider:
        """The primary runnable provider. Callers that need a real path,
        version or resolution reason must go through this."""
        for p in self.providers:
            if p.runnable:
                return p
        raise LookupError(
            f"{self.capability.key} has no runnable provider; "
            "PlanEntry should only be constructed for runnable capabilities")

    @property
    def provider(self) -> Provider:
        return self.resolved.provider

    @property
    def native_refs(self) -> list[str]:
        """All runnable native handler refs, for callers that fan out.

        A capability may declare several native implementations that each
        contribute findings (malicious_package_scan has both a package-behaviour
        analyser and an invisible-unicode detector).
        """
        return [p.provider.ref for p in self.providers
                if p.runnable and p.provider.kind is ProviderKind.NATIVE]

    @property
    def is_native(self) -> bool:
        return bool(self.native_refs)


@dataclass(slots=True)
class Ledger:
    config: Config
    entries: list[ResolvedCapability] = field(default_factory=list)

    # ------------------------------------------------------------------ build
    @classmethod
    def build(cls, config: Config, only: Iterable[str] | None = None) -> Ledger:
        onlyset = {o.lower() for o in only} if only else None
        led = cls(config=config)
        for cap in CATALOG:
            if onlyset and cap.id.lower() not in onlyset and cap.domain.value.lower() not in onlyset:
                continue
            rps = [resolve(p, config) for p in cap.providers]
            runnable = [r for r in rps if r.runnable]
            if runnable:
                cov = Coverage.COVERED
            elif any(r.provider.kind.value == "manual" for r in rps):
                cov = Coverage.MANUAL
            elif rps:
                cov = Coverage.DEGRADED
            else:
                cov = Coverage.UNCOVERED
            notes = ""
            if not rps:
                notes = "no provider declared — this is a design gap"
            led.entries.append(ResolvedCapability(capability=cap, coverage=cov,
                                                  providers=rps, notes=notes))
        return led

    # ------------------------------------------------------------------ queries
    def get(self, cap_id: str) -> ResolvedCapability | None:
        for e in self.entries:
            if e.capability.id == cap_id or e.capability.key == cap_id:
                return e
        return None

    def by_domain(self) -> dict[str, list[ResolvedCapability]]:
        out: dict[str, list[ResolvedCapability]] = defaultdict(list)
        for e in self.entries:
            out[e.capability.domain.value].append(e)
        return dict(out)

    def counts(self) -> dict[str, int]:
        c: dict[str, int] = {k.value: 0 for k in Coverage}
        for e in self.entries:
            c[e.coverage.value] += 1
        return c

    # Reporting order for gaps: no implementation is worse than a declared-but-
    # unavailable provider, which is worse than a manual/licensed-only path.
    _GAP_RANK = {"uncovered": 0, "degraded": 1, "manual": 2}

    def gaps(self) -> list[Gap]:
        """Every capability that is not COVERED right now, in this environment.

        All three non-covered states are reported: UNCOVERED (no implementation),
        DEGRADED (implementation declared but not runnable here) and MANUAL (only
        a manual/licensed path exists).

        MANUAL used to be omitted, which produced a self-contradictory report:
        `coverage_pct()` correctly read 99.2 while `gaps()` returned [] and
        `complete()` returned True, so `aegis coverage` exited 0 and `aegis doctor`
        exited 0 with a capability that could not run unattended. A manual-only
        capability is by definition an unattended gap, so it belongs here.
        """
        out: list[Gap] = []
        prio = {"s05_detection": "high", "s04_supplychain": "high",
                "s03_identity": "high", "s07_aisec": "high", "s06_response": "high"}
        for e in self.entries:
            if e.coverage is Coverage.COVERED:
                continue
            if e.coverage is Coverage.UNCOVERED:
                out.append(Gap(
                    key=e.capability.key, title=e.capability.title,
                    domain=e.capability.domain.value, phase=e.capability.phase.value,
                    reason="no implementation exists",
                    remedy="write a native provider: aegis.suites.<mod>:check_*",
                    priority=prio.get(e.capability.domain.value, "normal"),
                    reason_kind=Coverage.UNCOVERED.value,
                ))
                continue
            # Pick the provider that actually explains this state, not providers[0].
            # For MANUAL the actionable reason is that the only remaining path is a
            # manual/licensed one; reporting providers[0] (e.g. "offline mode")
            # would name an incidental blocker rather than the real one.
            if e.coverage is Coverage.MANUAL:
                rp = next((p for p in e.providers
                           if p.provider.kind is ProviderKind.MANUAL),
                          e.providers[0] if e.providers else None)
            else:
                rp = e.providers[0] if e.providers else None
            reason = rp.reason if rp else "unresolved"
            if e.coverage is Coverage.MANUAL and not reason:
                reason = "manual / licensed path only"
            remedy = ""
            if rp is not None and rp.provider.install:
                remedy = rp.provider.install
            elif rp is not None and rp.provider.notes:
                remedy = rp.provider.notes
            elif e.coverage is Coverage.MANUAL:
                remedy = ("no unattended provider; run the manual procedure or "
                          "provision one of the unavailable providers above")
            else:
                remedy = "see provider notes"
            out.append(Gap(
                key=e.capability.key, title=e.capability.title,
                domain=e.capability.domain.value, phase=e.capability.phase.value,
                reason=reason, remedy=remedy,
                priority=prio.get(e.capability.domain.value, "normal"),
                reason_kind=e.coverage.value,
            ))
        out.sort(key=lambda g: (0 if g.priority == "high" else 1,
                                self._GAP_RANK.get(g.reason_kind, 3),
                                g.domain, g.key))
        return out

    def hard_gaps(self) -> list[Gap]:
        return [g for g in self.gaps() if g.reason == "no implementation exists"]

    def dead_natives(self) -> list[dict[str, str | None]]:
        """Native providers whose handler is not importable.

        Deliberately *not* a gap. A capability can have a broken native handler and
        still be COVERED via a runnable docker/local/remote provider — coverage
        stays 100% and the dead code silently never runs. That blind spot is
        exactly what this method exists to surface, so a typo in a handler name
        cannot hide behind a healthy fallback provider.
        """
        out: list[dict[str, str | None]] = []
        for e in self.entries:
            for p in e.providers:
                if p.provider.kind.value != "native" or p.runnable:
                    continue
                out.append({
                    "capability": e.capability.key,
                    "ref": p.provider.ref,
                    "reason": p.reason or "handler not importable",
                    # None when nothing else covers this capability either: the
                    # dead handler is then the only reason it cannot run.
                    "masked_by": (e.best.provider.kind.value if e.best else None),
                })
        return out

    def coverage_pct(self) -> float:
        if not self.entries:
            return 100.0
        cov = sum(1 for e in self.entries if e.coverage is Coverage.COVERED)
        return round(100.0 * cov / len(self.entries), 1)

    def complete(self) -> bool:
        """True only when nothing is uncovered and nothing is degraded."""
        return not self.gaps()

    def runnable(self, cap_id: str) -> ResolvedCapability | None:
        e = self.get(cap_id)
        return e if (e and e.best) else None

    def active_plan(self) -> list[tuple[Capability, PlanEntry]]:
        """Every capability with a runnable provider, in phase order.

        Returns `(capability, PlanEntry)` pairs. Use `entry.resolved` for the
        primary `ResolvedProvider`, `entry.native_refs` to fan out across sibling
        native handlers.
        """
        order = {p: i for i, p in enumerate(Phase)}
        plan: list[tuple[Capability, PlanEntry]] = []
        for e in sorted(self.entries, key=lambda x: (order.get(x.capability.phase, 99),
                                                     x.capability.domain.value,
                                                     x.capability.id)):
            if e.best:
                plan.append((e.capability, PlanEntry(e.capability, list(e.providers))))
        return plan

    # ------------------------------------------------------------------ serialise
    def to_dict(self, include_gaps: bool = True) -> dict[str, Any]:
        by_d = self.by_domain()
        d: dict[str, Any] = {
            "generated": __import__("time").time(),
            "total": len(self.entries),
            "counts": self.counts(),
            "coverage_pct": self.coverage_pct(),
            "complete": self.complete(),
            "domains": {
                dom: {
                    "label": _domain_label(dom),
                    "covered": sum(1 for e in v if e.coverage is Coverage.COVERED),
                    "total": len(v),
                    "capabilities": [e.to_dict() for e in v],
                }
                for dom, v in sorted(by_d.items())
            },
        }
        if include_gaps:
            d["gaps"] = [g.to_dict() for g in self.gaps()]
            d["hard_gap_count"] = len(self.hard_gaps())
            d["dead_natives"] = self.dead_natives()
        return d


_DOMAIN_LABELS = {
    "s01_recon": "S01 Reconnaissance",
    "s02_surface": "S02 Attack Surface",
    "s03_identity": "S03 Identity & AD",
    "s04_supplychain": "S04 Supply Chain",
    "s05_detection": "S05 Detection Engineering",
    "s06_response": "S06 Response & DFIR",
    "s07_aisec": "S07 AI Security",
    "s08_lab": "S08 Lab & Emulation",
    "s09_assure": "S09 Assurance & Compliance",
    "s00_core": "S00 Core",
}


def _domain_label(k: str) -> str:
    return _DOMAIN_LABELS.get(k, k)
