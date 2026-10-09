"""DNS helpers built on dnspython, with a pure-socket fallback."""
from __future__ import annotations

import socket

try:
    import dns.resolver
    import dns.reversename
    _HAVE_DNSPY = True
except Exception:  # pragma: no cover
    _HAVE_DNSPY = False

RESOLVER = None
if _HAVE_DNSPY:
    RESOLVER = dns.resolver.Resolver()
    RESOLVER.timeout = 5
    RESOLVER.lifetime = 6
    try:
        RESOLVER.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    except Exception:
        pass


def _q(name: str, rtype: str) -> list[str]:
    if not _HAVE_DNSPY or RESOLVER is None:
        return []
    try:
        ans = RESOLVER.resolve(name, rtype, raise_on_no_answer=False)
        return [str(r).strip(".") for r in ans]
    except Exception:
        return []


def resolve(name: str, rtype: str = "A") -> list[str]:
    if _HAVE_DNSPY:
        return _q(name, rtype)
    try:
        if rtype in ("A", "AAAA"):
            infos = socket.getaddrinfo(name, None)
            # sockaddr[0] is a str for AF_INET/AF_INET6 but can be a number for
            # other families, so coerce rather than pretending it is always str.
            return sorted({str(i[4][0]) for i in infos})
    except Exception:
        pass
    return []


def a(name: str) -> list[str]:
    return resolve(name, "A")


def aaaa(name: str) -> list[str]:
    return resolve(name, "AAAA")


def cname(name: str) -> list[str]:
    return resolve(name, "CNAME")


def ns(name: str, rtype: str = "NS") -> list[str]:
    return resolve(name, rtype)


def mx(name: str, rtype: str = "MX") -> list[str]:
    return resolve(name, rtype)


def txt(name: str, rtype: str = "TXT") -> list[str]:
    raw = _q(name, rtype)
    out = []
    for r in raw:
        out.append(r.strip('"'))
    return out


def soa(name: str) -> list[str]:
    return _q(name, "SOA")


def ptr(ip: str) -> list[str]:
    if not _HAVE_DNSPY:
        return []
    try:
        rev = dns.reversename.from_address(ip)
        return _q(str(rev), "PTR")
    except Exception:
        return []


def wildcard_probe(domain: str, sub: str = "aegis-wildcard-probe-9f3b") -> bool:
    """True if a random label resolves → the zone is wildcarded, so brute force is useless."""
    return bool(resolve(f"{sub}.{domain}", "A"))


def has_mx(domain: str) -> bool:
    return bool(mx(domain))
