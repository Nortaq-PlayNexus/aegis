"""Polite HTTP client.

Cached, rate-limited, retried, and scope-aware. Every outbound request in AEGIS
goes through here so that politeness and scope enforcement are not optional.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass(slots=True)
class Response:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed: float
    from_cache: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400 and not self.error

    def json(self, default: Any = None) -> Any:
        try:
            return json.loads(self.text)
        except Exception:
            return default if default is not None else {}

    @property
    def tech(self) -> list[str]:
        t = []
        h = self.headers
        for k in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            if h.get(k):
                t.append(h[k])
        return t

    @property
    def title(self) -> str:
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", self.text or "", re.I | re.S)
        return (m.group(1).strip()[:120] if m else "")


class RateLimiter:
    """Per-host token bucket. No global thundering herd."""

    def __init__(self, per_second: float = 6.0, burst: int = 6):
        self.rate = max(0.1, per_second)
        self.burst = burst
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, key: str) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                prev = self._last.get(key, 0.0)
                gap = 1.0 / self.rate
                delta = now - prev
                if delta >= gap:
                    self._last[key] = now
                    return
                sleep_for = gap - delta
            time.sleep(sleep_for)


class HttpClient:
    def __init__(self, config: Any, scope: Any = None, cache_dir: Any = None,
                 cache_ttl: int = 3600, enforce_scope: bool = False):
        self.cfg = config
        self.scope = scope
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        # Scope is advisory unless enforcement is switched on in config.
        self.enforce_scope = enforce_scope
        self.limiter = RateLimiter(getattr(config, "rate_limit", 6.0))
        self._mem: dict[str, Response] = {}
        self.s = requests.Session()
        retry = Retry(total=getattr(config, "max_retries", 2),
                      backoff_factor=0.4,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset({"GET", "HEAD"}),
                      respect_retry_after_header=True)
        adapter = HTTPAdapter(max_retries=retry, pool_connections=32, pool_maxsize=32)
        self.s.mount("https://", adapter)
        self.s.mount("http://", adapter)
        self.s.headers.update({
            "User-Agent": getattr(config, "user_agent", "AEGIS/1.0"),
            "Accept": "*/*",
            "Accept-Language": "en",
        })
        self.stats = {"requests": 0, "cached": 0, "errors": 0, "blocked": 0, "bytes": 0}

    # ------------------------------------------------------------------ scope
    def allowed(self, url: str) -> bool:
        if not self.enforce_scope:
            return True
        if self.scope is None:
            return True
        if getattr(self.scope, "is_empty", lambda: True)():
            return True
        host = urlparse(url).hostname or ""
        return self.scope.allows_host(host)

    # ------------------------------------------------------------------ cache
    def _cache_path(self, url: str, body: str | None):
        if not self.cache_dir:
            return None
        try:
            from pathlib import Path
            h = hashlib.sha256((url + (body or "")).encode()).hexdigest()[:32]
            d = Path(self.cache_dir) / "http"
            d.mkdir(parents=True, exist_ok=True)
            return d / f"{h}.json.gz"
        except Exception:
            return None

    def _cache_get(self, url: str, body: str | None) -> Response | None:
        key = url + "|" + (body or "")
        if key in self._mem:
            return self._mem[key]
        p = self._cache_path(url, body)
        if not p or not p.exists():
            return None
        try:
            if (time.time() - p.stat().st_mtime) > self.cache_ttl:
                return None
            import gzip
            data = json.loads(gzip.decompress(p.read_bytes()).decode())
            r = Response(url=data["url"], status=data["status"],
                         headers=data["headers"], text=data.get("text", "")[:200_000],
                         elapsed=0.0, from_cache=True)
            self._mem[key] = r
            self.stats["cached"] += 1
            return r
        except Exception:
            return None

    def _cache_put(self, r: Response, body: str | None) -> None:
        key = r.url + "|" + (body or "")
        self._mem[key] = r
        p = self._cache_path(r.url, body)
        if not p:
            return
        try:
            import gzip
            p.write_bytes(gzip.compress(json.dumps({
                "url": r.url, "status": r.status, "headers": r.headers,
                "text": (r.text or "")[:400_000],
            }).encode()))
        except Exception:
            pass

    # ------------------------------------------------------------------ get
    def get(self, url: str, headers: dict[str, str] | None = None,
            params: dict[str, Any] | None = None, timeout: float | None = None,
            allow_redirects: bool = True, data: Any = None) -> Response:
        if not self.allowed(url):
            self.stats["blocked"] += 1
            return Response(url=url, status=0, headers={}, text="", elapsed=0.0,
                            error=f"blocked by scope: {urlparse(url).hostname}")
        cached = self._cache_get(url, json.dumps(params, sort_keys=True) if params else None)
        if cached:
            return cached

        host = urlparse(url).hostname or "*"
        self.limiter.wait(host)
        t0 = time.time()
        self.stats["requests"] += 1
        try:
            resp = self.s.get(url, headers=headers, params=params, timeout=timeout or getattr(self.cfg, "timeout", 20),
                              allow_redirects=allow_redirects, verify=False, data=data)
            r = Response(url=resp.url, status=resp.status_code,
                         headers={k.lower(): v for k, v in resp.headers.items()},
                         text=resp.text[:400_000], elapsed=time.time() - t0)
            self.stats["bytes"] += len(r.text)
            self._cache_put(r, json.dumps(params, sort_keys=True) if params else None)
            return r
        except requests.RequestException as e:
            self.stats["errors"] += 1
            return Response(url=url, status=0, headers={}, text="", elapsed=time.time() - t0,
                            error=f"{type(e).__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            self.stats["errors"] += 1
            return Response(url=url, status=0, headers={}, text="", elapsed=time.time() - t0,
                            error=str(e))

    def head(self, url: str, timeout: float | None = None) -> Response:
        r = self.get(url, timeout=timeout)
        return r

    def post_json(self, url: str, payload: Any, headers: dict[str, str] | None = None,
                  timeout: float | None = None) -> Response:
        if not self.allowed(url):
            return Response(url=url, status=0, headers={}, text="", elapsed=0.0,
                            error="blocked by scope")
        host = urlparse(url).hostname or "*"
        self.limiter.wait(host)
        t0 = time.time()
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        try:
            resp = self.s.post(url, json=payload, headers=h,
                               timeout=timeout or getattr(self.cfg, "timeout", 20), verify=False)
            self.stats["requests"] += 1
            return Response(url=resp.url, status=resp.status_code,
                            headers={k.lower(): v for k, v in resp.headers.items()},
                            text=resp.text[:200_000], elapsed=time.time() - t0)
        except Exception as e:  # noqa: BLE001
            self.stats["errors"] += 1
            return Response(url=url, status=0, headers={}, text="", elapsed=time.time() - t0,
                            error=str(e))

    def close(self) -> None:
        try:
            self.s.close()
        except Exception:
            pass
