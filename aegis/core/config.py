"""Configuration + filesystem layout."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ENV_PREFIX = "AEGIS_"


def _root() -> Path:
    for cand in (os.environ.get("AEGIS_HOME"),):
        if cand:
            return Path(cand).expanduser()
    return Path.home() / ".aegis"


@dataclass(slots=True)
class Config:
    home: Path
    data: Path
    runs: Path
    cache: Path
    bin: Path
    reports: Path
    scope_file: Path

    # network behaviour
    rate_limit: float = 6.0           # requests/sec per host
    timeout: float = 20.0
    max_retries: int = 2
    user_agent: str = "AEGIS/1.0 (defensive security assessment; +contact required)"
    respect_robots: bool = True

    # runtime
    use_docker: bool = True
    docker_image_prefix: str = ""
    pull_images: bool = False
    parallel: int = 8
    offline: bool = False

    # policy
    default_profile: str = "standard"
    allow_active_by_default: bool = True
    redact_secrets: bool = True

    # Optional enforcement, off by default. Flip these on when you want the tool to
    # refuse things rather than just report them.
    guardrails: dict[str, bool] = field(default_factory=lambda: {
        "require_scope_for_active": False,      # block active runs with no scope
        "block_nonlocal_targets": False,        # block out-of-scope hosts in http client
        "require_authorisation_record": False,  # require authorised_by/reference
    })

    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path | None = None) -> Config:
        home = _root()
        data = {
            "rate_limit": float(os.environ.get(ENV_PREFIX + "RATE", 6.0)),
            "timeout": float(os.environ.get(ENV_PREFIX + "TIMEOUT", 20.0)),
            "parallel": int(os.environ.get(ENV_PREFIX + "PARALLEL", 8)),
            "use_docker": os.environ.get(ENV_PREFIX + "DOCKER", "1") != "0",
            "pull_images": os.environ.get(ENV_PREFIX + "PULL", "0") == "1",
            "offline": os.environ.get(ENV_PREFIX + "OFFLINE", "0") == "1",
        }
        p = Path(path).expanduser() if path else home / "config.json"
        if p.exists():
            try:
                # utf-8-sig: Windows editors write a BOM, and a BOM makes json.loads
                # raise — which would silently discard the entire config file.
                data.update(json.loads(p.read_text(encoding="utf-8-sig")))
            except Exception as e:  # noqa: BLE001
                import sys
                print(f"aegis: ignoring unreadable config {p}: {e}", file=sys.stderr)
        home.mkdir(parents=True, exist_ok=True)
        cfg = cls(
            home=home,
            data=home / "data",
            runs=home / "runs",
            cache=home / "cache",
            bin=home / "bin",
            reports=home / "reports",
            scope_file=home / "scope.json",
            raw=data,
        )
        for d in (cfg.data, cfg.runs, cfg.cache, cfg.bin, cfg.reports):
            d.mkdir(parents=True, exist_ok=True)
        for k, v in data.items():
            if hasattr(cfg, k) and k not in ("home", "data", "runs", "cache", "bin",
                                              "reports", "scope_file"):
                setattr(cfg, k, v)
        return cfg

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, self.raw.get(key, default))

    def env_for(self, provider: Any) -> dict[str, str]:
        """Merge process env with any provider-specific requirements."""
        env = dict(os.environ)
        for k in getattr(provider, "env", {}) or {}:
            v = os.environ.get(k)
            if v is None:
                raise RuntimeError(f"missing required environment variable: {k}")
            env[k] = v
        return env
