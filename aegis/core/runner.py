"""Provider resolution + subprocess/container execution.

This is the load-bearing piece. A capability is only "covered" if a provider can be
made runnable *here* — a local binary, a pullable container, a reachable API, or a
native function. Resolution is recorded, never assumed.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .models import Provider, ProviderKind, ResolvedProvider
from .util import run as _run, which, which_any

# ---------------------------------------------------------------- docker state
_DOCKER_OK: bool | None = None
_DOCKER_IMAGES: set[str] | None = None


def docker_available() -> bool:
    global _DOCKER_OK
    if _DOCKER_OK is None:
        _DOCKER_OK = which("docker") is not None
    return _DOCKER_OK


def docker_images() -> set[str]:
    """Lazily load local image names (repo:tag form)."""
    global _DOCKER_IMAGES
    if _DOCKER_IMAGES is None:
        _DOCKER_IMAGES = set()
        if docker_available():
            rc, out, _ = _run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                              timeout=45)
            if rc == 0:
                for line in out.splitlines():
                    line = line.strip()
                    if line and line != "<none>:<none>":
                        _DOCKER_IMAGES.add(line)
    return _DOCKER_IMAGES


def image_present(ref: str) -> bool:
    imgs = docker_images()
    if ref in imgs:
        return True
    # match on repository regardless of tag
    repo = ref.split(":")[0]
    return any(i.split(":")[0] == repo for i in imgs)


def _docker_pull_ok(ref: str, timeout: float = 300) -> bool:
    rc, _, _ = _run(["docker", "pull", "-q", ref], timeout=timeout)
    if rc == 0:
        docker_images()  # refresh
        return True
    return False


# ---------------------------------------------------------------- native registry
NATIVE: dict[str, Any] = {}


def native(ref: str) -> Provider:
    """Declare a provider implemented inside this package.

    `ref` is "module.path:function" resolvable from the aegis.suites package.
    """
    p = Provider(kind=ProviderKind.NATIVE, ref=ref, summary="built into AEGIS")
    NATIVE[ref] = p
    return p


def resolve_native(ref: str) -> bool:
    mod_path, _, fn = ref.partition(":")
    if not fn:
        return False
    try:
        import importlib
        mod = importlib.import_module(mod_path)
        if not hasattr(mod, fn):
            return False
        return callable(getattr(mod, fn))
    except Exception:
        return False


# ---------------------------------------------------------------- resolution
def resolve(provider: Provider, cfg: Config) -> ResolvedProvider:
    """Decide whether a provider is runnable right now, and say why not if it isn't."""
    kind = provider.kind

    if kind is ProviderKind.NATIVE:
        ok = resolve_native(provider.ref)
        return ResolvedProvider(
            provider, ok,
            "" if ok else "native handler not importable",
            provider.ref,
        )

    if kind is ProviderKind.LOCAL:
        path = which(provider.ref)
        if path:
            return ResolvedProvider(provider, True, "", path)
        alt = None
        for a in provider.requires:
            alt = which_any(a) or alt
        if alt:
            return ResolvedProvider(provider, True, f"via alias {alt}", alt)
        return ResolvedProvider(
            provider, False,
            f"`{provider.ref}` not on PATH" + (f" — install: {provider.install}" if provider.install else ""),
            "",
        )

    if kind is ProviderKind.DOCKER:
        if not cfg.use_docker:
            return ResolvedProvider(provider, False, "docker disabled in config", "")
        if not docker_available():
            return ResolvedProvider(provider, False,
                                    "docker not available (install Docker Desktop / enable WSL backend)", "")
        if image_present(provider.ref):
            return ResolvedProvider(provider, True, "image present", provider.ref)
        if cfg.pull_images:
            if _docker_pull_ok(provider.ref):
                return ResolvedProvider(provider, True, "image pulled", provider.ref)
            return ResolvedProvider(provider, False, f"image pull failed: {provider.ref}", "")
        return ResolvedProvider(
            provider, False,
            f"image {provider.ref} not local — `aegis install {provider.ref}` or set AEGIS_PULL=1",
            provider.ref,
        )

    if kind is ProviderKind.REMOTE:
        if cfg.offline:
            return ResolvedProvider(provider, False, "offline mode", "")
        if provider.env:
            missing = [k for k in provider.env if not _has_env(k)]
            if missing:
                return ResolvedProvider(provider, False,
                                        "missing env: " + ", ".join(missing), "")
        return ResolvedProvider(provider, True, "network", provider.ref)

    if kind is ProviderKind.MANUAL:
        return ResolvedProvider(provider, False, "manual / licensed path only", provider.ref)

    return ResolvedProvider(provider, False, "unknown provider kind", "")


def _has_env(k: str) -> bool:
    import os
    # NET is a marker, not a credential: network reachability is the default posture.
    if k == "NET":
        return True
    return bool(os.environ.get(k))


# ---------------------------------------------------------------- execution
@dataclass(slots=True)
class Result:
    rc: int
    stdout: str
    stderr: str
    how: str            # local | docker:<image> | native
    secs: float
    command: list[str]

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def lines(self) -> list[str]:
        return [l for l in (self.stdout or "").splitlines() if l.strip()]


VOLATILE = "${HOME}"


def _expand(p: str, cfg: Config) -> str:
    return (p.replace(VOLATILE, str(cfg.home))
             .replace("$OUT", str(cfg.cache)))


def execute(provider: Provider, argv: list[str], cfg: Config, *,
            timeout: float = 300, workdir: Path | None = None,
            env: dict[str, str] | None = None,
            mounts: list[tuple[str, str, str]] | None = None,
            network: str | None = None,
            stdin: str | None = None,
            uid: int | None = None) -> Result:
    """Run a provider with a normal argv. The provider kind decides how.

    For docker providers, `argv[0]` is the binary *inside* the image.
    """
    t0 = time.time()

    if provider.kind is ProviderKind.NATIVE:
        rc, out, err = _run([sys_executable(), "-m", "aegis.native_exec", provider.ref,
                             *argv],
                            timeout=timeout, cwd=workdir, env=env or None, stdin=stdin)
        return Result(rc, out, err, f"native:{provider.ref}", time.time() - t0,
                      [provider.ref, *argv])

    if provider.kind is ProviderKind.LOCAL:
        binpath = which(provider.ref)
        if not binpath:
            for a in provider.requires:
                binpath = which_any(a)
                if binpath:
                    break
        if not binpath:
            return Result(127, "", f"{provider.ref} not found", "local", 0.0, argv)
        cmd = [binpath, *argv]
        rc, out, err = _run(cmd, timeout=timeout, cwd=workdir, env=env or None, stdin=stdin)
        return Result(rc, out, err, "local", time.time() - t0, cmd)

    if provider.kind is ProviderKind.DOCKER:
        cmd = ["docker", "run", "--rm"]
        if network:
            cmd += ["--network", network]
        for host_path, cont_path, mode in (mounts or []):
            cmd += ["-v", f"{host_path}:{cont_path}{':' + mode if mode else ''}"]
        if provider.privileged:
            cmd += ["--privileged"]
        if uid is not None:
            cmd += ["--user", str(uid)]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        if workdir:
            cmd += ["-w", str(workdir)]
        cmd += [provider.ref, *argv]
        rc, out, err = _run(cmd, timeout=timeout)
        how = f"docker:{provider.ref}"
        return Result(rc, out, err, how, time.time() - t0, cmd)

    if provider.kind is ProviderKind.REMOTE:
        return Result(1, "", "remote providers are invoked via aegis.http, not execute()",
                      "remote", 0.0, argv)

    return Result(1, "", "manual provider", "manual", 0.0, argv)


def sys_executable() -> str:
    import sys
    return sys.executable or "python"


def interactive(ok: bool) -> bool:  # tiny helper for runnability summaries
    return ok
