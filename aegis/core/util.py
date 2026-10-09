"""Small shared helpers. No security logic here — just plumbing."""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")
R = TypeVar("R")

ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "mag": "\033[35m", "cyan": "\033[36m", "grey": "\033[90m",
}
_SEV_COLOR = {
    "critical": "red", "high": "red", "medium": "yellow",
    "low": "blue", "info": "grey", "ok": "green",
}


def colour(text: str, *styles: str) -> str:
    if os.environ.get("NO_COLOR") or not sys_isatty():
        return text
    return "".join(ANSI.get(s, "") for s in styles) + text + ANSI["reset"]


def sys_isatty() -> bool:
    import sys
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def sev_colour(sev: str, text: str | None = None) -> str:
    return colour(text or sev.upper(), _SEV_COLOR.get(sev, "grey"), "bold")


# ------------------------------------------------------------------ string / parsing
_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(text: str) -> str:
    return _SLUG_RE.sub("-", (text or "").lower()).strip("-")[:64]


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        k = (it or "").strip().lower().rstrip(".")
        if k and k not in seen:
            seen.add(k)
            out.append(k.strip())
    return out


def as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y")


def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{n:.1f}PB"


def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, limit: int = 0) -> str:
    """Hash a file. limit>0 hashes only the first N bytes (large binaries)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            read = 0
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
                if limit and read >= limit:
                    break
        return h.hexdigest()
    except Exception:
        return ""


def read_bytes_summary(path: str | Path) -> dict[str, Any]:
    """Cheap static summary of a binary: size, magic, entropy, printable ratio."""
    import math
    p = Path(path)
    out: dict[str, Any] = {"path": str(p), "size": 0, "entropy": 0.0,
                           "printable_ratio": 0.0, "magic": ""}
    try:
        data = p.read_bytes()[:8_000_000]
    except Exception:
        return out
    out["size"] = p.stat().st_size if p.exists() else 0
    if not data:
        return out
    out["magic"] = data[:4].hex()
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            q = c / n
            ent -= q * math.log2(q)
    out["entropy"] = round(ent, 3)
    printable = sum(c for i, c in enumerate(counts) if 32 <= i < 127 or i in (9, 10, 13))
    out["printable_ratio"] = round(printable / n, 3)
    return out


def redact(secret: str, keep: int = 4) -> str:
    """Keep a short prefix/suffix so findings stay verifiable without leaking."""
    s = secret or ""
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * max(4, len(s) - keep * 2)}{s[-keep:]}"


# ------------------------------------------------------------------ time / files
def now() -> float:
    return time.time()


def stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime())


def read_text(p: str | Path, limit: int = 20_000_000) -> str:
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def write_text(p: str | Path, data: str) -> None:
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data, encoding="utf-8")


def read_json(p: str | Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return default if default is not None else {}


def write_json(p: str | Path, data: Any) -> None:
    write_text(p, json.dumps(data, indent=2, default=str, sort_keys=False))


def walk_files(root: str | Path, exts: set[str] | None = None,
               skip: set[str] | None = None, limit: int = 200_000) -> Iterator[Path]:
    """Safe-ish file walker that never follows symlinks out of the tree."""
    skip = skip or {".git", "node_modules", ".venv", "venv", "__pycache__",
                    "dist", "build", ".mypy_cache", ".pytest_cache", "target"}
    exts = {e.lower() for e in exts} if exts else None
    n = 0
    root = Path(root)
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip and not d.startswith(".git")]
        for fn in filenames:
            fp = Path(dirpath) / fn
            if exts and fp.suffix.lower() not in exts:
                continue
            yield fp
            n += 1
            if n >= limit:
                return


# ------------------------------------------------------------------ concurrency
def pmap(fn: Callable[[T], R], items: Iterable[T], workers: int = 8,
         on_error: Callable[[T, BaseException], R] | None = None) -> list[R]:
    """Parallel map that never raises. Order preserved."""
    items = list(items)
    if not items:
        return []
    if workers <= 1:
        out: list[R] = []
        for it in items:
            try:
                out.append(fn(it))
            except BaseException as e:  # noqa: BLE001
                out.append(on_error(it, e) if on_error else None)  # type: ignore[arg-type]
        return out
    out = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(fn, it): it for it in items}
        for fut in cf.as_completed(futs):
            it = futs[fut]
            try:
                out.append(fut.result())
            except BaseException as e:  # noqa: BLE001
                out.append(on_error(it, e) if on_error else None)  # type: ignore[arg-type]
    return out


# ------------------------------------------------------------------ process
def which(name: str) -> str | None:
    return shutil.which(name)


def have(name: str) -> bool:
    return which(name) is not None


def run(cmd: list[str], timeout: float = 120, cwd: str | Path | None = None,
        env: dict[str, str] | None = None, stdin: str | None = None,
        shell: bool = False) -> tuple[int, str, str]:
    """Run a command, always returning (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, env=env, shell=shell,
            input=stdin, capture_output=True, text=True,
            errors="replace", timeout=timeout,
        )
        return p.returncode, (p.stdout or "")[:4_000_000], (p.stderr or "")[:200_000]
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0] if cmd else cmd}"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def which_any(*names: str) -> str | None:
    for n in names:
        p = which(n)
        if p:
            return p
    return None
