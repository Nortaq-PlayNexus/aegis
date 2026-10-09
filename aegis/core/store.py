"""SQLite persistence for runs, findings, evidence and the coverage ledger history."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, started REAL, finished REAL, profile TEXT,
  active INTEGER, suite TEXT, targets TEXT, provider TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  fingerprint TEXT PRIMARY KEY, run_id TEXT, first_seen REAL, last_seen REAL,
  times_seen INTEGER DEFAULT 1, capability TEXT, title TEXT, severity TEXT,
  target TEXT, detail TEXT, remediation TEXT, attack_ids TEXT, tags TEXT,
  confidence TEXT, cwe TEXT, cvss REAL, suite_run TEXT, meta TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT, run_id REAL,
  kind TEXT, summary TEXT, locator TEXT, excerpt TEXT, raw TEXT
);
CREATE TABLE IF NOT EXISTS coverage_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, coverage_pct REAL,
  total INTEGER, covered INTEGER, gaps TEXT
);
CREATE TABLE IF NOT EXISTS baselines (
  name TEXT PRIMARY KEY, created REAL, kind TEXT, payload TEXT
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_f_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_f_cap ON findings(capability);
CREATE INDEX IF NOT EXISTS idx_f_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_e_fp ON evidence(fingerprint);
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(self.path), timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------------------------------------------------------------- runs
    def start_run(self, run_id: str, profile: str, active: bool, suite: str,
                  targets: Iterable[str], provider: str = "aegis") -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO runs(run_id,started,finished,profile,active,suite,targets,provider,notes)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (run_id, time.time(), None, profile, int(active), suite,
             json.dumps(list(targets)), provider, ""))
        self.audit("run.start", f"{run_id} {suite} profile={profile} active={active}")
        self.db.commit()

    def finish_run(self, run_id: str, notes: str = "") -> None:
        self.db.execute("UPDATE runs SET finished=?, notes=? WHERE run_id=?",
                        (time.time(), notes, run_id))
        self.audit("run.finish", f"{run_id} {notes[:200]}")
        self.db.commit()

    def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        cur = self.db.execute("SELECT * FROM runs ORDER BY started DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    # ---------------------------------------------------------------- findings
    def upsert_findings(self, run_id: str, findings: Iterable[Finding]) -> tuple[int, int]:
        new = updated = 0
        now = time.time()
        for f in findings:
            row = self.db.execute(
                "SELECT times_seen, first_seen FROM findings WHERE fingerprint=?",
                (f.fingerprint,)).fetchone()
            if row:
                updated += 1
                self.db.execute(
                    "UPDATE findings SET last_seen=?, times_seen=times_seen+1, run_id=?,"
                    " severity=?, status='open' WHERE fingerprint=?",
                    (now, run_id, f.severity.value, f.fingerprint))
            else:
                new += 1
                self.db.execute(
                    "INSERT OR IGNORE INTO findings(fingerprint,run_id,first_seen,last_seen,"
                    "times_seen,capability,title,severity,target,detail,remediation,attack_ids,"
                    "tags,confidence,cwe,cvss,suite_run,meta,status)"
                    " VALUES(?,?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,'open')",
                    (f.fingerprint, run_id, now, now, f.capability, f.title,
                     f.severity.value, f.target, f.detail, f.remediation,
                     json.dumps(f.attack_ids), json.dumps(f.tags), f.confidence,
                     f.cwe, f.cvss, f.suite_run, json.dumps(f.meta, default=str)))
                for e in f.evidence:
                    self.db.execute(
                        "INSERT INTO evidence(fingerprint,run_id,kind,summary,locator,excerpt,raw)"
                        " VALUES(?,?,?,?,?,?,?)",
                        (f.fingerprint, now, e.kind, e.summary, e.locator,
                         e.excerpt[:4000], e.raw[:8000]))
        self.db.commit()
        return new, updated

    def findings(self, run_id: str | None = None, severity: str | None = None,
                 capability: str | None = None, status: str | None = None,
                 limit: int = 5000) -> list[dict[str, Any]]:
        q = "SELECT * FROM findings WHERE 1=1"
        a: list[Any] = []
        if run_id:
            q += " AND run_id=?"
            a.append(run_id)
        if severity:
            q += " AND severity=?"
            a.append(severity)
        if capability:
            q += " AND capability LIKE ?"
            a.append(f"%{capability}%")
        if status:
            q += " AND status=?"
            a.append(status)
        q += " ORDER BY last_seen DESC LIMIT ?"
        a.append(limit)
        cur = self.db.execute(q, a)
        out = []
        for r in cur.fetchall():
            d = dict(r)
            for k in ("attack_ids", "tags", "meta"):
                try:
                    d[k] = json.loads(d.get(k) or "null")
                except Exception:
                    d[k] = None
            out.append(d)
        return out

    def evidence_for(self, fingerprint: str) -> list[dict[str, Any]]:
        cur = self.db.execute("SELECT * FROM evidence WHERE fingerprint=? ORDER BY id", (fingerprint,))
        return [dict(r) for r in cur.fetchall()]

    def set_status(self, fingerprint: str, status: str) -> None:
        self.db.execute("UPDATE findings SET status=? WHERE fingerprint=?", (status, fingerprint))
        self.db.commit()

    # ---------------------------------------------------------------- coverage
    def record_coverage(self, coverage_pct: float, total: int, covered: int,
                        gaps: list[dict[str, Any]]) -> None:
        self.db.execute(
            "INSERT INTO coverage_history(ts,coverage_pct,total,covered,gaps) VALUES(?,?,?,?,?)",
            (time.time(), coverage_pct, total, covered, json.dumps(gaps)))
        self.db.commit()

    def coverage_trend(self, limit: int = 30) -> list[dict[str, Any]]:
        cur = self.db.execute(
            "SELECT ts, coverage_pct, total, covered FROM coverage_history ORDER BY ts DESC LIMIT ?",
            (limit,))
        return [dict(r) for r in cur.fetchall()][::-1]

    # ---------------------------------------------------------------- baselines
    def put_baseline(self, name: str, kind: str, payload: Any) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO baselines(name,created,kind,payload) VALUES(?,?,?,?)",
            (name, time.time(), kind, json.dumps(payload, default=str)))
        self.db.commit()

    def get_baseline(self, name: str) -> Any:
        row = self.db.execute("SELECT payload FROM baselines WHERE name=?", (name,)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["payload"])
        except Exception:
            return None

    # ---------------------------------------------------------------- audit
    def audit(self, action: str, detail: str = "", actor: str = "local") -> None:
        try:
            self.db.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
                            (time.time(), actor, action, detail[:4000]))
        except Exception:
            pass

    def audit_trail(self, limit: int = 200) -> list[dict[str, Any]]:
        cur = self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]

    def close(self) -> None:
        try:
            self.db.commit()
            self.db.close()
        except Exception:
            pass
