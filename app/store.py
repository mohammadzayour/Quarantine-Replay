"""SQLite persistence.

Three separate database files:
  world_vulnerable.sqlite3 - endpoint state seen by the vulnerable backend
  world_protected.sqlite3  - endpoint state seen by the protected backend
  control.sqlite3          - approvals, captured tool calls, timeline
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from . import fixtures

APPROVAL_TTL = timedelta(minutes=15)


def now_iso(offset: timedelta = timedelta(0)) -> str:
    # Fixed-width UTC timestamps, so string comparison equals time comparison.
    return (datetime.now(timezone.utc) + offset).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


class World:
    """One isolated copy of the simulated environment."""

    def __init__(self, name: str, path: Path):
        self.name = name
        self.path = path
        with connect(path) as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS endpoints(
                    endpoint_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    compromised INTEGER NOT NULL,
                    network_status TEXT NOT NULL CHECK(network_status IN ('connected','isolated')),
                    isolated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS services(
                    service_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    depends_on TEXT NOT NULL REFERENCES endpoints(endpoint_id)
                );
                CREATE TABLE IF NOT EXISTS customer_orders(
                    order_id TEXT PRIMARY KEY,
                    customer TEXT NOT NULL,
                    item TEXT NOT NULL,
                    total_cents INTEGER NOT NULL
                );
                """
            )

    def reset(self) -> None:
        with connect(self.path) as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("DELETE FROM services")
            c.execute("DELETE FROM customer_orders")
            c.execute("DELETE FROM endpoints")
            c.executemany(
                "INSERT INTO endpoints VALUES(:endpoint_id,:hostname,:role,:ip,:compromised,'connected',NULL)",
                fixtures.ENDPOINTS,
            )
            c.execute(
                "INSERT INTO services VALUES(:service_id,:name,:description,:depends_on)",
                fixtures.SERVICE,
            )
            c.executemany("INSERT INTO customer_orders VALUES(?,?,?,?)", fixtures.CUSTOMER_ORDERS)
            c.execute("COMMIT")

    def endpoints(self) -> list[dict[str, Any]]:
        with connect(self.path) as c:
            rows = c.execute("SELECT * FROM endpoints ORDER BY endpoint_id DESC").fetchall()
        return [dict(r) | {"compromised": bool(r["compromised"])} for r in rows]

    def resolve(self, reference: str) -> dict[str, Any] | None:
        """Map an untrusted endpoint reference to the canonical inventory record."""
        ref = reference.strip().lower()
        if ref.endswith(".corp.example"):
            ref = ref[: -len(".corp.example")]
        for ep in self.endpoints():
            if ref in (ep["endpoint_id"].lower(), ep["hostname"].lower()):
                return ep
        return None

    def isolate(self, endpoint_id: str) -> bool:
        """Mark an endpoint isolated. Returns False if it already was."""
        with connect(self.path) as c:
            cur = c.execute(
                "UPDATE endpoints SET network_status='isolated', isolated_at=? "
                "WHERE endpoint_id=? AND network_status='connected'",
                (now_iso(), endpoint_id),
            )
            return cur.rowcount == 1

    def app_health(self) -> dict[str, Any]:
        """Probe the simulated customer application. It needs its database to answer."""
        with connect(self.path) as c:
            svc = c.execute("SELECT * FROM services").fetchone()
            dep = c.execute("SELECT * FROM endpoints WHERE endpoint_id=?", (svc["depends_on"],)).fetchone()
            base = {
                "service_id": svc["service_id"],
                "name": svc["name"],
                "description": svc["description"],
                "depends_on": dep["hostname"],
            }
            if dep["network_status"] != "connected":
                return base | {
                    "status": "offline",
                    "http_status": 503,
                    "orders_visible": 0,
                    "detail": f"Upstream {dep['hostname']} unreachable (network isolated)",
                }
            n = c.execute("SELECT COUNT(*) FROM customer_orders").fetchone()[0]
            return base | {
                "status": "online",
                "http_status": 200,
                "orders_visible": n,
                "detail": f"Serving {n} synthetic orders from {dep['hostname']}",
            }

    def snapshot(self) -> dict[str, Any]:
        return {"world": self.name, "endpoints": self.endpoints(), "app": self.app_health()}


class ApprovalStore:
    """Server-side approvals. Only the analyst route holds a reference to grant()."""

    def __init__(self, path: Path):
        self.path = path
        with connect(path) as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals(
                    approval_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    endpoint_id TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
                )
                """
            )

    def grant(
        self, incident_id: str, action: str, endpoint_id: str, approved_by: str,
        ttl: timedelta = APPROVAL_TTL,
    ) -> dict[str, Any]:
        row = {
            "approval_id": "apr-" + uuid.uuid4().hex[:12],
            "incident_id": incident_id,
            "action": action,
            "endpoint_id": endpoint_id,
            "approved_by": approved_by,
            "created_at": now_iso(),
            "expires_at": now_iso(ttl),
            "consumed_at": None,
        }
        with connect(self.path) as c:
            c.execute(
                "INSERT INTO approvals VALUES(:approval_id,:incident_id,:action,:endpoint_id,"
                ":approved_by,:created_at,:expires_at,:consumed_at)",
                row,
            )
        return row

    def consume(self, incident_id: str, action: str, endpoint_id: str) -> dict[str, Any] | None:
        """Atomically spend one unexpired approval matching the exact triple."""
        with connect(self.path) as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                now = now_iso()
                row = c.execute(
                    "SELECT * FROM approvals WHERE incident_id=? AND action=? AND endpoint_id=? "
                    "AND consumed_at IS NULL AND expires_at > ? ORDER BY created_at LIMIT 1",
                    (incident_id, action, endpoint_id, now),
                ).fetchone()
                if row is not None:
                    c.execute("UPDATE approvals SET consumed_at=? WHERE approval_id=?", (now, row["approval_id"]))
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
        return (dict(row) | {"consumed_at": now}) if row is not None else None

    def all(self) -> list[dict[str, Any]]:
        now = now_iso()
        with connect(self.path) as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM approvals ORDER BY created_at")]
        for r in rows:
            r["status"] = "used" if r["consumed_at"] else ("expired" if r["expires_at"] <= now else "active")
        return rows

    def clear(self) -> None:
        with connect(self.path) as c:
            c.execute("DELETE FROM approvals")


class ApprovalVerifier:
    """The only view of approvals the tool path gets: verify-and-spend, nothing else."""

    __slots__ = ("_consume",)

    def __init__(self, store: ApprovalStore):
        self._consume = store.consume

    def consume(self, incident_id: str, action: str, endpoint_id: str) -> dict[str, Any] | None:
        return self._consume(incident_id, action, endpoint_id)


class Journal:
    """Captured tool calls and the inspectable timeline."""

    def __init__(self, path: Path):
        self.path = path
        with connect(path) as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS captures(
                    capture_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    replayed_at TEXT,
                    body TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events(
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    lane TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    detail TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS live_runs(
                    capture_id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    body TEXT NOT NULL
                );
                """
            )

    # Live-run history: a log of what the model did, kept across demo resets.
    def add_live_run(self, capture_id: str, body: dict[str, Any]) -> None:
        with connect(self.path) as c:
            c.execute("INSERT INTO live_runs VALUES(?,?,?)", (capture_id, now_iso(), json.dumps(body)))

    def set_live_run_replay(self, capture_id: str, replay: dict[str, Any]) -> None:
        with connect(self.path) as c:
            row = c.execute("SELECT body FROM live_runs WHERE capture_id=?", (capture_id,)).fetchone()
            if row is not None:
                body = json.loads(row["body"]) | {"replay": replay}
                c.execute("UPDATE live_runs SET body=? WHERE capture_id=?", (json.dumps(body), capture_id))

    def live_runs(self) -> list[dict[str, Any]]:
        with connect(self.path) as c:
            rows = c.execute("SELECT * FROM live_runs ORDER BY ts, rowid").fetchall()
        return [json.loads(r["body"]) | {"capture_id": r["capture_id"], "ts": r["ts"]} for r in rows]

    def clear_live_runs(self) -> None:
        with connect(self.path) as c:
            c.execute("DELETE FROM live_runs")

    def add_capture(self, body: dict[str, Any]) -> dict[str, Any]:
        capture_id = "cap-" + uuid.uuid4().hex[:12]
        created = now_iso()
        with connect(self.path) as c:
            c.execute("INSERT INTO captures VALUES(?,?,NULL,?)", (capture_id, created, json.dumps(body)))
        return self.get_capture(capture_id)  # type: ignore[return-value]

    def get_capture(self, capture_id: str) -> dict[str, Any] | None:
        with connect(self.path) as c:
            row = c.execute("SELECT * FROM captures WHERE capture_id=?", (capture_id,)).fetchone()
        return self._capture(row)

    def latest_capture(self) -> dict[str, Any] | None:
        with connect(self.path) as c:
            row = c.execute("SELECT * FROM captures ORDER BY created_at DESC, rowid DESC LIMIT 1").fetchone()
        return self._capture(row)

    @staticmethod
    def _capture(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        return json.loads(row["body"]) | {
            "capture_id": row["capture_id"],
            "created_at": row["created_at"],
            "replayed_at": row["replayed_at"],
        }

    def mark_replayed(self, capture_id: str) -> None:
        with connect(self.path) as c:
            c.execute("UPDATE captures SET replayed_at=? WHERE capture_id=?", (now_iso(), capture_id))

    def add_event(self, lane: str, kind: str, title: str, summary: str, detail: dict[str, Any]) -> dict[str, Any]:
        ts = now_iso()
        with connect(self.path) as c:
            cur = c.execute(
                "INSERT INTO events(ts,lane,kind,title,summary,detail) VALUES(?,?,?,?,?,?)",
                (ts, lane, kind, title, summary, json.dumps(detail)),
            )
            event_id = cur.lastrowid
        return {"event_id": event_id, "ts": ts, "lane": lane, "kind": kind,
                "title": title, "summary": summary, "detail": detail}

    def events(self) -> list[dict[str, Any]]:
        with connect(self.path) as c:
            rows = c.execute("SELECT * FROM events ORDER BY event_id").fetchall()
        return [dict(r) | {"detail": json.loads(r["detail"])} for r in rows]

    def clear(self) -> None:
        with connect(self.path) as c:
            c.execute("DELETE FROM captures")
            c.execute("DELETE FROM events")
