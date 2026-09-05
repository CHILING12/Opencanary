"""SQLite persistence for normalized events and alert state."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import Aggregate, Alert, NormalizedEvent, RiskAssessment


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
 event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, node_id TEXT NOT NULL,
 src_ip TEXT NOT NULL, src_port INTEGER, dst_ip TEXT NOT NULL, dst_port INTEGER,
 protocol TEXT NOT NULL, event_type TEXT NOT NULL, username TEXT,
 password_hash TEXT, user_agent TEXT, raw_event TEXT NOT NULL,
 weak_credential INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS events_timestamp_idx ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_src_idx ON events(src_ip, timestamp);
CREATE TABLE IF NOT EXISTS aggregates (
 aggregate_id TEXT PRIMARY KEY, src_ip TEXT NOT NULL, window_start TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, event_count INTEGER NOT NULL,
 unique_ports TEXT NOT NULL, unique_protocols TEXT NOT NULL, tags TEXT NOT NULL,
 score INTEGER NOT NULL, severity TEXT NOT NULL, reasons TEXT NOT NULL,
 UNIQUE(src_ip, window_start)
);
CREATE TABLE IF NOT EXISTS alerts (
 alert_id TEXT PRIMARY KEY, aggregate_id TEXT NOT NULL, src_ip TEXT NOT NULL,
 created_at TEXT NOT NULL, last_seen TEXT NOT NULL, event_count INTEGER NOT NULL,
 score INTEGER NOT NULL, severity TEXT NOT NULL, payload TEXT NOT NULL,
 notified_at TEXT, notification_attempts INTEGER NOT NULL DEFAULT 0,
 notification_error TEXT
);
CREATE INDEX IF NOT EXISTS alerts_created_idx ON alerts(created_at);
CREATE TABLE IF NOT EXISTS metrics (
 name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS checkpoints (
 path TEXT PRIMARY KEY, inode INTEGER, offset INTEGER NOT NULL DEFAULT 0
);
"""


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


class SQLiteStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.executescript(SCHEMA)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(events)")}
        if "weak_credential" not in columns:
            self.db.execute(
                "ALTER TABLE events ADD COLUMN weak_credential INTEGER NOT NULL DEFAULT 0"
            )
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def add_event(self, event: NormalizedEvent) -> bool:
        try:
            self.db.execute(
                """INSERT INTO events(event_id,timestamp,node_id,src_ip,src_port,dst_ip,dst_port,
                protocol,event_type,username,password_hash,user_agent,raw_event,weak_credential)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.event_id,
                    iso(event.timestamp),
                    event.node_id,
                    event.src_ip,
                    event.src_port,
                    event.dst_ip,
                    event.dst_port,
                    event.protocol,
                    event.event_type,
                    event.username,
                    event.password_hash,
                    event.user_agent,
                    json.dumps(event.raw_event, sort_keys=True, ensure_ascii=False, default=str),
                    int(event.weak_credential),
                ),
            )
            self.increment("events_accepted")
            self.db.commit()
            return True
        except sqlite3.IntegrityError:
            self.increment("events_duplicate")
            self.db.rollback()
            return False

    def increment(self, name: str, amount: int = 1) -> None:
        self.db.execute(
            "INSERT INTO metrics(name,value) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
            (name, amount),
        )
        self.db.commit()

    def metric(self, name: str) -> int:
        row = self.db.execute("SELECT value FROM metrics WHERE name=?", (name,)).fetchone()
        return int(row[0]) if row else 0

    def aggregate_row(self, aggregate_id: str) -> sqlite3.Row | None:
        return self.db.execute(
            "SELECT * FROM aggregates WHERE aggregate_id=?", (aggregate_id,)
        ).fetchone()

    def events_for_window(
        self, src_ip: str, start: datetime, end: datetime, exclude_event_id: str | None = None
    ) -> list[NormalizedEvent]:
        """Rebuild the rule-relevant event view for a persisted time window."""
        sql = """SELECT * FROM events WHERE src_ip=? AND timestamp>=? AND timestamp<?"""
        args: tuple[Any, ...] = (src_ip, iso(start), iso(end))
        if exclude_event_id is not None:
            sql += " AND event_id<>?"
            args += (exclude_event_id,)
        rows = self.query_all(sql + " ORDER BY timestamp, event_id", args)
        result: list[NormalizedEvent] = []
        for row in rows:
            raw_event = json.loads(row["raw_event"])
            timestamp = datetime.fromisoformat(row["timestamp"])
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            result.append(
                NormalizedEvent(
                    event_id=row["event_id"], timestamp=timestamp,
                    node_id=row["node_id"], src_ip=row["src_ip"],
                    src_port=row["src_port"], dst_ip=row["dst_ip"],
                    dst_port=row["dst_port"], protocol=row["protocol"],
                    event_type=row["event_type"], username=row["username"],
                    password_hash=row["password_hash"], user_agent=row["user_agent"],
                    raw_event=raw_event,
                    weak_credential=bool(row["weak_credential"]),
                )
            )
        return result

    def save_aggregate(self, aggregate: Aggregate, risk: RiskAssessment) -> None:
        self.db.execute(
            """INSERT INTO aggregates VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(aggregate_id) DO UPDATE SET first_seen=excluded.first_seen,
            last_seen=excluded.last_seen,event_count=excluded.event_count,
            unique_ports=excluded.unique_ports,unique_protocols=excluded.unique_protocols,
            tags=excluded.tags,score=excluded.score,severity=excluded.severity,reasons=excluded.reasons""",
            (
                aggregate.aggregate_id,
                aggregate.src_ip,
                iso(aggregate.window_start),
                iso(aggregate.first_seen),
                iso(aggregate.last_seen),
                aggregate.event_count,
                json.dumps(sorted(aggregate.unique_ports)),
                json.dumps(sorted(aggregate.unique_protocols)),
                json.dumps(sorted(aggregate.tags)),
                risk.score,
                risk.severity,
                json.dumps([hit.to_dict() for hit in risk.reasons], ensure_ascii=False),
            ),
        )
        self.db.commit()

    def alert_exists(self, alert_id: str) -> bool:
        return self.db.execute("SELECT 1 FROM alerts WHERE alert_id=?", (alert_id,)).fetchone() is not None

    def save_alert(self, alert: Alert) -> bool:
        cursor = self.db.execute(
            """INSERT INTO alerts(alert_id,aggregate_id,src_ip,created_at,last_seen,event_count,score,severity,payload)
               VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(alert_id) DO NOTHING""",
            (
                alert.alert_id, alert.aggregate_id, alert.src_ip, iso(alert.first_seen),
                iso(alert.last_seen), alert.event_count, alert.score, alert.severity,
                json.dumps(alert.to_dict(), ensure_ascii=False),
            ),
        )
        if cursor.rowcount != 1:
            self.db.rollback()
            return False
        self.increment("alerts_created")
        self.db.commit()
        return True

    def pending_alerts(self, limit: int = 100) -> list[sqlite3.Row]:
        return self.query_all(
            """SELECT * FROM alerts WHERE notified_at IS NULL
               ORDER BY created_at, alert_id LIMIT ?""",
            (max(1, int(limit)),),
        )

    def mark_notified(self, alert_id: str, error: str | None = None) -> None:
        if error:
            self.db.execute(
                "UPDATE alerts SET notification_attempts=notification_attempts+1,notification_error=? WHERE alert_id=?",
                (error[:1000], alert_id),
            )
        else:
            self.db.execute(
                "UPDATE alerts SET notified_at=?,notification_attempts=notification_attempts+1,notification_error=NULL WHERE alert_id=?",
                (datetime.now(timezone.utc).isoformat(), alert_id),
            )
        self.db.commit()

    def recent_alert_for(self, src_ip: str, now: datetime, cooldown_seconds: int) -> bool:
        since = iso(now - timedelta(seconds=cooldown_seconds))
        return self.db.execute(
            "SELECT 1 FROM alerts WHERE src_ip=? AND created_at>=? LIMIT 1", (src_ip, since)
        ).fetchone() is not None

    def checkpoint(self, path: str) -> tuple[int | None, int]:
        row = self.db.execute("SELECT inode,offset FROM checkpoints WHERE path=?", (path,)).fetchone()
        return (row[0], row[1]) if row else (None, 0)

    def save_checkpoint(self, path: str, inode: int, offset: int) -> None:
        self.db.execute(
            "INSERT INTO checkpoints(path,inode,offset) VALUES(?,?,?) ON CONFLICT(path) DO UPDATE SET inode=excluded.inode,offset=excluded.offset",
            (path, inode, offset),
        )
        self.db.commit()

    def retention(self, days: int) -> None:
        cutoff = iso(datetime.now(timezone.utc) - timedelta(days=days))
        self.db.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        self.db.execute("DELETE FROM aggregates WHERE last_seen < ?", (cutoff,))
        self.db.execute("DELETE FROM alerts WHERE last_seen < ?", (cutoff,))
        self.db.commit()

    def query_all(self, sql: str, args: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return list(self.db.execute(sql, args).fetchall())
