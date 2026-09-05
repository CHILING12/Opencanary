"""Markdown daily reports for the OpenCanary analytics SQLite store.

The report deliberately only reads aggregate fields and selected, non-secret
columns.  In particular, it never renders an event's ``raw_event`` or an
alert's JSON payload: both may contain values supplied by an attacker.
"""

from __future__ import annotations

import html
import sqlite3
from contextlib import contextmanager
from datetime import date as date_type
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from .rules import PORT_SCAN_TYPES


_HIGH_RISK_SEVERITIES = frozenset({"high", "critical"})
_BRUTE_FORCE_TYPES = frozenset({"login_attempt", "auth_initiated", "brute_force"})


@contextmanager
def _connection(store: Any) -> Iterator[Any]:
    """Yield a DB-API connection for an SQLiteStore, connection, or path.

    ``SQLiteStore`` exposes its connection as ``db``.  Accepting a regular
    ``sqlite3.Connection`` as well makes the report useful to callers that
    already own a transaction and keeps this module independent of store
    mutation methods.  A path is accepted as a convenience and is closed when
    report generation finishes.
    """
    if hasattr(store, "db"):
        yield store.db
        return
    if isinstance(store, sqlite3.Connection):
        yield store
        return
    if isinstance(store, (str, Path)):
        connection = sqlite3.connect(str(store))
        try:
            yield connection
        finally:
            connection.close()
        return
    raise TypeError("store must be an SQLiteStore, sqlite3.Connection, or database path")


def _rows(connection: Any, query: str, args: tuple[Any, ...] = ()) -> list[Any]:
    """Execute a read-only query and return its rows.

    The small fallback for ``query_all`` supports lightweight store doubles in
    tests while normal callers use the store's underlying DB-API connection.
    """
    result = connection.execute(query, args)
    return list(result.fetchall())


def _value(row: Any, name: str, index: int) -> Any:
    """Read a named column from sqlite3.Row or an ordinary tuple/mapping."""
    if isinstance(row, Mapping):
        return row.get(name)
    try:
        return row[name]
    except (IndexError, KeyError, TypeError):
        return row[index]


def _report_date(value: Any) -> date_type:
    """Normalize a report date to a UTC calendar date."""
    if value is None:
        return datetime.now(timezone.utc).date()
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.date()
    if isinstance(value, date_type):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("date must not be empty")
        # Accept both a calendar date and an ISO timestamp for convenience.
        try:
            return date_type.fromisoformat(text[:10])
        except ValueError:
            try:
                timestamp = text[:-1] + "+00:00" if text.endswith("Z") else text
                parsed = datetime.fromisoformat(timestamp)
            except ValueError as exc:
                raise ValueError("date must be an ISO date or datetime") from exc
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc)
            return parsed.date()
    raise TypeError("date must be a date, datetime, ISO string, or None")


def _escape_cell(value: Any) -> str:
    """Escape untrusted text for a Markdown table cell.

    HTML escaping prevents HTML/injection, while escaping Markdown delimiters
    prevents attacker-controlled values from changing table structure or
    creating links/emphasis. Newlines are replaced because a table cell may
    not span physical Markdown lines.
    """
    if value is None:
        text = "—"
    else:
        text = str(value)
    text = text.replace("\r\n", " ").replace("\r", " ").replace("\n", " ")
    text = text.replace("\\", "\\\\")
    for marker in ("|", "`", "*", "_", "{", "}", "[", "]", "(", ")", "!"):
        text = text.replace(marker, "\\" + marker)
    return html.escape(text, quote=True)


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _hour(value: Any) -> int | None:
    """Extract a UTC hour from a stored ISO timestamp."""
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            # SQLite's common space-separated representation is handled by
            # this fallback as well as by fromisoformat on supported Pythons.
            return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.hour


def _metric(connection: Any, names: tuple[str, ...], default: int = 0) -> int:
    """Return the first present metric from ``names``."""
    for name in names:
        try:
            result = _rows(
                connection,
                "SELECT value FROM metrics WHERE name=? LIMIT 1",
                (name,),
            )
        except sqlite3.OperationalError:
            # A caller may provide a pre-schema database.  Reports should be
            # useful with zero metric values rather than failing altogether.
            return default
        if result:
            return _integer(_value(result[0], "value", 0), default)
    return default


def _table(rows: list[str]) -> str:
    """Join already-rendered Markdown lines with a trailing newline."""
    return "\n".join(rows)


def generate_markdown(store: Any, date: Any = None) -> str:
    """Generate a Markdown report for one UTC calendar day.

    Parameters
    ----------
    store:
        An :class:`~opencanary_analytics.storage.SQLiteStore`, an existing
        ``sqlite3.Connection``, or a path to the SQLite database.
    date:
        A ``datetime.date``, ``datetime.datetime``, ISO date/timestamp, or
        ``None`` (today in UTC).

    All SQL values are bound parameters.  The returned Markdown contains no
    raw event or alert payloads, and therefore does not expose plaintext
    credentials even if a database was populated by an untrusted event.
    """
    day = _report_date(date)
    day_text = day.isoformat()

    with _connection(store) as connection:
        source_rows = _rows(
            connection,
            """
            SELECT src_ip, COUNT(*) AS event_count
              FROM events
             WHERE date(timestamp, 'utc')=?
             GROUP BY src_ip
             ORDER BY event_count DESC, src_ip ASC
             LIMIT 10
            """,
            (day_text,),
        )
        protocol_rows = _rows(
            connection,
            """
            SELECT protocol, COUNT(*) AS event_count
              FROM events
             WHERE date(timestamp, 'utc')=?
             GROUP BY protocol
             ORDER BY event_count DESC, protocol ASC
            """,
            (day_text,),
        )
        username_rows = _rows(
            connection,
            """
            SELECT username, COUNT(*) AS event_count
              FROM events
             WHERE date(timestamp, 'utc')=?
               AND username IS NOT NULL
               AND trim(username) <> ''
             GROUP BY username
             ORDER BY event_count DESC, username ASC
             LIMIT 10
            """,
            (day_text,),
        )
        hourly_rows = _rows(
            connection,
            """
            SELECT timestamp, event_type
              FROM events
             WHERE date(timestamp, 'utc')=?
            """,
            (day_text,),
        )
        alert_rows = _rows(
            connection,
            """
            SELECT alert_id, src_ip, created_at, last_seen,
                   event_count, score, severity
              FROM alerts
             WHERE date(created_at, 'utc')=?
             ORDER BY score DESC, created_at ASC, alert_id ASC
            """,
            (day_text,),
        )
        event_total_rows = _rows(
            connection,
            "SELECT COUNT(*) AS event_count FROM events WHERE date(timestamp, 'utc')=?",
            (day_text,),
        )

        # Metrics are counters in the current schema and have no timestamp.
        # Consequently they are shown as recorded (process-lifetime) counters;
        # event and alert tables above remain scoped to the requested day.
        whitelist_count = _metric(connection, ("events_whitelisted",))
        raw_alert_count = _metric(
            connection,
            ("alerts_raw", "alerts_total", "alerts_generated", "alerts_candidates", "alerts_created"),
            default=-1,
        )
        dedup_metric = _metric(
            connection,
            ("alerts_deduplicated", "alerts_dedup", "alerts_saved"),
            default=-1,
        )

    high_risk_rows: list[tuple[Any, ...]] = []
    for row in alert_rows:
        score = _integer(_value(row, "score", 5))
        severity = str(_value(row, "severity", 6) or "").lower()
        if score >= 60 or severity in _HIGH_RISK_SEVERITIES:
            high_risk_rows.append(
                (
                    _value(row, "alert_id", 0),
                    _value(row, "src_ip", 1),
                    _value(row, "created_at", 2),
                    _value(row, "last_seen", 3),
                    _integer(_value(row, "event_count", 4)),
                    score,
                    severity or "unknown",
                )
            )

    hourly: list[list[int]] = [[0, 0] for _ in range(24)]
    for row in hourly_rows:
        hour = _hour(_value(row, "timestamp", 0))
        if hour is None or not 0 <= hour <= 23:
            continue
        event_type = str(_value(row, "event_type", 1) or "").lower()
        if event_type in PORT_SCAN_TYPES or "scan" in event_type:
            hourly[hour][0] += 1
        if event_type in _BRUTE_FORCE_TYPES or "brute" in event_type:
            hourly[hour][1] += 1

    event_total = _integer(_value(event_total_rows[0], "event_count", 0)) if event_total_rows else 0
    daily_alert_count = len(alert_rows)
    if raw_alert_count < 0:
        raw_alert_count = daily_alert_count
    if dedup_metric < 0:
        dedup_metric = daily_alert_count

    source_lines = ["| Source | Events |", "| --- | ---: |"]
    source_lines.extend(
        f"| {_escape_cell(_value(row, 'src_ip', 0))} | {_integer(_value(row, 'event_count', 1))} |"
        for row in source_rows
    )
    if not source_rows:
        source_lines.append("| _None_ | 0 |")

    protocol_lines = ["| Protocol | Events |", "| --- | ---: |"]
    protocol_lines.extend(
        f"| {_escape_cell(_value(row, 'protocol', 0))} | {_integer(_value(row, 'event_count', 1))} |"
        for row in protocol_rows
    )
    if not protocol_rows:
        protocol_lines.append("| _None_ | 0 |")

    username_lines = ["| Username | Attempts |", "| --- | ---: |"]
    username_lines.extend(
        f"| {_escape_cell(_value(row, 'username', 0))} | {_integer(_value(row, 'event_count', 1))} |"
        for row in username_rows
    )
    if not username_rows:
        username_lines.append("| _None_ | 0 |")

    hourly_lines = ["| Hour (UTC) | Scan events | Brute-force events |", "| ---: | ---: | ---: |"]
    hourly_lines.extend(
        f"| {hour:02d} | {counts[0]} | {counts[1]} |"
        for hour, counts in enumerate(hourly)
    )

    alert_lines = [
        "| Alert ID | Source | Created (UTC) | Last seen (UTC) | Events | Score | Severity |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    alert_lines.extend(
        "| "
        + " | ".join(
            (
                _escape_cell(alert_id),
                _escape_cell(src_ip),
                _escape_cell(created_at),
                _escape_cell(last_seen),
                str(event_count),
                str(score),
                _escape_cell(severity),
            )
        )
        + " |"
        for alert_id, src_ip, created_at, last_seen, event_count, score, severity in high_risk_rows
    )
    if not high_risk_rows:
        alert_lines.append("| _None_ | — | — | — | 0 | 0 | — |")

    return "\n".join(
        (
            f"# OpenCanary Daily Report — {day_text}",
            "",
            "## Summary",
            "",
            f"- Events recorded: **{event_total}**",
            f"- High-risk alerts: **{len(high_risk_rows)}**",
            "",
            "## Top 10 Sources",
            "",
            "Top sources by event count (limited to 10).",
            _table(source_lines),
            "",
            "## Protocol Counts",
            "",
            _table(protocol_lines),
            "",
            "## Top 10 Usernames",
            "",
            "Usernames with the most recorded authentication attempts (limited to 10).",
            _table(username_lines),
            "",
            "## Hourly Scan / Brute-Force Distribution",
            "",
            _table(hourly_lines),
            "",
            "## High-Risk Alerts",
            "",
            "Only alerts with severity high/critical or score at least 60 are shown; alert payloads are intentionally omitted.",
            _table(alert_lines),
            "",
            "## Whitelist Count",
            "",
            f"- Whitelisted events: **{whitelist_count}** (recorded metric counter)",
            "",
            "## Raw vs Deduplicated Alert Counts",
            "",
            "| Alert measure | Count |",
            "| --- | ---: |",
            f"| Raw alert candidates | {raw_alert_count} |",
            f"| Deduplicated alerts | {dedup_metric} |",
            "",
        )
    )


# Friendly aliases for callers that use a generic report name.
generate_report = generate_markdown
generate_daily_report = generate_markdown


class DailyReport:
    """Small object-oriented wrapper around :func:`generate_markdown`."""

    def __init__(self, store: Any):
        self.store = store

    def generate(self, date: Any = None) -> str:
        return generate_markdown(self.store, date)

    render = generate


__all__ = [
    "DailyReport",
    "generate_daily_report",
    "generate_markdown",
    "generate_report",
]
