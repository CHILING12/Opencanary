"""Dependency-injected event processing pipeline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from .correlation import CorrelationEngine, window_start
from .ingest import ParseResult, parse_result
from .models import Aggregate, Alert, ProcessResult, RuleHit
from .storage import SQLiteStore


@dataclass
class PipelineStats:
    lines: int = 0
    parsed: int = 0
    accepted: int = 0
    duplicates: int = 0
    malformed: int = 0
    filtered: int = 0
    alerts: int = 0


class AnalyticsPipeline:
    """Normalize, deduplicate, persist, correlate, and score events."""

    def __init__(
        self,
        store: SQLiteStore,
        hmac_key: bytes,
        correlation: CorrelationEngine | None = None,
        notifier: Callable[[Any], bool] | None = None,
    ) -> None:
        if not hmac_key:
            raise ValueError("an HMAC key is required")
        self.store = store
        self.hmac_key = hmac_key
        self.correlation = correlation or CorrelationEngine()
        self.notifier = notifier

    def process_line(self, line: str | bytes) -> ProcessResult:
        result: ParseResult = parse_result(line, self.hmac_key)
        if result.event is None:
            self.store.increment("events_malformed")
            return ProcessResult(None, None, None, None, False, error=result.error)
        return self.process_event(result.event)

    def _restore_window_if_needed(self, event: Any) -> None:
        aggregate_id = self.correlation.aggregate_id_for(event)
        if self.correlation.has_aggregate(aggregate_id):
            return
        row = self.store.aggregate_row(aggregate_id)
        if row is None:
            return
        start = window_start(event.timestamp, self.correlation.window_seconds)
        events = self.store.events_for_window(
            event.src_ip, start, event.timestamp, exclude_event_id=event.event_id
        )
        reasons = tuple(
            RuleHit(item["rule"], int(item["points"]), item["reason"])
            for item in json.loads(row["reasons"])
        )
        aggregate = Aggregate(
            aggregate_id=row["aggregate_id"], src_ip=row["src_ip"],
            window_start=start,
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            event_count=int(row["event_count"]),
            unique_ports=set(json.loads(row["unique_ports"])),
            unique_protocols=set(json.loads(row["unique_protocols"])),
            tags=set(json.loads(row["tags"])),
            score=int(row["score"]), severity=row["severity"], reasons=reasons,
        )
        self.correlation.restore(aggregate, events)

    def process_event(self, event: Any) -> ProcessResult:
        """Process an already normalized event (useful for safe file acking)."""
        if not self.store.add_event(event):
            return ProcessResult(event, None, None, None, False, duplicate=True)
        self.store.increment("events_parsed")
        self.store.increment("events_raw")

        if self.correlation.risk_engine.is_whitelisted(event.src_ip):
            self.store.increment("events_whitelisted")
            return ProcessResult(event, None, None, None, True, filtered=True)

        self._restore_window_if_needed(event)
        aggregate, risk, alert = self.correlation.add(event)
        self.store.save_aggregate(aggregate, risk)
        persisted_alert = None
        if alert is not None:
            if self.store.save_alert(alert):
                persisted_alert = alert
                self.store.increment("alerts_created")
                if self.notifier is not None:
                    try:
                        delivered = bool(self.notifier(alert))
                    except Exception as exc:
                        delivered = False
                        self.store.mark_notified(alert.alert_id, str(exc))
                    else:
                        self.store.mark_notified(
                            alert.alert_id,
                            None if delivered else "notification returned false",
                        )
                    if delivered:
                        self.store.increment("alerts_notified")
        return ProcessResult(event, aggregate, risk, persisted_alert, True)

    def retry_pending_notifications(self, limit: int = 100) -> int:
        """Retry durable alerts left unnotified by a transient failure."""
        if self.notifier is None:
            return 0
        delivered = 0
        for row in self.store.pending_alerts(limit):
            try:
                payload = json.loads(row["payload"])
                alert = Alert(
                    alert_id=payload["alert_id"], aggregate_id=payload["aggregate_id"],
                    src_ip=payload["src_ip"],
                    first_seen=datetime.fromisoformat(payload["first_seen"].replace("Z", "+00:00")),
                    last_seen=datetime.fromisoformat(payload["last_seen"].replace("Z", "+00:00")),
                    event_count=int(payload["event_count"]),
                    unique_ports=tuple(payload["unique_ports"]),
                    unique_protocols=tuple(payload["unique_protocols"]),
                    tags=tuple(payload["tags"]),
                    score=int(payload["score"]), severity=payload["severity"],
                    reasons=tuple(
                        RuleHit(item["rule"], int(item["points"]), item["reason"])
                        for item in payload["reasons"]
                    ),
                )
                ok = bool(self.notifier(alert))
            except Exception as exc:
                self.store.mark_notified(row["alert_id"], str(exc))
                continue
            self.store.mark_notified(
                row["alert_id"], None if ok else "notification returned false"
            )
            delivered += int(ok)
        return delivered

    def process_lines(self, lines: Any) -> PipelineStats:
        stats = PipelineStats()
        for line in lines:
            stats.lines += 1
            outcome = self.process_line(line)
            if outcome.error:
                stats.malformed += 1
            elif outcome.duplicate:
                stats.duplicates += 1
            else:
                stats.parsed += 1
                stats.accepted += 1
                if outcome.filtered:
                    stats.filtered += 1
                if outcome.alert is not None:
                    stats.alerts += 1
        return stats
