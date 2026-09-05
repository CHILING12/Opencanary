"""Five-minute source activity aggregation and cross-protocol correlation."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .models import Aggregate, Alert, NormalizedEvent, RiskAssessment
from .rules import RiskEngine


WINDOW_SECONDS = 5 * 60


def window_start(timestamp: datetime, window_seconds: int = WINDOW_SECONDS) -> datetime:
    timestamp = timestamp.astimezone(timezone.utc)
    epoch = int(timestamp.timestamp())
    return datetime.fromtimestamp(epoch - epoch % window_seconds, tz=timezone.utc)


class CorrelationEngine:
    """Keep a bounded in-memory view of current source windows.

    SQLite receives every aggregate update, so a process restart does not lose
    the durable result. The in-memory event lists are intentionally limited to
    the current windows used for rule evaluation.
    """

    def __init__(
        self,
        risk_engine: RiskEngine | None = None,
        window_seconds: int = WINDOW_SECONDS,
        alert_threshold: int = 30,
    ):
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        if alert_threshold < 0:
            raise ValueError("alert_threshold must not be negative")
        self.risk_engine = risk_engine or RiskEngine()
        self.window_seconds = window_seconds
        self.alert_threshold = alert_threshold
        self._aggregates: dict[str, Aggregate] = {}
        self._events: dict[str, list[NormalizedEvent]] = {}

    def aggregate_id_for(self, event: NormalizedEvent) -> str:
        start = window_start(event.timestamp, self.window_seconds)
        return hashlib.sha256(
            f"{event.src_ip}|{start.isoformat()}".encode("utf-8")
        ).hexdigest()[:32]

    def has_aggregate(self, aggregate_id: str) -> bool:
        return aggregate_id in self._aggregates

    def restore(self, aggregate: Aggregate, events: Iterable[NormalizedEvent]) -> None:
        """Restore a persisted source window after a process restart."""
        self._aggregates[aggregate.aggregate_id] = aggregate
        self._events[aggregate.aggregate_id] = list(events)

    def add(self, event: NormalizedEvent) -> tuple[Aggregate, RiskAssessment, Alert | None]:
        start = window_start(event.timestamp, self.window_seconds)
        aggregate_id = self.aggregate_id_for(event)
        aggregate = self._aggregates.get(aggregate_id)
        if aggregate is None:
            aggregate = Aggregate(
                aggregate_id=aggregate_id,
                src_ip=event.src_ip,
                window_start=start,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
            self._aggregates[aggregate_id] = aggregate
            self._events[aggregate_id] = []
        aggregate.first_seen = min(aggregate.first_seen, event.timestamp)
        aggregate.last_seen = max(aggregate.last_seen, event.timestamp)
        aggregate.event_count += 1
        if event.dst_port is not None:
            aggregate.unique_ports.add(event.dst_port)
        aggregate.unique_protocols.add(event.protocol)
        aggregate.tags.update(self.risk_engine.event_tags(event))
        self._events[aggregate_id].append(event)
        risk = self.risk_engine.assess(aggregate, self._events[aggregate_id])
        aggregate.score = risk.score
        aggregate.severity = risk.severity
        aggregate.reasons = risk.reasons

        alert = None
        if risk.score >= self.alert_threshold:
            alert_id = f"{aggregate_id}:{risk.severity}"
            alert = Alert(
                alert_id=alert_id,
                aggregate_id=aggregate_id,
                src_ip=aggregate.src_ip,
                first_seen=aggregate.first_seen,
                last_seen=aggregate.last_seen,
                event_count=aggregate.event_count,
                unique_ports=tuple(sorted(aggregate.unique_ports)),
                unique_protocols=tuple(sorted(aggregate.unique_protocols)),
                tags=tuple(sorted(aggregate.tags)),
                score=risk.score,
                severity=risk.severity,
                reasons=risk.reasons,
            )
        self._discard_old(event.timestamp)
        return aggregate, risk, alert

    def _discard_old(self, now: datetime) -> None:
        cutoff = now.astimezone(timezone.utc) - timedelta(seconds=self.window_seconds * 2)
        for aggregate_id, aggregate in list(self._aggregates.items()):
            if aggregate.last_seen < cutoff:
                self._aggregates.pop(aggregate_id, None)
                self._events.pop(aggregate_id, None)

    def events_for(self, aggregate_id: str) -> Iterable[NormalizedEvent]:
        return tuple(self._events.get(aggregate_id, ()))
