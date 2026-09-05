"""Data models used by the OpenCanary analytics sidecar."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    timestamp: datetime
    node_id: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str
    event_type: str
    username: str | None
    password_hash: str | None
    user_agent: str | None
    raw_event: dict[str, Any]
    # Derived before redaction so rules can classify a credential without
    # retaining or exposing its plaintext value.
    weak_credential: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "node_id": self.node_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "event_type": self.event_type,
            "username": self.username,
            "password_hash": self.password_hash,
            "user_agent": self.user_agent,
            "raw_event": self.raw_event,
            "weak_credential": self.weak_credential,
        }


@dataclass(frozen=True)
class RuleHit:
    rule: str
    points: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "points": self.points, "reason": self.reason}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: str
    reasons: tuple[RuleHit, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "reasons": [reason.to_dict() for reason in self.reasons],
        }


@dataclass
class Aggregate:
    aggregate_id: str
    src_ip: str
    window_start: datetime
    first_seen: datetime
    last_seen: datetime
    event_count: int = 0
    unique_ports: set[int] = field(default_factory=set)
    unique_protocols: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    score: int = 0
    severity: str = "low"
    reasons: tuple[RuleHit, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "aggregate_id": self.aggregate_id,
            "src_ip": self.src_ip,
            "window_start": self.window_start.isoformat().replace("+00:00", "Z"),
            "first_seen": self.first_seen.isoformat().replace("+00:00", "Z"),
            "last_seen": self.last_seen.isoformat().replace("+00:00", "Z"),
            "event_count": self.event_count,
            "unique_ports": sorted(self.unique_ports),
            "unique_protocols": sorted(self.unique_protocols),
            "tags": sorted(self.tags),
            "score": self.score,
            "severity": self.severity,
            "reasons": [reason.to_dict() for reason in self.reasons],
        }


@dataclass(frozen=True)
class Alert:
    alert_id: str
    aggregate_id: str
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    unique_ports: tuple[int, ...]
    unique_protocols: tuple[str, ...]
    tags: tuple[str, ...]
    score: int
    severity: str
    reasons: tuple[RuleHit, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "aggregate_id": self.aggregate_id,
            "src_ip": self.src_ip,
            "first_seen": self.first_seen.isoformat().replace("+00:00", "Z"),
            "last_seen": self.last_seen.isoformat().replace("+00:00", "Z"),
            "event_count": self.event_count,
            "unique_ports": list(self.unique_ports),
            "unique_protocols": list(self.unique_protocols),
            "tags": list(self.tags),
            "score": self.score,
            "severity": self.severity,
            "reasons": [reason.to_dict() for reason in self.reasons],
        }


@dataclass(frozen=True)
class ProcessResult:
    event: NormalizedEvent | None
    aggregate: Aggregate | None
    risk: RiskAssessment | None
    alert: Alert | None
    accepted: bool
    duplicate: bool = False
    filtered: bool = False
    error: str | None = None
