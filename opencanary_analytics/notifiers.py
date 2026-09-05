"""Non-blocking-friendly HTTP notification helpers for analytics alerts.

The analytics pipeline deliberately gives a notifier a small callable interface:
``notifier(alert) -> bool``.  This module keeps the HTTP details here and makes
sure that an alert payload is a summary rather than a copy of an input event.
In particular, credentials, usernames, and ``raw_event`` are never included in
the webhook payload.

The implementation is synchronous because the pipeline currently invokes
notifiers synchronously.  Requests are bounded by a timeout and a small,
configurable retry budget, so a failed endpoint cannot make ingestion hang
indefinitely.  A notifier can be given the pipeline's ``SQLiteStore`` to make
successful notification cooldowns survive a process restart.
"""

from __future__ import annotations

import logging
import os
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from .models import Alert
from .redaction import redact


DEFAULT_URL_ENV = "OPENCANARY_ANALYTICS_WEBHOOK_URL"
DEFAULT_TOKEN_ENV = "OPENCANARY_ANALYTICS_WEBHOOK_TOKEN"
DEFAULT_HMAC_ENV = "OPENCANARY_ANALYTICS_HMAC_KEY"
# Legacy/generic aliases keep the sidecar easy to embed in existing setups.
URL_ENV_ALIASES = (DEFAULT_URL_ENV, "OPENCANARY_WEBHOOK_URL", "WEBHOOK_URL")
TOKEN_ENV_ALIASES = (DEFAULT_TOKEN_ENV, "OPENCANARY_WEBHOOK_TOKEN", "WEBHOOK_TOKEN")
HMAC_ENV_ALIASES = (DEFAULT_HMAC_ENV, "OPENCANARY_HMAC_KEY")
DEFAULT_TIMEOUT = 5.0
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_FACTOR = 0.25
DEFAULT_COOLDOWN_SECONDS = 0
DEFAULT_SUCCESS_CODES = (200, 201, 202, 204)
DEFAULT_RETRY_STATUS_CODES = (408, 425, 429, 500, 502, 503, 504)


class Notifier(ABC):
    """Small interface used by :class:`~opencanary_analytics.pipeline.AnalyticsPipeline`."""

    @abstractmethod
    def notify(self, alert: Alert | Mapping[str, Any]) -> bool:
        """Deliver ``alert`` and return whether it was delivered or suppressed."""

    def __call__(self, alert: Alert | Mapping[str, Any]) -> bool:
        return self.notify(alert)


def _as_alert_dict(alert: Alert | Mapping[str, Any]) -> dict[str, Any]:
    """Get a plain dictionary from an Alert or an Alert-shaped mapping."""
    if isinstance(alert, Alert):
        return alert.to_dict()
    if isinstance(alert, Mapping):
        return dict(alert)
    to_dict = getattr(alert, "to_dict", None)
    if callable(to_dict):
        value = to_dict()
        if isinstance(value, Mapping):
            return dict(value)
    raise TypeError("alert must be an Alert or mapping")


def _utc(value: datetime) -> datetime:
    """Normalize a clock value to an aware UTC datetime."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _iso(value: Any) -> Any:
    """Serialize datetimes without allowing a webhook call to fail on one."""
    if isinstance(value, datetime):
        return _utc(value).isoformat().replace("+00:00", "Z")
    return value


def _env_first(names: Sequence[str]) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _hmac_key(value: bytes | str | None) -> bytes | None:
    if value is None:
        value = _env_first(HMAC_ENV_ALIASES)
    if value is None or value == b"" or value == "":
        return None
    return value if isinstance(value, bytes) else value.encode("utf-8")


def build_alert_payload(
    alert: Alert | Mapping[str, Any],
    *,
    hmac_key: bytes | str | None = None,
) -> dict[str, Any]:
    """Build the deliberately small, redacted payload sent to a webhook.

    The top-level fields are convenient for generic webhook consumers.  The
    nested ``alert`` object retains the complete *alert* contract (which does
    not contain event credentials) for consumers that prefer that shape.  No
    event or ``raw_event`` field is copied into either object.
    """
    source = _as_alert_dict(alert)
    reasons = source.get("reasons", ())
    if not isinstance(reasons, (list, tuple)):
        reasons = []

    # Copy only fields defined by Alert.  This also protects callers passing a
    # larger event-like mapping from accidentally forwarding arbitrary fields.
    allowed = (
        "alert_id",
        "aggregate_id",
        "src_ip",
        "first_seen",
        "last_seen",
        "event_count",
        "unique_ports",
        "unique_protocols",
        "tags",
        "score",
        "severity",
        "reasons",
    )
    clean_alert = {name: _iso(source[name]) for name in allowed if name in source}
    severity = source.get("severity", "unknown")
    source_ip = source.get("src_ip")
    ports = list(source.get("unique_ports", ()) or ())
    protocols = list(source.get("unique_protocols", ()) or ())
    tags = list(source.get("tags", ()) or ())
    score = source.get("score", 0)
    count = source.get("event_count", 0)

    payload: dict[str, Any] = {
        "type": "opencanary.alert",
        "alert_id": source.get("alert_id"),
        "aggregate_id": source.get("aggregate_id"),
        "level": severity,
        "severity": severity,
        "source_ip": source_ip,
        "source": {"ip": source_ip},
        "targets": {"ports": ports, "protocols": protocols},
        "target_ports": ports,
        "target_protocols": protocols,
        "first_seen": _iso(source.get("first_seen")),
        "last_seen": _iso(source.get("last_seen")),
        "event_count": count,
        "count": count,
        "tags": tags,
        "score": score,
        "reasons": list(reasons),
        "alert": clean_alert,
    }
    # ``redact`` is defense in depth for future Alert fields/reason structures;
    # it never turns an HMAC key into a value in the outgoing request.
    result = redact(payload, _hmac_key(hmac_key))
    return result if isinstance(result, dict) else payload


# Friendly aliases for callers that used the terminology "webhook payload".
redacted_alert_payload = build_alert_payload
build_webhook_payload = build_alert_payload


class WebhookNotifier(Notifier):
    """Send redacted Alert summaries to an HTTP endpoint.

    Parameters are intentionally usable without a config framework.  With no
    ``url``, ``OPENCANARY_ANALYTICS_WEBHOOK_URL`` is read.  ``retries`` is the
    number of retries *after* the initial request.  A ``store`` may be a
    ``SQLiteStore`` (or a compatible repository exposing ``query_all``) to
    persist idempotency/cooldown state.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        store: Any | None = None,
        timeout: float | tuple[float, float] = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        cooldown_seconds: int | float = DEFAULT_COOLDOWN_SECONDS,
        hmac_key: bytes | str | None = None,
        headers: Mapping[str, str] | None = None,
        method: str = "POST",
        expected_status: int | Sequence[int] | None = DEFAULT_SUCCESS_CODES,
        retry_statuses: Sequence[int] = DEFAULT_RETRY_STATUS_CODES,
        max_backoff: float = 30.0,
        session: Any | None = None,
        transport: Callable[..., Any] | None = None,
        sleeper: Callable[[float], None] | None = None,
        clock: Callable[[], datetime] | None = None,
        logger: logging.Logger | None = None,
        **options: Any,
    ) -> None:
        # Accept common spellings while keeping the documented constructor
        # compact.  They are useful when options originate in JSON config.
        if options.get("webhook_url") and url is None:
            url = options.pop("webhook_url")
        if "max_retries" in options:
            retries = options.pop("max_retries")
        if "retry_count" in options:
            retries = options.pop("retry_count")
        if "backoff" in options:
            backoff_factor = options.pop("backoff")
        # ``status_code`` is a notifier option, not a requests option.  Pop it
        # even when an explicit expected_status was supplied, otherwise it
        # would be forwarded to requests.request and fail every attempt.
        if "status_code" in options:
            configured_status = options.pop("status_code")
            if expected_status == DEFAULT_SUCCESS_CODES:
                expected_status = configured_status
        if "verify" in options or "params" in options or "auth" in options:
            # These request options are passed to requests, but never included
            # in the JSON payload.
            pass

        self.url = str(url or _env_first(URL_ENV_ALIASES) or "").strip()
        if not self.url:
            raise ValueError(
                f"webhook URL is required (pass url or set {DEFAULT_URL_ENV})"
            )
        if not method or not str(method).strip():
            raise ValueError("HTTP method must not be empty")
        try:
            self.timeout = timeout
            self.retries = max(0, min(int(retries), 10))
            self.backoff_factor = max(0.0, float(backoff_factor))
            self.cooldown_seconds = max(0.0, float(cooldown_seconds))
            self.max_backoff = max(0.0, float(max_backoff))
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout/retry/cooldown settings are invalid") from exc
        self.method = str(method).upper()
        self.store = store
        self.hmac_key = _hmac_key(hmac_key)
        self.headers = {"Content-Type": "application/json"}
        if headers:
            self.headers.update({str(k): str(v) for k, v in headers.items()})
        token = _env_first(TOKEN_ENV_ALIASES)
        if token and not any(key.lower() == "authorization" for key in self.headers):
            self.headers["Authorization"] = f"Bearer {token}"
        self.request_options = dict(options)
        self.success_statuses = self._statuses(expected_status, DEFAULT_SUCCESS_CODES)
        self.retry_statuses = self._statuses(retry_statuses, DEFAULT_RETRY_STATUS_CODES)
        self.session = session
        self.transport = transport
        self.sleeper = sleeper or time.sleep
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.logger = logger or logging.getLogger(__name__)
        self._delivered: set[str] = set()
        self._sent_at: dict[str, datetime] = {}

    @staticmethod
    def _statuses(value: int | Sequence[int] | None, default: Sequence[int]) -> frozenset[int]:
        if value is None:
            return frozenset(default)
        if isinstance(value, int):
            return frozenset({value})
        try:
            return frozenset(int(item) for item in value)
        except (TypeError, ValueError) as exc:
            raise ValueError("HTTP status codes must be integers") from exc

    def build_payload(self, alert: Alert | Mapping[str, Any]) -> dict[str, Any]:
        return build_alert_payload(alert, hmac_key=self.hmac_key)

    def _now(self) -> datetime:
        try:
            return _utc(self.clock())
        except Exception:
            return datetime.now(timezone.utc)

    @staticmethod
    def _row_value(row: Any, name: str, index: int = 0) -> Any:
        if isinstance(row, Mapping):
            return row.get(name)
        try:
            return row[name]
        except (IndexError, KeyError, TypeError):
            try:
                return row[index]
            except (IndexError, KeyError, TypeError):
                return None

    def _stored_state(self, alert_id: str, source_ip: str, now: datetime) -> tuple[bool, bool]:
        """Return ``(already_delivered, cooldown_active)`` from a compatible store."""
        if self.store is None:
            return alert_id in self._delivered, self._cooldown_memory(source_ip, now)
        query_all = getattr(self.store, "query_all", None)
        if not callable(query_all):
            return alert_id in self._delivered, self._cooldown_memory(source_ip, now)
        cutoff = (now - timedelta(seconds=self.cooldown_seconds)).isoformat()
        try:
            current = query_all(
                "SELECT notified_at FROM alerts WHERE alert_id=? LIMIT 1", (alert_id,)
            )
            already = bool(current and self._row_value(current[0], "notified_at"))
            if self.cooldown_seconds <= 0:
                return already, False
            prior = query_all(
                """SELECT alert_id, notified_at FROM alerts
                   WHERE src_ip=? AND created_at>=? AND alert_id<>?
                     AND notified_at IS NOT NULL LIMIT 1""",
                (source_ip, cutoff, alert_id),
            )
            return already, bool(prior)
        except Exception as exc:  # storage failure must not take down ingest
            self.logger.warning("unable to read notification state: %s", exc)
            return alert_id in self._delivered, self._cooldown_memory(source_ip, now)

    def _cooldown_memory(self, source_ip: str, now: datetime) -> bool:
        if self.cooldown_seconds <= 0:
            return False
        sent = self._sent_at.get(source_ip)
        return sent is not None and (now - sent).total_seconds() < self.cooldown_seconds

    def _request(self, payload: dict[str, Any]) -> Any:
        kwargs = dict(self.request_options)
        kwargs.update(
            method=self.method,
            url=self.url,
            json=payload,
            headers=self.headers,
            timeout=self.timeout,
        )
        if self.transport is not None:
            return self.transport(**kwargs)
        requester = self.session.request if self.session is not None else requests.request
        return requester(**kwargs)

    def notify(self, alert: Alert | Mapping[str, Any]) -> bool:
        try:
            source = _as_alert_dict(alert)
            alert_id = str(source.get("alert_id", ""))
            source_ip = str(source.get("src_ip", ""))
            now = self._now()
            already, cooled_down = self._stored_state(alert_id, source_ip, now)
            if already:
                return True
            if cooled_down:
                self.logger.info("notification suppressed by cooldown for %s", source_ip)
                return False
            payload = self.build_payload(source)
            last_error: Exception | None = None
            for attempt in range(self.retries + 1):
                try:
                    response = self._request(payload)
                    status = int(getattr(response, "status_code", response))
                    if status in self.success_statuses:
                        self._delivered.add(alert_id)
                        self._sent_at[source_ip] = now
                        return True
                    last_error = RuntimeError(f"webhook returned HTTP {status}")
                    retryable = status in self.retry_statuses
                except Exception as exc:  # requests and injected transports
                    last_error = exc
                    retryable = True
                if not retryable or attempt >= self.retries:
                    break
                delay = min(self.max_backoff, self.backoff_factor * (2**attempt))
                if delay > 0:
                    self.sleeper(delay)
            self.logger.warning("webhook notification failed: %s", last_error)
            return False
        except Exception as exc:
            # Notification failures are intentionally non-fatal to ingestion.
            self.logger.warning("webhook notification could not be sent: %s", exc)
            return False

    # Convenient names for callers that do not use the pipeline's callable API.
    send = notify
    notify_alert = notify


class SlackNotifier(WebhookNotifier):
    """WebhookNotifier variant emitting Slack Incoming Webhook JSON."""

    def build_payload(self, alert: Alert | Mapping[str, Any]) -> dict[str, Any]:
        summary = build_alert_payload(alert, hmac_key=self.hmac_key)
        reasons = summary.get("reasons", [])
        reason_text = "; ".join(
            str(item.get("reason", item)) if isinstance(item, Mapping) else str(item)
            for item in reasons
        )
        text = (
            f"OpenCanary {summary.get('level', 'unknown')} alert from "
            f"{summary.get('source_ip', 'unknown')} "
            f"(score {summary.get('score', 0)}, {summary.get('count', 0)} events)"
        )
        if reason_text:
            text += f": {reason_text}"
        return {"text": text, "attachments": [{"fields": [
            {"title": "Alert ID", "value": str(summary.get("alert_id", "")), "short": True},
            {"title": "Protocols", "value": ", ".join(map(str, summary.get("target_protocols", []))), "short": True},
            {"title": "Ports", "value": ", ".join(map(str, summary.get("target_ports", []))), "short": True},
        ]}], "alert": summary}


# Name used by a few integrations and intuitive alias for Slack's endpoint.
SlackWebhookNotifier = SlackNotifier


__all__ = [
    "Notifier",
    "WebhookNotifier",
    "SlackNotifier",
    "SlackWebhookNotifier",
    "build_alert_payload",
    "redacted_alert_payload",
    "build_webhook_payload",
]
