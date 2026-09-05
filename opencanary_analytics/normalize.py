"""Convert legacy OpenCanary JSON lines into a stable event contract."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .models import NormalizedEvent
from .redaction import redact, secret_value, fingerprint
from .rules import DEFAULT_USERS, WEAK_PASSWORDS


LOGTYPE_MAP = {
    2000: ("ftp", "login_attempt"),
    2001: ("ftp", "auth_initiated"),
    3000: ("http", "get"),
    3001: ("http", "login_attempt"),
    3002: ("http", "unimplemented_method"),
    3003: ("http", "redirect"),
    4000: ("ssh", "connection"),
    4001: ("ssh", "version"),
    4002: ("ssh", "login_attempt"),
    5000: ("smb", "file_open"),
    5001: ("tcp", "port_scan_syn"),
    5002: ("tcp", "port_scan_nmap_os"),
    5003: ("tcp", "port_scan_nmap_null"),
    5004: ("tcp", "port_scan_nmap_xmas"),
    5005: ("tcp", "port_scan_nmap_fin"),
    6001: ("telnet", "login_attempt"),
    6002: ("telnet", "connection"),
    7001: ("http_proxy", "login_attempt"),
    8001: ("mysql", "login_attempt"),
    9001: ("mssql", "login_attempt"),
    9002: ("mssql", "login_attempt"),
    9003: ("mysql", "connection"),
    10001: ("tftp", "request"),
    11001: ("ntp", "monlist"),
    12001: ("vnc", "connection"),
    13001: ("snmp", "command"),
    14001: ("rdp", "connection"),
    15001: ("sip", "request"),
    16001: ("git", "clone_request"),
    17001: ("redis", "command"),
    18001: ("tcp_banner", "connection"),
    18002: ("tcp_banner", "keep_alive_connection"),
    18003: ("tcp_banner", "keep_alive_secret"),
    18004: ("tcp_banner", "keep_alive_data"),
    18005: ("tcp_banner", "data"),
    19001: ("llmnr", "query_response"),
    20001: ("mongodb", "login_attempt"),
}


def _as_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _port(value: Any) -> int | None:
    try:
        number = int(value)
        return number if 0 <= number <= 65535 else None
    except (TypeError, ValueError):
        return None


def parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = _as_text(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for pattern in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _payload(event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("logdata")
    return data if isinstance(data, dict) else {}


def normalize_event(
    event: dict[str, Any], hmac_key: bytes, max_field_length: int = 4096
) -> NormalizedEvent:
    """Normalize an already decoded legacy event; raise ValueError if unusable."""
    if not isinstance(event, dict):
        raise ValueError("event must be a JSON object")
    timestamp = (
        parse_timestamp(event.get("timestamp"))
        or parse_timestamp(event.get("utc_time"))
        or parse_timestamp(event.get("local_time"))
        or datetime.now(timezone.utc)
    )
    logtype = event.get("logtype")
    try:
        logtype_number = int(logtype)
    except (TypeError, ValueError):
        logtype_number = -1
    protocol, event_type = LOGTYPE_MAP.get(
        logtype_number, ("unknown", "logtype_" + str(logtype_number))
    )
    logdata = _payload(event)
    # MongoDB and user modules may provide their own semantic action.
    action = logdata.get("action")
    if isinstance(action, str) and "." in action:
        protocol, event_type = action.split(".", 1)
    username = logdata.get("USERNAME", logdata.get("username"))
    password = secret_value(event)
    clean = redact(event, hmac_key)
    raw_json = json.dumps(clean, sort_keys=True, ensure_ascii=False, default=str)
    supplied_id = event.get("event_id")
    if supplied_id is not None and _as_text(supplied_id):
        event_id = _as_text(supplied_id)
    else:
        event_id = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
    user_text = _as_text(username)[:max_field_length] if username is not None else None
    password_hash = fingerprint(password, hmac_key) if password is not None else None
    login_event = event_type in {"login_attempt", "auth_initiated", "auth_attempt"}
    weak_credential = login_event and (
        _as_text(username).lower() in DEFAULT_USERS
        or (password is not None and _as_text(password).lower() in WEAK_PASSWORDS)
    )
    user_agent = logdata.get("USERAGENT", logdata.get("user_agent"))
    return NormalizedEvent(
        event_id=event_id if len(event_id) <= 128 else hashlib.sha256(
            event_id.encode("utf-8", "replace")
        ).hexdigest(),
        timestamp=timestamp,
        node_id=_as_text(event.get("node_id"), "unknown")[:max_field_length],
        src_ip=_as_text(event.get("src_ip", event.get("src_host")), "unknown")[:max_field_length],
        src_port=_port(event.get("src_port")),
        dst_ip=_as_text(event.get("dst_ip", event.get("dst_host")), "unknown")[:max_field_length],
        dst_port=_port(event.get("dst_port")),
        protocol=protocol[:64],
        event_type=event_type[:128],
        username=user_text,
        password_hash=password_hash,
        user_agent=_as_text(user_agent)[:max_field_length] if user_agent is not None else None,
        raw_event=clean,
        weak_credential=weak_credential,
    )


def parse_line(line: str | bytes, hmac_key: bytes) -> NormalizedEvent:
    try:
        decoded = json.loads(line)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON") from exc
    return normalize_event(decoded, hmac_key)
