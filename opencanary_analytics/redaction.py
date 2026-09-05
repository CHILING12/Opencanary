"""Secret handling for events, persistence, and notifications."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from typing import Any


PASSWORD_KEYS = {
    "password",
    "passwd",
    "pass",
    "secret",
    "secret_string",
    "token",
    "access_token",
    "api_key",
    "private_key",
    "client_secret",
    "community_string",
    "password_hash",
}


def _is_secret_key(key: object) -> bool:
    normalized = str(key).lower().replace("-", "_").replace(" ", "_")
    return (
        normalized in PASSWORD_KEYS
        or normalized.endswith("_password")
        or normalized.endswith("_secret")
    )


def mask_secret(value: Any, visible: int = 2) -> str:
    """Return a short, useful display value without exposing the secret."""
    text = str(value)
    if not text:
        return "<empty>"
    if len(text) <= visible * 2:
        return "*" * len(text)
    return text[:visible] + "*" * (len(text) - visible * 2) + text[-visible:]


def fingerprint(value: Any, key: bytes) -> str:
    """Create a stable keyed SHA-256 fingerprint, never a reversible value."""
    if not key:
        raise ValueError("an HMAC key is required")
    return hmac.new(key, str(value).encode("utf-8", "replace"), hashlib.sha256).hexdigest()


def redact(value: Any, key: bytes | None = None) -> Any:
    """Recursively redact secret values and optionally attach their fingerprint."""
    if isinstance(value, Mapping):
        result = {}
        for name, child in value.items():
            if _is_secret_key(name):
                if child is None:
                    result[name] = None
                elif key:
                    result[name] = "hmac-sha256:" + fingerprint(child, key)
                else:
                    result[name] = "<redacted>"
            else:
                result[name] = redact(child, key)
        return result
    if isinstance(value, (list, tuple, set)):
        return [redact(item, key) for item in value]
    return value


def secret_value(event: Mapping[str, Any]) -> Any:
    """Extract a password from legacy OpenCanary event data."""
    data = event.get("logdata", {})
    if not isinstance(data, Mapping):
        return None
    for key, value in data.items():
        if str(key).lower() in {"password", "passwd", "pass"}:
            return value
    return None
