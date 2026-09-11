"""Ephemeral Redis cache layer (SPEC.md directive #5 — IMMUTABLE).

Guarantees enforced here and by tests (R5):

* **Every ``SET`` carries a TTL** — :meth:`TTLCache.set` *requires* a positive
  TTL; a caller that tries to write without one gets a
  :class:`TTLViolation` before anything reaches Redis.
* **Cache only** — the app treats Redis as a pure speed-up / session-token
  revocation store. All durable state lives in SQLite + encrypted files. If
  Redis is down the API degrades gracefully (health reports ``"down"``).
* The production Redis is launched with ``--appendonly no --save ""`` so it
  never touches disk (enforced in the ops lane / docker-compose).
"""
from __future__ import annotations

import json
from typing import Any, Optional, Protocol

import redis

from app.config import get_settings


class TTLViolation(RuntimeError):
    """Attempted a Redis SET without a positive TTL (directive #5)."""


class CacheBackend(Protocol):
    """Minimal sync Redis interface the app relies on (fakeredis-compatible)."""

    def set(self, name: str, value: bytes, ex: int) -> Any: ...
    def get(self, name: str) -> Optional[bytes]: ...
    def delete(self, *names: str) -> Any: ...
    def ping(self) -> bool: ...


class TTLCache:
    """Redis wrapper that *cannot* store a key without a TTL."""

    def __init__(self, backend: CacheBackend, default_ttl: int) -> None:
        if default_ttl <= 0:
            raise ValueError("default_ttl must be positive")
        self._backend = backend
        self._default_ttl = default_ttl

    # -- low-level, TTL-enforced --------------------------------------------
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Store ``value`` under ``key``.

        ``value`` is JSON-encoded when it is not already ``bytes``. ``ttl``
        defaults to the app's default TTL; a non-positive explicit TTL is a
        hard error (never silently persist).
        """
        if ttl is None:
            ttl = self._default_ttl
        if ttl <= 0:
            raise TTLViolation("directive #5: every Redis SET must carry a positive TTL")
        payload = bytes(value) if isinstance(value, (bytes, bytearray)) else json.dumps(value).encode()
        self._backend.set(key, payload, ex=int(ttl))

    def get(self, key: str) -> Any:
        raw = self._backend.get(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return raw

    def delete(self, key: str) -> None:
        self._backend.delete(key)

    def ping(self) -> bool:
        try:
            return bool(self._backend.ping())
        except Exception:
            return False


def make_cache(backend: Optional[CacheBackend] = None) -> TTLCache:
    """Build a :class:`TTLCache`.

    When ``backend`` is None (production path) a ``redis.Redis`` client is
    created from ``SECWEB_REDIS_URL`` with a short socket timeout so a dead
    Redis fails fast instead of stalling requests.
    """
    s = get_settings()
    if backend is None:
        backend = redis.Redis.from_url(
            s.redis_url,
            socket_connect_timeout=2,
            socket_timeout=2,
            decode_responses=False,
        )
    return TTLCache(backend, s.default_ttl_seconds)
