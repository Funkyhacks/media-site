"""Unit tests for the TTL-enforced cache (directive #5 / R5)."""
from __future__ import annotations

import time

import fakeredis
import pytest

from app.core.cache import TTLCache, TTLViolation


def _cache(default_ttl: int = 60) -> tuple[TTLCache, fakeredis.FakeRedis]:
    backend = fakeredis.FakeRedis(decode_responses=False)
    return TTLCache(backend, default_ttl), backend


def test_set_requires_positive_ttl():
    cache, _ = _cache()
    with pytest.raises(TTLViolation):
        cache.set("k", "v", ttl=0)
    with pytest.raises(TTLViolation):
        cache.set("k", "v", ttl=-5)


def test_set_uses_default_ttl_when_omitted():
    cache, backend = _cache(default_ttl=7)
    cache.set("k", {"a": 1})
    assert backend.ttl("k") is not None and backend.ttl("k") > 0 and backend.ttl("k") <= 7


def test_roundtrip_dict():
    cache, _ = _cache()
    cache.set("k", {"a": 1, "b": [1, 2, 3]})
    assert cache.get("k") == {"a": 1, "b": [1, 2, 3]}


def test_roundtrip_bytes():
    cache, _ = _cache()
    cache.set("k", b"\x00\x01\x02", ttl=10)
    assert cache.get("k") == b"\x00\x01\x02"


def test_ttl_expires():
    cache, backend = _cache()
    cache.set("k", "v", ttl=1)
    assert cache.get("k") == "v"
    # fakeredis honours real time
    time.sleep(1.1)
    assert cache.get("k") is None


def test_delete():
    cache, _ = _cache()
    cache.set("k", "v")
    cache.delete("k")
    assert cache.get("k") is None


def test_ping_up():
    cache, _ = _cache()
    assert cache.ping() is True


def test_default_ttl_must_be_positive():
    with pytest.raises(ValueError):
        TTLCache(fakeredis.FakeRedis(), 0)
