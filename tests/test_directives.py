"""Security-directive regression tests (the 6 immutable directives + R2/R3/R5).

These tests encode the IMMUTABLE release-gate from SPEC.md so any future
regression fails loudly.
"""
from __future__ import annotations

import io
from pathlib import Path

from app.core import crypto
from app.core.keys import key_scope
from tests.conftest import USER1, USER2, _b64


def test_d1_dual_key_single_key_insufficient(env, user1_id):
    """Directive #1: content/metadata only decrypt with BOTH keys."""
    from app.core import crypto
    from app.models.repo import Repository

    repo = env.repo
    user = repo.get_user(user1_id)
    # derive with key1 only (key2 empty) must be refused
    try:
        crypto.derive_master_key(USER1["key1"], b"", bytes.fromhex(user.key_salt))
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_d2_zero_knowledge_keys_never_persisted(env, client, headers1):
    """Directive #2: the raw security keys must not appear in the DB."""
    client.post("/api/folders", json={"name": "F"}, headers=headers1)
    raw = (env.tmp / "db.sqlite").read_bytes()
    assert USER1["key1"] not in raw
    assert USER1["key2"] not in raw
    assert b"K1-alice" not in raw
    assert b"K2-alice" not in raw


def test_d2_wrong_keys_leak_nothing_anywhere(client, headers1, headers2, user1_id):
    """Key-lifecycle: wrong keys -> 403 on every key-bearing route, no plaintext."""
    files = {"file": ("leak.txt", io.BytesIO(b"DO-NOT-LEAK-MARKER"), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    bad1 = dict(headers1); bad1["X-Sec-Key-1"] = "AAAA"
    bad2 = dict(headers1); bad2["X-Sec-Key-2"] = "BBBB"
    for h in (bad1, bad2):
        for path in ("/api/folders", f"/api/files", f"/api/files/{up['id']}/content",
                     f"/api/files/{up['id']}/thumb", "/api/favorites"):
            r = client.get(path, headers=h)
            assert r.status_code == 403, (path, r.status_code)
            assert b"DO-NOT-LEAK-MARKER" not in r.content
            assert "DO-NOT-LEAK-MARKER" not in r.text


def test_d3_metadata_encrypted_not_readable_without_keys(env, user1_id, client, headers1):
    """Directive #3: raw DB scan reveals no plaintext metadata."""
    files = {"file": ("needle-in-haystack.txt", io.BytesIO(b"x"), "text/plain")}
    client.post("/api/files/upload", files=files, headers=headers1)
    db_bytes = (env.tmp / "db.sqlite").read_bytes()
    assert b"needle-in-haystack" not in db_bytes


def test_d4_cross_user_key_cannot_decrypt_other_user(env, user1_id, user2_id, client, headers1, headers2):
    """Directive #4: one user's key material must never decrypt another's data."""
    from app.core import crypto
    from app.models.repo import Repository

    # alice uploads a file
    files = {"file": ("alice.txt", io.BytesIO(b"alice-secret-payload"), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()

    # try to unwrap alice's content key using BOB's derived master key
    bob = env.repo.get_user(user2_id)
    alice_rec = env.repo.get_file(user1_id, up["id"])
    bob_master = crypto.derive_master_key(USER2["key1"], USER2["key2"], bytes.fromhex(bob.key_salt))
    try:
        crypto.unwrap_key(bob_master, bytes.fromhex(alice_rec.content_key), aad=up["id"].encode())
        raise AssertionError("bob's master key must NOT unwrap alice's content key")
    except crypto.DecryptionError:
        pass


def test_d5_every_redis_write_has_ttl(env):
    """Directive #5 / R5: the cache layer refuses TTL-less writes."""
    from app.core.cache import TTLViolation

    try:
        env.cache.set("no-ttl-key", "value", ttl=0)
        raise AssertionError("expected TTLViolation")
    except TTLViolation:
        pass
    # and a normal write does carry a TTL
    env.cache.set("ok-key", "value")
    assert env.cache._backend.ttl("ok-key") > 0


def test_d6_auth_surface_no_store(client):
    """Directive #6: auth endpoints send Cache-Control: no-store."""
    r = client.post("/api/auth/register", json={
        "username": "nocache", "password": "pw",
        "key1": _b64(b"K1-0123456789abcdef"), "key2": _b64(b"K2-0123456789abcdef"),
    })
    assert r.headers.get("Cache-Control") == "no-store"


def test_zeroize_after_use(env):
    """Standing default: derived key material is zeroizable and zeroized."""
    k = crypto.SecretBytes(b"\xAB" * 32)
    with key_scope(k):
        assert bytes(k) == b"\xAB" * 32
    assert bytes(k) == b"\x00" * 32


def test_zeroize_on_exception(env):
    """key_scope zeroizes even when the body raises."""
    k = crypto.SecretBytes(b"\xCD" * 32)
    try:
        with key_scope(k):
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert bytes(k) == b"\x00" * 32


def test_r3_no_temp_files_created(client, headers1, env):
    """R3: download must not create decrypted temp files in the storage tree."""
    files = {"file": ("big.txt", io.BytesIO(b"Z" * 5000), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    before = {p for p in (env.tmp / "storage").rglob("*")}
    client.get(f"/api/files/{up['id']}/content", headers=headers1)
    after = {p for p in (env.tmp / "storage").rglob("*")}
    new = after - before
    # the only allowed new entries are none — no temp files may appear
    assert new == set(), f"unexpected new files on disk: {new}"
