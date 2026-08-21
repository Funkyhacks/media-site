"""Integration tests: auth routes (register / login / logout) + directive #6.

These run the full FastAPI stack against a hermetic env (temp SQLite, fakeredis,
temp store) — the real repo + crypto, not mocks.
"""
from __future__ import annotations

import base64

import pytest

from tests.conftest import USER1, USER2, _b64


def _reg(client, spec):
    return client.post("/api/auth/register", json={
        "username": spec["username"], "password": spec["password"],
        "key1": _b64(spec["key1"]), "key2": _b64(spec["key2"]),
    })


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["redis"] == "up"
    assert "version" in body


def test_register_success(client):
    r = _reg(client, USER1)
    assert r.status_code == 201
    body = r.json()
    assert body["user_id"] == 1
    assert body["jwt"]
    # directive #6: no-store on the auth surface
    assert r.headers.get("Cache-Control") == "no-store"


def test_register_duplicate_409(client):
    assert _reg(client, USER1).status_code == 201
    r = _reg(client, USER1)
    assert r.status_code == 409
    assert "detail" in r.json()


def test_register_requires_both_keys(client):
    r = client.post("/api/auth/register", json={
        "username": "noperm", "password": "pw", "key1": _b64(b"only-one"),
    })
    assert r.status_code == 422  # pydantic: key2 required


def test_login_success(client):
    _reg(client, USER1)
    r = client.post("/api/auth/login", json={
        "username": USER1["username"], "password": USER1["password"],
        "key1": _b64(USER1["key1"]), "key2": _b64(USER1["key2"]),
    })
    assert r.status_code == 200
    body = r.json()
    assert body["user_id"] == 1
    assert body["jwt"]
    assert r.headers.get("Cache-Control") == "no-store"


def test_login_wrong_password_401(client):
    _reg(client, USER1)
    r = client.post("/api/auth/login", json={
        "username": USER1["username"], "password": "WRONG",
        "key1": _b64(USER1["key1"]), "key2": _b64(USER1["key2"]),
    })
    assert r.status_code == 401


def test_login_unknown_user_401(client):
    r = client.post("/api/auth/login", json={
        "username": "ghost", "password": "pw",
        "key1": _b64(b"k1"), "key2": _b64(b"k2"),
    })
    assert r.status_code == 401


def test_login_wrong_security_keys_401(client):
    """Directive #2: wrong key pair must be rejected even with valid password."""
    _reg(client, USER1)
    r = client.post("/api/auth/login", json={
        "username": USER1["username"], "password": USER1["password"],
        "key1": _b64(b"WRONG-K1"), "key2": _b64(b"WRONG-K2"),
    })
    assert r.status_code == 401


def test_logout(client, user1_id, jwt1):
    r = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {jwt1}"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert r.headers.get("Cache-Control") == "no-store"


def test_jwt_is_rejected_after_user_deletion(client, env, jwt1):
    """A JWT alone is not enough once the user is gone."""
    env.db.execute("DELETE FROM Users WHERE id=1")
    r = client.get("/api/folders", headers={"Authorization": f"Bearer {jwt1}"})
    assert r.status_code == 401
