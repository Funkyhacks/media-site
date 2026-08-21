"""Integration tests: favorites routes (key-bearing, per-user)."""
from __future__ import annotations

import io


def _upload(client, headers, name="f.txt", data=b"fav data"):
    files = {"file": (name, io.BytesIO(data), "text/plain")}
    return client.post("/api/files/upload", files=files, headers=headers).json()


def test_add_and_list_favorite(client, headers1):
    up = _upload(client, headers1)
    r = client.post(f"/api/favorites/{up['id']}", headers=headers1)
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    r = client.get("/api/favorites", headers=headers1)
    assert r.status_code == 200
    assert r.json() == [{"file_id": up["id"]}]


def test_remove_favorite(client, headers1):
    up = _upload(client, headers1)
    client.post(f"/api/favorites/{up['id']}", headers=headers1)
    r = client.delete(f"/api/favorites/{up['id']}", headers=headers1)
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert client.get("/api/favorites", headers=headers1).json() == []


def test_add_favorite_unknown_file_404(client, headers1):
    r = client.post("/api/favorites/00000000-0000-4000-8000-000000000000", headers=headers1)
    assert r.status_code == 404


def test_add_favorite_requires_keys(client, headers1, user1_id):
    from app.core import auth as authcore
    up = _upload(client, headers1)
    jwt = authcore.create_jwt(user1_id, "alice")
    r = client.post(f"/api/favorites/{up['id']}", headers={"Authorization": f"Bearer {jwt}"})
    assert r.status_code == 403


def test_favorites_isolated_per_user(client, headers1, headers2):
    """D4 tenancy: bob's favorites do not include alice's files."""
    up = _upload(client, headers1)
    client.post(f"/api/favorites/{up['id']}", headers=headers1)
    r = client.get("/api/favorites", headers=headers2)
    assert r.status_code == 200
    assert r.json() == []
    # bob cannot favorite alice's file (not visible to him)
    r2 = client.post(f"/api/favorites/{up['id']}", headers=headers2)
    assert r2.status_code == 404
