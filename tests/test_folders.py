"""Integration tests: folder routes + directive #3 (encrypted folder names)."""
from __future__ import annotations

from tests.conftest import USER1


def test_create_folder(client, headers1):
    r = client.post("/api/folders", json={"name": "Movies"}, headers=headers1)
    assert r.status_code == 201
    assert r.json()["id"] == 1


def test_create_subfolder(client, headers1):
    top = client.post("/api/folders", json={"name": "Media"}, headers=headers1).json()["id"]
    sub = client.post("/api/folders", json={"name": "2026", "parent_id": top}, headers=headers1)
    assert sub.status_code == 201


def test_create_folder_bad_parent_404(client, headers1):
    r = client.post("/api/folders", json={"name": "X", "parent_id": 999}, headers=headers1)
    assert r.status_code == 404


def test_list_folders_returns_decrypted_name(client, headers1):
    client.post("/api/folders", json={"name": "Music"}, headers=headers1)
    client.post("/api/folders", json={"name": "Photos"}, headers=headers1)
    r = client.get("/api/folders", headers=headers1)
    assert r.status_code == 200
    names = [f["name"] for f in r.json()]
    assert names == ["Music", "Photos"]


def test_folder_row_is_encrypted_in_db(env, headers1, client, user1_id):
    """Directive #3: folder names are stored ONLY in encrypted form."""
    client.post("/api/folders", json={"name": "SecretFolderName"}, headers=headers1)
    row = env.db.query("SELECT encrypted_name FROM Folders WHERE user_id=?", (user1_id,))[0]
    enc = row["encrypted_name"]
    assert "SecretFolderName" not in enc  # plaintext must not appear in the DB
    assert len(bytes.fromhex(enc)) > 12


def test_folder_name_not_plaintext_in_db(env, user1_id, client, headers1):
    client.post("/api/folders", json={"name": "topsecret"}, headers=headers1)
    # raw table scan must not expose the name
    for row in env.db.query("SELECT * FROM Folders WHERE user_id=?", (user1_id,)):
        assert b"topsecret" not in str(row["encrypted_name"]).encode()


def test_list_folders_requires_keys(client, user1_id):
    """Valid JWT but missing security headers -> 403 (key-lifecycle rule)."""
    from app.core import auth as authcore
    jwt = authcore.create_jwt(user1_id, USER1["username"])
    r = client.get("/api/folders", headers={"Authorization": f"Bearer {jwt}"})
    assert r.status_code == 403


def test_list_folders_wrong_keys_403(client, headers1):
    h = dict(headers1)
    h["X-Sec-Key-1"] = "AAAA"
    h["X-Sec-Key-2"] = "BBBB"
    r = client.get("/api/folders", headers=h)
    assert r.status_code == 403
    # must NOT leak any plaintext
    assert "detail" in r.json()


def test_folders_isolated_per_user(client, headers1, headers2, user2_id):
    """D4 tenancy: user2 must not see user1's folders."""
    client.post("/api/folders", json={"name": "AliceOnly"}, headers=headers1)
    r = client.get("/api/folders", headers=headers2)
    assert r.status_code == 200
    assert [f["name"] for f in r.json()] == []


def test_file_count_reflects_uploads(client, headers1, user1_id):
    fid = client.post("/api/folders", json={"name": "Clips"}, headers=headers1).json()["id"]
    # upload a dummy file
    import io
    files = {"file": ("a.txt", io.BytesIO(b"hello"), "text/plain")}
    up = client.post("/api/files/upload", files=files, data={"folder_id": fid}, headers=headers1)
    assert up.status_code == 201
    r = client.get("/api/folders", headers=headers1)
    counts = {f["id"]: f["file_count"] for f in r.json()}
    assert counts[fid] == 1
