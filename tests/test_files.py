"""Integration tests: file upload / list / content / thumb + directives #3,#4 and R3.

R3 (zero plaintext to disk) is verified by scanning the storage tree: after an
upload the only bytes on disk are the UUID ciphertexts — the original plaintext
and filename never appear in any file or path.
"""
from __future__ import annotations

import io
import uuid
from pathlib import Path

from PIL import Image


def make_png(w=64, h=64, color=(200, 30, 30)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (w, h), color).save(buf, format="PNG")
    return buf.getvalue()


def test_upload_returns_id_and_thumb(client, headers1):
    data = make_png()
    files = {"file": ("photo.png", io.BytesIO(data), "image/png")}
    r = client.post("/api/files/upload", files=files, headers=headers1)
    assert r.status_code == 201
    body = r.json()
    # id must be a UUID (obfuscated storage, directive #4)
    uuid.UUID(body["id"])
    assert body["thumb_id"] == body["id"]  # png -> thumbnail generated


def test_upload_text_file_no_thumb(client, headers1):
    files = {"file": ("notes.txt", io.BytesIO(b"hello world"), "text/plain")}
    r = client.post("/api/files/upload", files=files, headers=headers1)
    assert r.status_code == 201
    assert r.json()["thumb_id"] is None


def test_upload_empty_rejected(client, headers1):
    files = {"file": ("empty.txt", io.BytesIO(b""), "text/plain")}
    r = client.post("/api/files/upload", files=files, headers=headers1)
    assert r.status_code == 400


def test_download_roundtrip_text(client, headers1):
    payload = b"the quick brown fox jumps over the lazy dog" * 100
    files = {"file": ("secret.txt", io.BytesIO(payload), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    r = client.get(f"/api/files/{up['id']}/content", headers=headers1)
    assert r.status_code == 200
    assert r.content == payload
    assert r.headers["content-type"].startswith("text/plain")
    assert r.headers["cache-control"] == "no-store"


def test_download_roundtrip_image_and_thumb(client, headers1):
    png = make_png(320, 240, (10, 200, 10))
    files = {"file": ("img.png", io.BytesIO(png), "image/png")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    # full content decrypts back to the original bytes
    r = client.get(f"/api/files/{up['id']}/content", headers=headers1)
    assert r.content == png
    # thumb decrypts to a valid JPEG
    t = client.get(f"/api/files/{up['id']}/thumb", headers=headers1)
    assert t.status_code == 200
    assert t.headers["content-type"] == "image/jpeg"
    thumb_img = Image.open(io.BytesIO(t.content))
    assert thumb_img.format == "JPEG"
    assert max(thumb_img.size) <= 256  # thumbnail was downscaled


def test_storage_layout_directive4(client, headers1, env):
    """Directive #4: on disk there is only <user>/<uuid>.bin + thumbs/<uuid>_thumb.bin."""
    files = {"file": ("original-name.png", io.BytesIO(make_png()), "image/png")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    root: Path = env.tmp / "storage" / str(1)
    blobs = sorted(p.name for p in root.iterdir())
    # the encrypted content blob + the thumbs directory
    assert up["id"] + ".bin" in blobs
    assert "thumbs" in blobs
    assert blobs.count(up["id"] + ".bin") == 1
    thumbs = sorted(p.name for p in (root / "thumbs").iterdir())
    assert thumbs == [up["id"] + "_thumb.bin"]
    # no extension revealing the original type, no original name anywhere
    for p in root.rglob("*"):
        assert "original-name" not in p.name


def test_zero_plaintext_on_disk_R3(client, headers1, env):
    """R3: the uploaded plaintext must never appear in any file on disk."""
    secret = b"ULTRA-SECRET-PLAINTEXT-MARKER-0123456789" * 50
    files = {"file": ("doc.txt", io.BytesIO(secret), "text/plain")}
    client.post("/api/files/upload", files=files, headers=headers1)
    for p in (env.tmp / "storage").rglob("*"):
        if p.is_file():
            assert secret not in p.read_bytes()
            assert b"ULTRA-SECRET" not in p.read_bytes()


def test_ciphertext_differs_from_plaintext(client, headers1, env):
    payload = b"AAAA" * 4096
    files = {"file": ("a.bin", io.BytesIO(payload), "application/octet-stream")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    blob = (env.tmp / "storage" / "1" / (up["id"] + ".bin")).read_bytes()
    assert payload not in blob
    # nonce(12) || ct(payload+16)
    assert len(blob) == 12 + len(payload) + 16


def test_list_files_decrypts_metadata(client, headers1):
    files = {"file": ("holiday.png", io.BytesIO(make_png()), "image/png")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    r = client.get("/api/files", headers=headers1)
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1
    item = items[0]
    assert item["id"] == up["id"]
    assert item["name"] == "holiday.png"
    assert item["extension"] == "png"
    assert item["size"] == len(make_png())
    assert item["thumb_id"] == up["id"]


def test_metadata_encrypted_in_db_directive3(env, user1_id, client, headers1):
    """Directive #3: original_name / extension / folder_path are encrypted blobs."""
    files = {"file": ("super-secret-filename.txt", io.BytesIO(b"data"), "text/plain")}
    client.post("/api/files/upload", files=files, headers=headers1)
    rows = env.db.query("SELECT * FROM Files WHERE user_id=?", (user1_id,))
    assert rows
    row = rows[0]
    for col in ("original_name", "extension", "folder_path"):
        val = row[col]
        assert "super-secret-filename" not in val
        assert len(bytes.fromhex(val)) >= 12 + 16  # nonce + tag minimum


def test_content_requires_correct_keys_403(client, headers1, user1_id):
    from app.core import auth as authcore
    files = {"file": ("x.txt", io.BytesIO(b"top secret data"), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    jwt = authcore.create_jwt(user1_id, "alice")
    bad = {"Authorization": f"Bearer {jwt}", "X-Sec-Key-1": "AAAA", "X-Sec-Key-2": "BBBB"}
    r = client.get(f"/api/files/{up['id']}/content", headers=bad)
    assert r.status_code == 403
    assert b"top secret data" not in r.content  # no plaintext leak


def test_content_missing_keys_403(client, headers1, user1_id):
    files = {"file": ("y.txt", io.BytesIO(b"data"), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    from app.core import auth as authcore
    jwt = authcore.create_jwt(user1_id, "alice")
    r = client.get(f"/api/files/{up['id']}/content", headers={"Authorization": f"Bearer {jwt}"})
    assert r.status_code == 403


def test_cross_user_cannot_read_file(client, headers1, headers2, user2_id):
    """D4 tenancy: bob cannot read or even see alice's file."""
    files = {"file": ("alice-only.txt", io.BytesIO(b"alice data"), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    # 404 (not 403) — must not even confirm the file exists
    r = client.get(f"/api/files/{up['id']}/content", headers=headers2)
    assert r.status_code == 404
    assert b"alice data" not in r.content
    # bob's listing is empty
    assert client.get("/api/files", headers=headers2).json() == []


def test_content_type_default(client, headers1):
    files = {"file": ("mystery", io.BytesIO(b"\x00\x01\x02"), None)}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    r = client.get(f"/api/files/{up['id']}/content", headers=headers1)
    assert r.headers["content-type"] == "application/octet-stream"


def test_missing_file_404(client, headers1):
    r = client.get("/api/files/00000000-0000-4000-8000-000000000000/content", headers=headers1)
    assert r.status_code == 404


def test_thumb_404_for_non_image(client, headers1):
    files = {"file": ("t.txt", io.BytesIO(b"txt"), "text/plain")}
    up = client.post("/api/files/upload", files=files, headers=headers1).json()
    r = client.get(f"/api/files/{up['id']}/thumb", headers=headers1)
    assert r.status_code == 404


def test_upload_requires_auth(client):
    files = {"file": ("z.txt", io.BytesIO(b"zz"), "text/plain")}
    r = client.post("/api/files/upload", files=files)
    assert r.status_code == 401
