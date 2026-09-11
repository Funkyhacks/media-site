"""Encrypted file storage + streaming (SPEC.md directives #3, #4, #5; R3).

Layout (ARCHITECTURE.md, D4 multi-user)::

    <storage>/<user_id>/<file_uuid>.bin        # AES-GCM content, NO extension
    <storage>/<user_id>/thumbs/<file_uuid>_thumb.bin

Guarantees:

* **Obfuscated storage (#4)** — files are named by UUID with ``.bin`` /
  ``_thumb.bin`` suffixes only; the original name/extension/path exist solely
  in the encrypted DB columns.
* **Zero plaintext to disk (R3)** — uploads are encrypted in memory then
  written as ciphertext; downloads are decrypted in small chunks and streamed
  straight to the caller. No decrypted temp file is ever created.
* **Thumbnails** — generated in-memory with Pillow, encrypted, stored as
  ``UUID_thumb.bin``.
"""
from __future__ import annotations

import io
import uuid
from pathlib import Path
from typing import Iterator, Optional

from app.core import crypto


class StorageError(Exception):
    """Raised on storage-layer failures (missing file, bad id, ...)."""


def safe_file_uuid(value: str) -> str:
    """Validate + normalize a file UUID (rejects path traversal)."""
    try:
        return str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise StorageError("invalid file id") from exc


class Store:
    """Filesystem store for per-user encrypted blobs."""

    def __init__(self, root: str) -> None:
        self._root = Path(root).resolve()

    # -- paths ---------------------------------------------------------------
    def _user_dir(self, user_id: int) -> Path:
        return self._root / str(int(user_id))

    def content_path(self, user_id: int, file_uuid: str) -> Path:
        return self._user_dir(user_id) / (safe_file_uuid(file_uuid) + ".bin")

    def thumb_path(self, user_id: int, file_uuid: str) -> Path:
        return self._user_dir(user_id) / "thumbs" / (safe_file_uuid(file_uuid) + "_thumb.bin")

    # -- writes --------------------------------------------------------------
    def save_content(self, user_id: int, file_uuid: str, ciphertext: bytes) -> Path:
        p = self.content_path(user_id, file_uuid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(ciphertext)
        return p

    def save_thumb(self, user_id: int, file_uuid: str, ciphertext: bytes) -> Path:
        p = self.thumb_path(user_id, file_uuid)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(ciphertext)
        return p

    # -- reads ---------------------------------------------------------------
    def read_content(self, user_id: int, file_uuid: str) -> bytes:
        p = self.content_path(user_id, file_uuid)
        if not p.exists():
            raise StorageError("content not found")
        return p.read_bytes()

    def read_thumb(self, user_id: int, file_uuid: str) -> bytes:
        p = self.thumb_path(user_id, file_uuid)
        if not p.exists():
            raise StorageError("thumbnail not found")
        return p.read_bytes()

    def exists(self, user_id: int, file_uuid: str) -> bool:
        return self.content_path(user_id, file_uuid).exists()

    def delete(self, user_id: int, file_uuid: str) -> None:
        for p in (self.content_path(user_id, file_uuid),
                  self.thumb_path(user_id, file_uuid)):
            try:
                p.unlink()
            except FileNotFoundError:
                pass


def decrypt_stream(
    blob: bytes,
    key: crypto.KeyMaterial,
    aad: bytes,
    chunk_size: int = 64 * 1024,
) -> Iterator[bytes]:
    """Decrypt an AES-GCM blob and yield the plaintext in chunks.

    AES-GCM is a single-shot AEAD, so the *ciphertext* is one buffer, but the
    decrypted plaintext is what must never sit on disk (R3). We therefore:

    1. decrypt into a single in-memory buffer (no temp file — R3),
    2. hand that buffer to the caller **in chunks**, so an HTTP handler can
       stream it straight to the socket without ever touching the filesystem.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    plaintext = crypto.decrypt(key, blob, aad)
    for i in range(0, len(plaintext), chunk_size):
        yield plaintext[i : i + chunk_size]


def make_thumbnail(image_bytes: bytes, max_dim: int = 256) -> Optional[bytes]:
    """Generate a JPEG thumbnail in-memory (Pillow). Returns None for
    non-image inputs (video files, unknown types)."""
    try:
        from PIL import Image  # local import keeps Pillow optional at module load
    except Exception:
        return None
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.thumbnail((max_dim, max_dim))
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=82)
        return buf.getvalue()
    except Exception:
        return None
