"""SQLite schema (SPEC.md §Database — binding).

Tables: ``Users``, ``Folders``, ``Files``, ``Favorites``.

Directive #3 (IMMUTABLE): ``original_name``, ``extension`` and ``folder_path``
are stored **only** as encrypted blobs (hex strings) — never plaintext. Folder
names are likewise stored encrypted only; the API decrypts them per request
with the caller's keys.
Directive #4: physical files carry no original name/extension; the mapping
exists only in these encrypted columns.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS Users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    wrapped_meta_key TEXT   NOT NULL,      -- AES-GCM(master, meta_key, aad=b"meta"), hex
    key_salt        TEXT    NOT NULL,      -- per-user 16-byte HKDF salt, hex
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS Folders (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
    encrypted_name  TEXT    NOT NULL,      -- AES-GCM(meta_key, name, aad=b"folder"), hex
    parent_id       INTEGER REFERENCES Folders(id) ON DELETE CASCADE,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS Files (
    id              TEXT    PRIMARY KEY,   -- random UUID (obfuscated storage, #4)
    user_id         INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
    folder_id       INTEGER REFERENCES Folders(id) ON DELETE SET NULL,
    original_name   TEXT    NOT NULL,      -- AES-GCM(meta_key, name), hex
    extension       TEXT    NOT NULL,      -- AES-GCM(meta_key, ext), hex
    folder_path     TEXT    NOT NULL,      -- AES-GCM(meta_key, path), hex
    content_key     TEXT    NOT NULL,      -- AES-GCM(master, content_key, aad=file_id), hex
    content_salt    TEXT    NOT NULL,      -- per-file 16-byte HKDF salt, hex
    content_type    TEXT    NOT NULL DEFAULT 'application/octet-stream',
    size            INTEGER NOT NULL,      -- plaintext byte size
    thumb_id        TEXT,                  -- NULL or the file UUID (thumb stored as <uuid>_thumb.bin)
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS Favorites (
    user_id   INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
    file_id   TEXT    NOT NULL REFERENCES Files(id) ON DELETE CASCADE,
    created_at TEXT   NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (user_id, file_id)
);

CREATE INDEX IF NOT EXISTS idx_files_user_folder ON Files(user_id, folder_id);
CREATE INDEX IF NOT EXISTS idx_folders_user      ON Folders(user_id);
"""


class Database:
    """A thin, thread-safe sqlite3 wrapper.

    One connection, serialized with a lock (the API is synchronous; tests use
    a single worker thread via ``TestClient``). Foreign keys are enforced.
    """

    def __init__(self, path: str) -> None:
        import threading

        self.path = str(path)
        p = Path(self.path)
        if p.parent and str(p.parent) not in (".", ""):
            p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)

    # -- primitives ----------------------------------------------------------
    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock, self._conn:
            return self._conn.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def scalar(self, sql: str, params: tuple = ()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            row = cur.fetchone()
            return row[0] if row is not None else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
