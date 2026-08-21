"""Repository — ties the crypto core to SQLite.

This is where the zero-knowledge model is *proven*: every metadata field is
encrypted with a per-user ``meta_key`` (wrapped under the request's derived
master key) and every file's content key is wrapped under that same master
key. A request that presents the wrong ``X-Sec-Key-1``/``X-Sec-Key-2`` fails
at :meth:`Repository.derive` / unwrap and the API returns 403 — no plaintext
is ever returned (SPEC.md key-lifecycle rule).
"""
from __future__ import annotations

import bcrypt
import os
from dataclasses import dataclass
from typing import Optional

from app.core import crypto
from app.core.crypto import KEY_LEN, SALT_LEN, DecryptionError, KeyMaterial, SecretBytes
from app.models.schema import Database


class AuthError(Exception):
    """Wrong credentials / username (API -> 401)."""


class UserExists(AuthError):
    """Username already registered (API -> 409)."""


class KeyRejected(Exception):
    """Security keys do not match (API -> 403, no plaintext leaked)."""


class NotFound(Exception):
    """Resource not found for this user (API -> 404)."""


# --- row dataclasses ---------------------------------------------------------
@dataclass
class User:
    id: int
    username: str
    password_hash: str
    wrapped_meta_key: str
    key_salt: str


@dataclass
class Folder:
    id: int
    user_id: int
    encrypted_name: str
    parent_id: Optional[int]
    created_at: str


@dataclass
class FileRecord:
    id: str
    user_id: int
    folder_id: Optional[int]
    original_name: str
    extension: str
    folder_path: str
    content_key: str
    content_salt: str
    content_type: str
    size: int
    thumb_id: Optional[str]
    created_at: str


def _hex(b: bytes) -> str:
    return b.hex()


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def _lastrowid(cur) -> int:
    lid = cur.lastrowid
    if lid is None:  # pragma: no cover - sqlite3 always sets lastrowid on INSERT
        raise RuntimeError("INSERT did not return a lastrowid")
    return int(lid)


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=10)).decode()


def _check_password(password: str, stored: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), stored.encode())
    except ValueError:
        return False


class Repository:
    """All persistence + per-request crypto for one user's data."""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ============================ USERS =====================================
    def user_exists(self, username: str) -> bool:
        return self.db.scalar(
            "SELECT id FROM Users WHERE username=?", (username,)
        ) is not None

    def get_user(self, user_id: int) -> User:
        rows = self.db.query("SELECT * FROM Users WHERE id=?", (user_id,))
        if not rows:
            raise NotFound("user not found")
        r = rows[0]
        return User(
            id=r["id"], username=r["username"], password_hash=r["password_hash"],
            wrapped_meta_key=r["wrapped_meta_key"], key_salt=r["key_salt"],
        )

    def get_user_by_username(self, username: str) -> User:
        rows = self.db.query("SELECT * FROM Users WHERE username=?", (username,))
        if not rows:
            raise AuthError("invalid credentials")
        r = rows[0]
        return User(
            id=r["id"], username=r["username"], password_hash=r["password_hash"],
            wrapped_meta_key=r["wrapped_meta_key"], key_salt=r["key_salt"],
        )

    def register(self, username: str, password: str, key1: bytes, key2: bytes) -> User:
        if self.user_exists(username):
            raise UserExists("username already registered")
        if not key1 or not key2:
            raise AuthError("both security keys are required")

        # per-user fixed HKDF salt for the meta-key wrap (binding contract)
        key_salt = os.urandom(SALT_LEN)
        master = crypto.derive_master_key(key1, key2, key_salt)
        try:
            meta_key = os.urandom(KEY_LEN)
            wrapped_meta = crypto.wrap_key(master, meta_key, aad=b"meta")
            pw = _hash_password(password)
            cur = self.db.execute(
                "INSERT INTO Users (username, password_hash, wrapped_meta_key, key_salt)"
                " VALUES (?,?,?,?)",
                (username, pw, _hex(wrapped_meta), _hex(key_salt)),
            )
            user_id = _lastrowid(cur)
        finally:
            crypto.zeroize(master)
            crypto.zeroize(meta_key)
        return self.get_user(user_id)

    def login(self, username: str, password: str, key1: bytes, key2: bytes) -> User:
        user = self.get_user_by_username(username)  # raises AuthError if missing
        if not _check_password(password, user.password_hash):
            raise AuthError("invalid credentials")
        # Prove the caller holds the correct security keys (else 403 downstream);
        # unwrap-and-discard here to validate before minting a JWT.
        master = crypto.derive_master_key(key1, key2, _unhex(user.key_salt))
        try:
            crypto.unwrap_key(master, _unhex(user.wrapped_meta_key), aad=b"meta")
        except DecryptionError as exc:
            raise KeyRejected("security keys do not match") from exc
        finally:
            crypto.zeroize(master)
        return user

    # ============= per-request key derivation (key-bearing routes) =========
    def derive_master(self, user: User, key1: bytes, key2: bytes) -> SecretBytes:
        """Derive this request's master key. Raises :class:`KeyRejected` on a
        wrong-key pair (the wrapped meta key will not unwrap)."""
        master = crypto.derive_master_key(key1, key2, _unhex(user.key_salt))
        try:
            crypto.unwrap_key(master, _unhex(user.wrapped_meta_key), aad=b"meta")
        except DecryptionError as exc:
            crypto.zeroize(master)
            raise KeyRejected("security keys do not match") from exc
        return master  # caller owns zeroization via key_scope

    def unwrap_meta_key(self, master: SecretBytes, user: User) -> SecretBytes:
        return crypto.unwrap_key(master, _unhex(user.wrapped_meta_key), aad=b"meta")

    # ============================ FOLDERS ===================================
    def create_folder(self, user: User, meta_key: SecretBytes, name: str,
                      parent_id: Optional[int] = None) -> Folder:
        if not name:
            raise ValueError("folder name must be non-empty")
        if parent_id is not None:
            if self._folder_row(user.id, parent_id) is None:
                raise NotFound("parent folder not found")
        enc = crypto.encrypt(meta_key, name.encode(), aad=b"folder")
        cur = self.db.execute(
            "INSERT INTO Folders (user_id, encrypted_name, parent_id) VALUES (?,?,?)",
            (user.id, _hex(enc), parent_id),
        )
        return self.get_folder(user.id, _lastrowid(cur))

    def get_folder(self, user_id: int, folder_id: int) -> Folder:
        row = self._folder_row(user_id, folder_id)
        if row is None:
            raise NotFound("folder not found")
        return Folder(
            id=row["id"], user_id=row["user_id"],
            encrypted_name=row["encrypted_name"], parent_id=row["parent_id"],
            created_at=row["created_at"],
        )

    def _folder_row(self, user_id: int, folder_id: int):
        rows = self.db.query(
            "SELECT * FROM Folders WHERE id=? AND user_id=?", (folder_id, user_id)
        )
        return rows[0] if rows else None

    def has_folder(self, user_id: int, folder_id: int) -> bool:
        return self._folder_row(user_id, folder_id) is not None

    def list_folders(self, user: User) -> list[Folder]:
        rows = self.db.query(
            "SELECT f.* FROM Folders f WHERE f.user_id=? ORDER BY f.id", (user.id,),
        )
        return [
            Folder(
                id=r["id"], user_id=r["user_id"],
                encrypted_name=r["encrypted_name"], parent_id=r["parent_id"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def folder_file_count(self, user_id: int, folder_id: int) -> int:
        n = self.db.scalar(
            "SELECT COUNT(*) FROM Files WHERE folder_id=? AND user_id=?",
            (folder_id, user_id),
        )
        return int(n or 0)

    def decrypt_folder_name(self, meta_key: SecretBytes, folder: Folder) -> str:
        """Decrypt a folder's name under the caller's meta key (403 on mismatch)."""
        try:
            return crypto.decrypt(meta_key, _unhex(folder.encrypted_name), aad=b"folder").decode()
        except DecryptionError as exc:
            raise KeyRejected("security keys do not match") from exc

    def folder_path_segments(self, user_id: int, folder_id: int) -> list[Folder]:
        """Return the folder + its ancestor chain (root-first) for path building."""
        chain: list[Folder] = []
        cur_id: Optional[int] = folder_id
        seen = 0
        while cur_id is not None and seen < 64:
            row = self._folder_row(user_id, cur_id)
            if row is None:
                break
            chain.append(Folder(
                id=row["id"], user_id=row["user_id"],
                encrypted_name=row["encrypted_name"], parent_id=row["parent_id"],
                created_at=row["created_at"],
            ))
            cur_id = row["parent_id"]
            seen += 1
        chain.reverse()
        return chain

    # ============================ FILES =====================================
    def create_file_record(
        self,
        user: User,
        meta_key: SecretBytes,
        file_uuid: str,
        original_name: str,
        extension: str,
        folder_path: str,
        content_key: KeyMaterial,
        master: SecretBytes,
        folder_id: Optional[int],
        content_type: str,
        size: int,
        thumb_id: Optional[str],
    ) -> FileRecord:
        content_salt = os.urandom(SALT_LEN)
        # per-file content key wrapped under the *request* master (aad=file_id)
        wrapped_content = crypto.wrap_key(master, content_key, aad=file_uuid.encode())
        self.db.execute(
            "INSERT INTO Files (id, user_id, folder_id, original_name, extension,"
            " folder_path, content_key, content_salt, content_type, size, thumb_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                file_uuid, user.id, folder_id,
                _hex(crypto.encrypt(meta_key, original_name.encode(), aad=b"name")),
                _hex(crypto.encrypt(meta_key, extension.encode(), aad=b"ext")),
                _hex(crypto.encrypt(meta_key, folder_path.encode(), aad=b"path")),
                _hex(wrapped_content), _hex(content_salt),
                content_type, int(size), thumb_id,
            ),
        )
        return self.get_file(user.id, file_uuid)

    def get_file(self, user_id: int, file_uuid: str) -> FileRecord:
        rows = self.db.query(
            "SELECT * FROM Files WHERE id=? AND user_id=?", (file_uuid, user_id)
        )
        if not rows:
            raise NotFound("file not found")
        r = rows[0]
        return FileRecord(
            id=r["id"], user_id=r["user_id"], folder_id=r["folder_id"],
            original_name=r["original_name"], extension=r["extension"],
            folder_path=r["folder_path"], content_key=r["content_key"],
            content_salt=r["content_salt"], content_type=r["content_type"],
            size=r["size"], thumb_id=r["thumb_id"], created_at=r["created_at"],
        )

    def list_files(self, user_id: int, folder_id: Optional[int]) -> list[FileRecord]:
        if folder_id is None:
            rows = self.db.query(
                "SELECT * FROM Files WHERE user_id=? ORDER BY created_at, id", (user_id,)
            )
        else:
            rows = self.db.query(
                "SELECT * FROM Files WHERE user_id=? AND folder_id=? ORDER BY created_at, id",
                (user_id, folder_id),
            )
        return [
            FileRecord(
                id=r["id"], user_id=r["user_id"], folder_id=r["folder_id"],
                original_name=r["original_name"], extension=r["extension"],
                folder_path=r["folder_path"], content_key=r["content_key"],
                content_salt=r["content_salt"], content_type=r["content_type"],
                size=r["size"], thumb_id=r["thumb_id"], created_at=r["created_at"],
            )
            for r in rows
        ]

    def decrypt_metadata(
        self, meta_key: SecretBytes, rec: FileRecord
    ) -> tuple[str, str, str]:
        """Decrypt (name, extension, folder_path) under the caller's meta key."""
        try:
            name = crypto.decrypt(meta_key, _unhex(rec.original_name), aad=b"name").decode()
            ext = crypto.decrypt(meta_key, _unhex(rec.extension), aad=b"ext").decode()
            path = crypto.decrypt(meta_key, _unhex(rec.folder_path), aad=b"path").decode()
        except DecryptionError as exc:
            raise KeyRejected("security keys do not match") from exc
        return name, ext, path

    def unwrap_content_key(self, master: SecretBytes, rec: FileRecord) -> SecretBytes:
        """Unwrap this file's content key under the request master (aad=file_id).

        Raises :class:`KeyRejected` if the master key is wrong (wrong
        security keys presented) — the API maps to 403.
        """
        try:
            return crypto.unwrap_key(master, _unhex(rec.content_key), aad=rec.id.encode())
        except DecryptionError as exc:
            raise KeyRejected("security keys do not match") from exc

    # ============================ FAVORITES ================================
    def add_favorite(self, user_id: int, file_uuid: str) -> None:
        if self.get_file(user_id, file_uuid) is None:  # raises NotFound if absent
            raise NotFound("file not found")
        self.db.execute(
            "INSERT OR IGNORE INTO Favorites (user_id, file_id) VALUES (?,?)",
            (user_id, file_uuid),
        )

    def remove_favorite(self, user_id: int, file_uuid: str) -> None:
        self.db.execute(
            "DELETE FROM Favorites WHERE user_id=? AND file_id=?",
            (user_id, file_uuid),
        )

    def list_favorites(self, user_id: int) -> list[str]:
        rows = self.db.query(
            "SELECT file_id FROM Favorites WHERE user_id=? ORDER BY created_at, file_id",
            (user_id,),
        )
        return [r["file_id"] for r in rows]
