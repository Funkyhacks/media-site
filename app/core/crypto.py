"""Zero-knowledge crypto core (binding contract — docs/ARCHITECTURE.md).

Implements the exact primitives from the accepted crypto contract:

* ``derive_master_key`` — HKDF-SHA256 over ``ikm = key1 || key2`` with a
  per-record 16-byte salt (D2).
* ``encrypt`` / ``decrypt`` — AES-256-GCM (D1), fresh 12-byte random nonce
  per operation, ``nonce || ciphertext`` on the wire, 16-byte auth tag
  appended by GCM, AAD binding (standing default R1/R2).

Security directives honoured here (SPEC.md, IMMUTABLE):

* **#1 dual-key**: the master key is *only* derivable from BOTH user keys.
* **#2 zero-knowledge**: keys are in-memory only; :class:`SecretBytes`
  buffers are zeroized after use. Nothing key-related is ever persisted.
* **#5 ephemeral cache** is enforced in :mod:`app.core.cache`.
"""
from __future__ import annotations

import os
from typing import Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- constants (binding) -----------------------------------------------------
NONCE_LEN = 12          # 96-bit GCM nonce, fresh per op
KEY_LEN = 32            # AES-256
SALT_LEN = 16           # HKDF salt, per record, stored
TAG_LEN = 16            # GCM auth tag (inside ciphertext tail)
DEFAULT_INFO = b"secweb/v1"

KeyMaterial = Union[bytes, bytearray]


class DecryptionError(Exception):
    """Raised when authenticated decryption fails (wrong key / tamper).

    Routed to HTTP 403 by the API layer — the response must never reveal
    plaintext (SPEC.md key-lifecycle rule).
    """


class SecretBytes(bytearray):
    """A mutable byte buffer for live key material.

    Subclasses :class:`bytearray` so CPython keeps it mutable (unlike
    ``bytes``); :meth:`zeroize` overwrites the buffer in place per the
    "key zeroization" standing default.
    """

    def zeroize(self) -> None:
        """Overwrite every byte in place. Best-effort under CPython, but the
        buffer is no longer reusable and any retained reference is wiped."""
        for i in range(len(self)):
            self[i] = 0


def zeroize(buf: KeyMaterial | None) -> None:
    """Zeroize a mutable key buffer if possible; no-op for immutable bytes."""
    if isinstance(buf, SecretBytes):
        buf.zeroize()
    elif isinstance(buf, bytearray):
        buf[:] = b"\x00" * len(buf)


# --- key derivation (D2: HKDF-SHA256) ----------------------------------------
def derive_master_key(
    key1: KeyMaterial,
    key2: KeyMaterial,
    salt: KeyMaterial,
    info: bytes = DEFAULT_INFO,
) -> SecretBytes:
    """Combine the user's two security keys into an AES-256 master key.

    ``ikm = key1 || key2`` (D2). ``salt`` is per-record: per-user fixed for
    metadata wrapping, per-record random for content (stored with the record).

    Raises ``ValueError`` on empty inputs — a master key must never be
    derived from a single key or none (directive #1).
    """
    if not key1 or not key2:
        raise ValueError("both security keys are required (dual-key model)")
    if len(salt) < 8:
        raise ValueError("salt too short")
    kdf = HKDF(algorithm=SHA256(), length=KEY_LEN, salt=bytes(salt), info=info)
    return SecretBytes(kdf.derive(bytes(key1) + bytes(key2)))


# --- authenticated encryption (D1: AES-256-GCM) -------------------------------
def _check_key(key: KeyMaterial) -> None:
    if len(key) != KEY_LEN:
        raise ValueError(f"AES-256 key must be exactly {KEY_LEN} bytes")


def encrypt(key: KeyMaterial, plaintext: KeyMaterial, aad: bytes = b"") -> bytes:
    """Encrypt ``plaintext`` with AES-256-GCM.

    Returns ``nonce || ciphertext`` (nonce first, no other header — binding
    contract). A fresh ``os.urandom(12)`` nonce is generated for EVERY call
    and never reused (standing default / R2). ``aad`` is bound into the GCM
    auth tag so ciphertexts cannot be swapped between users/files (R1).
    """
    _check_key(key)
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), aad)
    return nonce + ct


def decrypt(key: KeyMaterial, blob: bytes, aad: bytes = b"") -> bytes:
    """Inverse of :func:`encrypt`. Raises :class:`DecryptionError` on any
    authentication failure (wrong key, wrong AAD, or tampered bytes)."""
    _check_key(key)
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise DecryptionError("ciphertext too short")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ct, aad)
    except InvalidTag as exc:  # wrong key, wrong AAD, or tamper
        raise DecryptionError("decryption failed: bad key or tampered data") from exc


# --- wrapped-key model (D3) ----------------------------------------------------
def wrap_key(master: KeyMaterial, key: KeyMaterial, aad: bytes = b"") -> bytes:
    """Wrap a per-record key under the master key (AES-GCM, fresh nonce)."""
    return encrypt(master, key, aad)


def unwrap_key(master: KeyMaterial, blob: bytes, aad: bytes = b"") -> SecretBytes:
    """Unwrap a per-record key under the master key.

    Returns :class:`SecretBytes` so the caller can zeroize it. Raises
    :class:`DecryptionError` if the master key is wrong (i.e. the caller
    presented the wrong security keys).
    """
    return SecretBytes(decrypt(master, blob, aad))
