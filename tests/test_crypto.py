"""Unit tests for the binding crypto contract (docs/ARCHITECTURE.md).

Covers: HKDF-SHA256 master-key derivation, AES-256-GCM encrypt/decrypt with
fresh nonces, AAD binding, wrapped-key model, zeroization, and the dual-key
rule (directive #1).
"""
from __future__ import annotations

import os

import pytest

from app.core import crypto
from app.core.crypto import (
    KEY_LEN,
    NONCE_LEN,
    DecryptionError,
    SecretBytes,
    decrypt,
    derive_master_key,
    encrypt,
    unwrap_key,
    wrap_key,
    zeroize,
)


# --- HKDF master-key derivation (D2) ---------------------------------------
def test_derive_master_key_length():
    k = derive_master_key(b"key1", b"key2", os.urandom(16))
    assert isinstance(k, SecretBytes)
    assert len(k) == 32


def test_derive_master_key_deterministic_for_same_salt():
    salt = os.urandom(16)
    a = bytes(derive_master_key(b"A", b"B", salt))
    b = bytes(derive_master_key(b"A", b"B", salt))
    assert a == b


def test_derive_master_key_differs_by_salt():
    a = bytes(derive_master_key(b"A", b"B", b"\x00" * 16))
    b = bytes(derive_master_key(b"A", b"B", b"\x01" * 16))
    assert a != b


def test_derive_master_key_order_matters():
    # ikm = key1 || key2; swapping keys must change the master key.
    salt = b"\x02" * 16
    ab = bytes(derive_master_key(b"A", b"B", salt))
    ba = bytes(derive_master_key(b"B", b"A", salt))
    assert ab != ba


def test_derive_master_key_requires_both_keys():
    with pytest.raises(ValueError):
        derive_master_key(b"", b"B", b"\x00" * 16)
    with pytest.raises(ValueError):
        derive_master_key(b"A", b"", b"\x00" * 16)


# --- AES-GCM encrypt/decrypt (D1) ------------------------------------------
def test_encrypt_roundtrip():
    key = os.urandom(32)
    pt = b"hello secweb"
    blob = encrypt(key, pt, aad=b"context")
    assert decrypt(key, blob, aad=b"context") == pt


def test_encrypt_blob_layout_nonce_first():
    key = os.urandom(32)
    pt = b"x" * 100
    blob = encrypt(key, pt)
    # nonce (12) || ciphertext (100 + 16 tag)
    assert len(blob) == NONCE_LEN + len(pt) + 16
    assert blob[:NONCE_LEN] != pt[:NONCE_LEN]  # nonce is random, not plaintext


def test_fresh_nonce_per_encryption():
    """R2: every encryption op uses a fresh random nonce (never reused)."""
    key = os.urandom(32)
    pt = b"same plaintext"
    blobs = {encrypt(key, pt) for _ in range(16)}
    nonces = {b[:NONCE_LEN] for b in blobs}
    # 16 distinct nonces -> nonces are freshly generated per call
    assert len(nonces) == 16
    assert len(blobs) == 16


def test_wrong_key_fails():
    key = os.urandom(32)
    other = os.urandom(32)
    blob = encrypt(key, b"secret")
    with pytest.raises(DecryptionError):
        decrypt(other, blob)


def test_wrong_aad_fails():
    key = os.urandom(32)
    blob = encrypt(key, b"secret", aad=b"file-1")
    with pytest.raises(DecryptionError):
        decrypt(key, blob, aad=b"file-2")


def test_tampered_ciphertext_fails():
    key = os.urandom(32)
    blob = bytearray(encrypt(key, b"secret"))
    blob[-1] ^= 1  # flip a bit in the auth tag
    with pytest.raises(DecryptionError):
        decrypt(key, bytes(blob))


def test_tampered_nonce_fails():
    key = os.urandom(32)
    blob = bytearray(encrypt(key, b"secret"))
    blob[0] ^= 1
    with pytest.raises(DecryptionError):
        decrypt(key, bytes(blob))


def test_empty_plaintext_roundtrip():
    key = os.urandom(32)
    blob = encrypt(key, b"")
    assert decrypt(key, blob) == b""


def test_key_length_enforced():
    with pytest.raises(ValueError):
        encrypt(os.urandom(16), b"pt")
    with pytest.raises(ValueError):
        decrypt(os.urandom(16), b"\x00" * 40)


# --- wrapped-key model (D3) -------------------------------------------------
def test_wrap_unwrap_roundtrip():
    master = os.urandom(32)
    inner = os.urandom(32)
    wrapped = wrap_key(master, inner, aad=b"meta")
    unwrapped = unwrap_key(master, wrapped, aad=b"meta")
    assert bytes(unwrapped) == inner
    assert isinstance(unwrapped, SecretBytes)


def test_unwrap_wrong_master_fails():
    master = os.urandom(32)
    other = os.urandom(32)
    wrapped = wrap_key(master, os.urandom(32), aad=b"meta")
    with pytest.raises(DecryptionError):
        unwrap_key(other, wrapped, aad=b"meta")


def test_unwrap_wrong_aad_fails():
    master = os.urandom(32)
    wrapped = wrap_key(master, os.urandom(32), aad=b"meta")
    with pytest.raises(DecryptionError):
        unwrap_key(master, wrapped, aad=b"content")


# --- zeroization (standing default) -----------------------------------------
def test_secret_bytes_zeroize():
    k = SecretBytes(os.urandom(32))
    zeroize(k)
    assert bytes(k) == b"\x00" * 32


def test_zeroize_plain_bytearray():
    b = bytearray(range(16))
    zeroize(b)
    assert bytes(b) == b"\x00" * 16
