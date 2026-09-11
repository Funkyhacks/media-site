"""Shared request context + FastAPI dependencies.

Every key-bearing route runs through :func:`require_keys`, which:

1. decodes the JWT (401 on failure),
2. requires BOTH ``X-Sec-Key-1`` and ``X-Sec-Key-2`` (403 if missing),
3. derives the request master key and unwraps the per-user meta key,
4. proves the keys are correct *before* any plaintext is produced — a wrong
   key pair raises a 403 with no data leaked.

The derived keys live in :class:`KeyContext`; routes zeroize them with
``key_scope`` (see :mod:`app.api.routes`).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request

from app.core import auth as authcore
from app.core import crypto
from app.models.repo import (
    KeyRejected,
    NotFound,
    Repository,
    User,
)


def get_repo(request: Request) -> Repository:
    return request.app.state.repo


def get_store(request: Request):
    return request.app.state.store


def current_user(
    request: Request,
    authorization: Optional[str] = Header(default=None),
) -> User:
    """Decode the Bearer token and load the user (401 on any failure)."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        ident = authcore.decode_jwt(token)
    except authcore.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    repo: Repository = request.app.state.repo
    try:
        return repo.get_user(ident.user_id)
    except NotFound as exc:
        raise HTTPException(status_code=401, detail="unknown user") from exc


def _b64decode_header(value: Optional[str]) -> Optional[bytes]:
    """Accept the security key as raw or base64 (header-safe)."""
    if value is None or value == "":
        return None
    try:
        return base64.b64decode(value, validate=False)
    except Exception:
        return value.encode()


@dataclass
class KeyContext:
    """Per-request derived key material (zeroized after the route body)."""

    user: User
    master: crypto.SecretBytes
    meta_key: crypto.SecretBytes


def require_keys(
    request: Request,
    user: User = Depends(current_user),
    x_sec_key_1: Optional[str] = Header(default=None, alias="X-Sec-Key-1"),
    x_sec_key_2: Optional[str] = Header(default=None, alias="X-Sec-Key-2"),
) -> KeyContext:
    """Validate JWT + both security keys; derive master + meta key."""
    key1 = _b64decode_header(x_sec_key_1)
    key2 = _b64decode_header(x_sec_key_2)
    if not key1 or not key2:
        raise HTTPException(status_code=403, detail="X-Sec-Key-1 and X-Sec-Key-2 required")
    repo: Repository = request.app.state.repo
    try:
        master = repo.derive_master(user, key1, key2)  # raises KeyRejected if wrong
    except KeyRejected as exc:
        raise HTTPException(status_code=403, detail="security keys rejected") from exc
    meta_key = repo.unwrap_meta_key(master, user)
    return KeyContext(user=user, master=master, meta_key=meta_key)
