"""JWT identity auth (HS256, server-side secret — ARCHITECTURE.md default).

The JWT carries ``user_id`` + ``exp`` only. It **does not** contain or derive
from the two security keys — those are the zero-knowledge material and arrive
per request in ``X-Sec-Key-1`` / ``X-Sec-Key-2`` headers.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import jwt

from app.config import get_settings


class AuthError(Exception):
    """Invalid / expired / missing token. API maps to 401."""


@dataclass(frozen=True)
class Identity:
    user_id: int
    username: str
    exp: int


def create_jwt(user_id: int, username: str) -> str:
    """Mint an HS256 JWT for ``user_id``."""
    s = get_settings()
    now = int(time.time())
    payload = {
        "user_id": int(user_id),
        "username": username,
        "iat": now,
        "exp": now + s.jwt_ttl_seconds,
    }
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256")


def decode_jwt(token: str) -> Identity:
    """Validate signature + expiry; return the identity. Raises :class:`AuthError`."""
    s = get_settings()
    try:
        payload = jwt.decode(token, s.jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("invalid token") from exc
    try:
        user_id = int(payload["user_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthError("token missing user_id") from exc
    return Identity(
        user_id=user_id,
        username=str(payload.get("username", "")),
        exp=int(payload.get("exp", 0)),
    )
