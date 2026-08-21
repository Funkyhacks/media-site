"""Auth routes: register / login / logout (binding API contract).

Directive #6: the login surface never persists credentials — responses carry
``Cache-Control: no-store`` and the frontend login form uses
``autocomplete="off"``. The server stores only a bcrypt password hash (identity)
and a *wrapped* meta key — never the two security keys (directive #2).
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator

from app.core import auth as authcore
from app.models.repo import (
    AuthError,
    KeyRejected,
    Repository,
    UserExists,
)
from app.api.deps import get_repo


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    key1: str = Field(min_length=1)
    key2: str = Field(min_length=1)

    @field_validator("username")
    @classmethod
    def _trim(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("username required")
        return v


def _b64(v: str) -> bytes:
    import base64

    try:
        return base64.b64decode(v, validate=False)
    except Exception:
        return v.encode()


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", status_code=201)
def register(
    body: Credentials,
    response: Response,
    repo: Repository = Depends(get_repo),
) -> dict:
    response.headers["Cache-Control"] = "no-store"
    try:
        user = repo.register(body.username, body.password, _b64(body.key1), _b64(body.key2))
    except UserExists as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except AuthError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    jwt = authcore.create_jwt(user.id, user.username)
    return {"jwt": jwt, "user_id": user.id}


@router.post("/login")
def login(
    body: Credentials,
    response: Response,
    repo: Repository = Depends(get_repo),
) -> dict:
    response.headers["Cache-Control"] = "no-store"
    try:
        user = repo.login(body.username, body.password, _b64(body.key1), _b64(body.key2))
    except UserExists as exc:  # pragma: no cover
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except KeyRejected as exc:
        raise HTTPException(status_code=401, detail="invalid credentials") from exc
    except AuthError as exc:
        raise HTTPException(status_code=401, detail="invalid credentials") from exc
    jwt = authcore.create_jwt(user.id, user.username)
    return {"jwt": jwt, "user_id": user.id}


@router.post("/logout")
def logout(
    response: Response,
    authorization: Optional[str] = Header(default=None),
) -> dict:
    """Revoke the session. Stateless model: the client discards the token; we
    echo success. ``Cache-Control: no-store`` so no intermediary retains it."""
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True}
