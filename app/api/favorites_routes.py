"""Favorites routes (binding API contract). All key-bearing."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from app.api.deps import KeyContext, get_repo, require_keys
from app.core.keys import key_scope
from app.models.repo import KeyRejected, NotFound, Repository

router = APIRouter(prefix="/api/favorites", tags=["favorites"])


@router.get("")
def list_favorites(
    request: Request,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
) -> list[dict]:
    # Key-bearing route: prove the keys before returning any ids.
    with key_scope(ctx.master, ctx.meta_key):
        pass
    return [{"file_id": fid} for fid in repo.list_favorites(ctx.user.id)]


@router.post("/{file_id}")
def add_favorite(
    file_id: str,
    request: Request,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
) -> dict:
    with key_scope(ctx.master, ctx.meta_key):
        try:
            repo.add_favorite(ctx.user.id, file_id)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"ok": True}


@router.delete("/{file_id}")
def remove_favorite(
    file_id: str,
    request: Request,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
) -> dict:
    with key_scope(ctx.master, ctx.meta_key):
        pass
    repo.remove_favorite(ctx.user.id, file_id)
    return {"ok": True}
