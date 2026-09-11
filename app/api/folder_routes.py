"""Folder routes (binding API contract). All key-bearing."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.deps import KeyContext, get_repo, require_keys
from app.core.keys import key_scope
from app.models.repo import KeyRejected, NotFound, Repository


class FolderIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: Optional[int] = None


router = APIRouter(prefix="/api/folders", tags=["folders"])


@router.get("")
def list_folders(
    request: Request,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
) -> list[dict]:
    with key_scope(ctx.master, ctx.meta_key):
        try:
            folders = repo.list_folders(ctx.user)
        except KeyRejected as exc:
            raise HTTPException(status_code=403, detail="security keys rejected") from exc
        out = []
        for f in folders:
            try:
                name = repo.decrypt_folder_name(ctx.meta_key, f)
            except KeyRejected as exc:
                raise HTTPException(status_code=403, detail="security keys rejected") from exc
            out.append({
                "id": f.id,
                "name": name,
                "encrypted_name": f.encrypted_name,
                "parent_id": f.parent_id,
                "file_count": repo.folder_file_count(ctx.user.id, f.id),
            })
        return out


@router.post("", status_code=201)
def create_folder(
    body: FolderIn,
    request: Request,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
) -> dict:
    with key_scope(ctx.master, ctx.meta_key):
        try:
            f = repo.create_folder(ctx.user, ctx.meta_key, body.name.strip(), body.parent_id)
        except NotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"id": f.id}
