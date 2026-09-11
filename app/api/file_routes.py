"""File routes (binding API contract): list, upload, content, thumb.

Security-critical paths honoured here:

* **R3 zero plaintext to disk** — uploads are encrypted in memory then written
  as ciphertext; downloads are decrypted and streamed chunk-by-chunk to the
  HTTP response. No decrypted temp file is ever created.
* **AAD binding** — content is encrypted with ``aad = file_id`` so a
  ciphertext cannot be swapped between files/users.
* **Wrong keys -> 403** — a JWT alone is insufficient; the caller must also
  present the correct ``X-Sec-Key-1``/``X-Sec-Key-2`` or the content key
  will not unwrap and the route fails before any plaintext is produced.
"""
from __future__ import annotations

import mimetypes
import os
import uuid
from typing import Iterator, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import StreamingResponse

from app.api.deps import KeyContext, get_repo, get_store, require_keys
from app.core import crypto
from app.core.keys import key_scope
from app.core.storage import Store, decrypt_stream, make_thumbnail
from app.models.repo import FileRecord, KeyRejected, NotFound, Repository

CHUNK = 256 * 1024  # 256 KiB stream chunks


def _content_type(filename: str, fallback: str = "application/octet-stream") -> str:
    guessed, _ = mimetypes.guess_type(filename)
    return guessed or fallback


def _ext_of(filename: str) -> str:
    _, ext = os.path.splitext(filename)
    return ext.lstrip(".").lower() or "bin"


def _get_rec(repo: Repository, ctx: KeyContext, file_id: str) -> FileRecord:
    try:
        return repo.get_file(ctx.user.id, file_id)
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _decrypt_chunks(key: crypto.SecretBytes, blob: bytes, file_id: str) -> Iterator[bytes]:
    """Decrypt and yield in chunks (zero plaintext to disk — R3)."""
    try:
        yield from decrypt_stream(blob, key, file_id.encode(), chunk_size=CHUNK)
    except crypto.DecryptionError as exc:
        raise HTTPException(status_code=403, detail="decryption failed") from exc


router = APIRouter(prefix="/api/files", tags=["files"])


@router.get("")
def list_files(
    request: Request,
    folder_id: Optional[int] = None,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
) -> list[dict]:
    try:
        with key_scope(ctx.master, ctx.meta_key):
            recs = repo.list_files(ctx.user.id, folder_id)
            out = []
            for r in recs:
                name, ext, _path = repo.decrypt_metadata(ctx.meta_key, r)
                out.append({
                    "id": r.id,
                    "type": r.content_type,
                    "encrypted_name": r.original_name,
                    "name": name,
                    "extension": ext,
                    "size": r.size,
                    "created_at": r.created_at,
                    "thumb_id": r.thumb_id,
                })
    except KeyRejected as exc:
        raise HTTPException(status_code=403, detail="security keys rejected") from exc
    return out


@router.post("/upload", status_code=201)
def upload(
    request: Request,
    file: UploadFile = File(...),
    folder_id: Optional[int] = Form(default=None),
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
    store: Store = Depends(get_store),
) -> dict:
    data = file.file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty file")
    name = os.path.basename(file.filename or "upload") or "upload"
    ext = _ext_of(name)
    content_type = _content_type(name, "application/octet-stream")

    if folder_id is not None and not repo.has_folder(ctx.user.id, folder_id):
        raise HTTPException(status_code=404, detail="folder not found")

    file_uuid = str(uuid.uuid4())
    content_key = crypto.SecretBytes(os.urandom(crypto.KEY_LEN))
    ct = crypto.encrypt(content_key, data, aad=file_uuid.encode())
    store.save_content(ctx.user.id, file_uuid, ct)

    # thumbnail (images only) — encrypted with the same content key
    thumb_id: Optional[str] = None
    thumb_bytes = make_thumbnail(data)
    if thumb_bytes is not None:
        store.save_thumb(ctx.user.id, file_uuid, crypto.encrypt(content_key, thumb_bytes, aad=file_uuid.encode()))
        thumb_id = file_uuid

    with key_scope(ctx.master, ctx.meta_key, content_key):
        try:
            repo.create_file_record(
                user=ctx.user,
                meta_key=ctx.meta_key,
                file_uuid=file_uuid,
                original_name=name,
                extension=ext,
                folder_path=f"folder:{folder_id}" if folder_id else "",
                content_key=content_key,
                master=ctx.master,
                folder_id=folder_id,
                content_type=content_type,
                size=len(data),
                thumb_id=thumb_id,
            )
        except NotFound as exc:
            store.delete(ctx.user.id, file_uuid)
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"id": file_uuid, "thumb_id": thumb_id}


@router.get("/{file_id}/content")
def file_content(
    file_id: str,
    request: Request,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
    store: Store = Depends(get_store),
) -> Response:
    rec = _get_rec(repo, ctx, file_id)
    try:
        with key_scope(ctx.master, ctx.meta_key):
            content_key = repo.unwrap_content_key(ctx.master, rec)
            blob = store.read_content(ctx.user.id, file_id)
            name, _ext, _path = repo.decrypt_metadata(ctx.meta_key, rec)
    except KeyRejected as exc:
        raise HTTPException(status_code=403, detail="security keys rejected") from exc
    except crypto.DecryptionError as exc:
        raise HTTPException(status_code=403, detail="security keys rejected") from exc

    def gen() -> Iterator[bytes]:
        with key_scope(content_key):
            yield from _decrypt_chunks(content_key, blob, file_id)

    return StreamingResponse(
        gen(),
        media_type=rec.content_type,
        headers={
            "Content-Length": str(rec.size),
            "Content-Disposition": f'inline; filename="{name}"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/{file_id}/thumb")
def file_thumb(
    file_id: str,
    request: Request,
    ctx: KeyContext = Depends(require_keys),
    repo: Repository = Depends(get_repo),
    store: Store = Depends(get_store),
) -> Response:
    rec = _get_rec(repo, ctx, file_id)
    if not rec.thumb_id:
        raise HTTPException(status_code=404, detail="no thumbnail")
    try:
        with key_scope(ctx.master, ctx.meta_key):
            content_key = repo.unwrap_content_key(ctx.master, rec)
            blob = store.read_thumb(ctx.user.id, file_id)
    except KeyRejected as exc:
        raise HTTPException(status_code=403, detail="security keys rejected") from exc
    except crypto.DecryptionError as exc:
        raise HTTPException(status_code=403, detail="security keys rejected") from exc

    def gen() -> Iterator[bytes]:
        with key_scope(content_key):
            yield from _decrypt_chunks(content_key, blob, file_id)

    return StreamingResponse(
        gen(),
        media_type="image/jpeg",
        headers={"Cache-Control": "no-store"},
    )
