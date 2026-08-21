# SecWeb — Accepted Decisions & Architecture Contract

> **Status: ACCEPTED** by operator Funkyhacks, 2026-08-20. These decisions and the
> contract below are **binding** for all implementation, review, and test lanes.
> The 6 security directives in `SPEC.md` remain the immutable release gate.

## Accepted Decisions

| # | Decision | Chosen | Rationale (recorded) |
|---|---|---|---|
| D1 | Content/metadata cipher | **AES-256-GCM** | Authenticated encryption; nonce discipline enforced by tests (R2). Fernet rejected (key-embedding model, slower). |
| D2 | Key derivation | **HKDF-SHA256** | Designed to combine multiple inputs into a key; `ikm = key1 ‖ key2`. PBKDF2 rejected (low-entropy password KDF, wrong tool). |
| D3 | Metadata key model | **Separate wrapped key** | A per-user metadata key is wrapped under the master key and stored; content uses a per-file content key also wrapped under master. Small DB rows, re-keyable. |
| D4 | Tenancy | **Multi-user** | Per-user key isolation; every file/folder row carries `user_id`; one user's key material must never decrypt another user's data. |
| D5 | CI | **GitHub Actions** | Backend (`pytest`) + Frontend (`vitest` + build) on `push`/`pull_request`; repo has `workflow` scope. |
| — | Defaults (operator "go with your recs") | see below | |

### Standing defaults (operator-approved)
- **Nonce/IV:** fresh `os.urandom(12)` per encryption op, prepended to ciphertext; **never reused** (R2 test).
- **AAD:** bind file `file_id` + `user_id` into AAD so ciphertext can't be swapped between users/files.
- **Key zeroization:** overwrite derived keys in memory after use; never log; short-lived scope.
- **Password storage:** `bcrypt` hash only — the password is for login identity; the two security keys are the zero-knowledge material.
- **JWT:** HS256, server-side `JWT_SECRET` (env), contains `user_id` + `exp`; **does not contain and does not derive from** the security keys.
- **Streaming:** decrypt in chunks to the HTTP response; **zero** decrypted bytes to disk (R3 test).
- **Redis:** `appendonly no`, `save ""`, every `SET` carries a TTL (R5 test).
- **Thumbnails:** generated in-memory (Pillow/ffmpeg), encrypted, stored as `UUID_thumb.bin`; no plaintext temp.

## Crypto Contract (binding)

```
derive_master_key(key1: bytes, key2: bytes, salt: bytes, info=b"secweb/v1")
  -> HKDF-SHA256(ikm=key1||key2, salt=salt, length=32)
  # salt = per-record random 16 bytes (content) or per-user fixed (meta-wrap), stored.
  # Returns a 32-byte AES-256 key. Zeroize after use.

encrypt(key: bytes, plaintext: bytes, aad: bytes) -> ciphertext
  nonce   = os.urandom(12)
  ct      = AESGCM(key).encrypt(nonce, plaintext, aad)   # 16-byte tag appended
  return nonce || ct                                       # nonce first, no other header

decrypt(key: bytes, blob: bytes, aad: bytes) -> plaintext
  nonce, ct = blob[:12], blob[12:]
  return AESGCM(key).decrypt(nonce, ct, aad)               # raises on tamper
```

**Wrapped-key model (D3):**
- Per-user: `meta_key = random(32)`; stored as `wrapped_meta_key = AES-GCM(master, meta_key, aad=b"meta")`.
- Per-file: `content_key = random(32)`; stored as `wrapped_content_key = AES-GCM(master, content_key, aad=file_id)`.
- On read: `master = derive(key1,key2,salt)` → `unwrap` the needed key → use → zeroize.

**Storage layout (D4 multi-user):**
```
storage/
  <user_id>/
    <file_uuid>.bin          # encrypted content, NO extension (directive #4)
  <user_id>/thumbs/
    <file_uuid>_thumb.bin    # encrypted thumbnail, NO extension
```

## API Contract (binding — frontend & backend must match exactly)

Common: `Authorization: Bearer <jwt>` on all authenticated routes.
Security-key routes additionally require `X-Sec-Key-1` and `X-Sec-Key-2` headers.
All success responses are JSON; errors are `{"detail": str}` with 4xx/5xx.

| Method | Path | Key hdrs | Purpose |
|---|---|---|---|
| POST | `/api/auth/register` | — | body `{username,password,key1,key2}` → `{jwt,user_id}` (409 if exists) |
| POST | `/api/auth/login` | — | body `{username,password,key1,key2}` → `{jwt,user_id}` (401 on bad creds) |
| POST | `/api/auth/logout` | — | revokes session → `{ok:true}` |
| GET | `/api/folders` | yes | → `[{id,name,encrypted_name,parent_id,file_count}]` |
| POST | `/api/folders` | yes | body `{name,parent_id?}` → `{id}` |
| GET | `/api/files?folder_id=` | yes | → `[{id,type,encrypted_name,extension,size,created_at,thumb_id}]` |
| POST | `/api/files/upload` | yes | multipart `file` + `folder_id` → `{id,thumb_id}` |
| GET | `/api/files/{id}/content` | yes | → decrypted binary stream (correct `Content-Type`) |
| GET | `/api/files/{id}/thumb` | yes | → decrypted thumbnail stream |
| GET | `/api/favorites` | yes | → `[{file_id}]` |
| POST | `/api/favorites/{file_id}` | yes | add → `{ok:true}` |
| DELETE | `/api/favorites/{file_id}` | yes | remove → `{ok:true}` |
| GET | `/api/health` | — | → `{status:"ok",version,redis:"up|down"}` |

**Key lifecycle (D2/zero-knowledge):** the two security keys are provided at
register/login AND passed on every key-bearing route. The server derives the
master key per request, uses it, and **discards it** before the response returns.
A request with a valid JWT but wrong/missing security keys must fail to decrypt
metadata/content (403) and must NOT reveal plaintext.
