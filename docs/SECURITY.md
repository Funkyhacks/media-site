# SecWeb — Security Review

> Lane: `lane/security` · Reviewed against the **6 IMMUTABLE directives**
> (docs/SPEC.md) and the **binding crypto/API contract** (docs/ARCHITECTURE.md).
> Backend under review: `lane/backend` (`app/**`). Frontend: `lane/frontend`.
> Ops: `lane/ops`.
>
> This is an independent review. Verdicts are **PASS / PASS (with reservation) /
> GAP** and cite the exact code that enforces each property.

## Scope & method

- Static read of every module in `app/` (core, api, models) plus the full
  pytest suite (79 tests) that encodes the directives.
- Cross-checked the 6 immutable directives and every standing default
  (R1 AAD binding, R2 fresh nonce, R3 zero-plaintext-to-disk, R5 TTL).
- STRIDE threat model: see THREAT-MODEL.md.
- Release-gate commands: see CHECKLIST.md.

## Verdict summary

| # | Directive | Verdict |
|---|-----------|---------|
| 1 | Dual-key encryption (both keys required) | **PASS** |
| 2 | Zero-knowledge (server never stores keys) | **PASS** |
| 3 | Encrypted metadata in DB | **PASS** |
| 4 | Obfuscated storage (UUID, no extension) | **PASS** |
| 5 | Ephemeral Redis (appendonly no, save "", TTL) | **PASS** |
| 6 | No browser persistence (autocomplete off, no-store) | **PASS (with reservation)** |
| — | Multi-user tenancy (D4) | **PASS** |
| — | AAD binding (R1) | **PASS** |
| — | Fresh nonce per op (R2) | **PASS** |
| — | Zero plaintext to disk (R3) | **PASS** |
| — | TTL on every Redis SET (R5) | **PASS** |

## Directive-by-directive

### #1 Dual-key encryption — PASS
The master key is derived **only** from both keys via `ikm = key1 || key2`:
- `app/core/crypto.py::derive_master_key` raises `ValueError` if either key is
  empty (`if not key1 or not key2`), and `test_derive_master_key_requires_both_keys`
  proves it. Swapping key order changes the key (`test_derive_master_key_order_matters`).
- Registration and login both require both keys (repo.register / repo.login).

### #2 Zero-knowledge — PASS
- The two security keys are **never** persisted. `test_d2_zero_knowledge_keys_never_persisted`
  scans the raw SQLite file and asserts neither `key1` nor `key2` (or their
  substrings) appear.
- Only a *wrapped* meta key + per-user salt are stored (schema `Users.wrapped_meta_key`,
  `Users.key_salt`). The raw keys exist only in memory during the request.
- Every derived buffer is zeroized via `key_scope` (`app/core/keys.py`), including on
  the exception path (`test_zeroize_on_exception`).

### #3 Encrypted metadata — PASS
- `schema.py`: `Files.original_name / extension / folder_path` and
  `Folders.encrypted_name` are stored as **hex of an AES-GCM ciphertext** — no
  plaintext column exists.
- `test_d3_metadata_encrypted_not_readable_without_keys` + `test_metadata_encrypted_in_db_directive3`
  scan the DB file and assert the plaintext name is absent.
- The API decrypts per request with the caller's meta key and returns 403 on
  mismatch (`repo.decrypt_metadata`, `repo.decrypt_folder_name`).

### #4 Obfuscated storage — PASS
- `app/core/storage.py` names blobs `<uuid>.bin` and `<uuid>_thumb.bin` under
  `<storage>/<user_id>/`; `safe_file_uuid` rejects path traversal.
- `test_storage_layout_directive4` asserts the on-disk set is exactly the
  ciphertext + `thumbs/`, with no original filename anywhere.

### #5 Ephemeral Redis — PASS
- `app/core/cache.py::TTLCache.set` **requires** a positive TTL and raises
  `TTLViolation` otherwise (`test_set_requires_positive_ttl`, `test_d5_every_redis_write_has_ttl`).
- `lane/ops` compose runs `redis-server --appendonly no --save ""`
  (checked in `.github/workflows/ci.yml` on `lane/ops`).

### #6 No browser persistence — PASS (with reservation)
- Frontend `src/components/Login.tsx`: all inputs use `autocomplete="off"` and the
  key fields use a readonly-on-focus guard; `src/main.tsx` wipes keys on
  `beforeunload`. Auth responses send `Cache-Control: no-store`
  (`auth_routes.py`).
- **Reservation:** the JWT itself is kept in React state and re-sent on every
  request; it is not pinned to a `HttpOnly` cookie (by design, to keep keys and
  token in memory and avoid storage). This is acceptable for the zero-knowledge
  model but means a page-level XSS could read the token — mitigated by
  same-origin API, no `document.write`, and CSP recommendations below.

### Multi-user tenancy (D4) — PASS
Every table row carries `user_id`; all repository queries are scoped by
`user_id`. `test_cross_user_cannot_read_file` (404, no existence leak) and
`test_d4_cross_user_key_cannot_decrypt_other_user` (bob's master key cannot
unwrap alice's content key) prove isolation. AAD binding (`aad=file_id` for
content, `aad=b"meta"` for the meta key) prevents ciphertext swapping.

## Findings (non-blocking, recommended)

These are **not** directive violations. They are hardening gaps worth closing
before production. Patches for the two code-level ones are in `patches/`.

1. **[HIGH] Pillow decompression-bomb (DoS).** `app/core/storage.py::make_thumbnail`
   calls `Image.open()` + `img.thumbnail()` on user-supplied bytes with **no
   pixel-count cap**. A crafted image (e.g. 1×1 stored, decompresses to a
   multi-GB bitmap) can exhaust memory and kill the worker. Fix: enable
   `Image.MAX_IMAGE_PIXELS` and/or bound the decompressed size before
   `thumbnail()`. → `patches/0001-storage-pillow-bomb.patch`
2. **[MED] Unbounded upload size.** `app/api/file_routes.py::upload` does
   `file.file.read()` with no length cap — a client can stream arbitrarily large
   bodies into memory. Fix: enforce a max upload size (reject > N MB).
   → `patches/0002-upload-size-limit.patch`
3. **[MED] No CORS policy.** No `CORSMiddleware` is configured, so the browser
   default is same-origin-only (good), but there is no explicit allow-list.
   If the frontend is ever served cross-origin, add an explicit
   `allow_origins` + `allow_credentials=False`.
4. **[LOW] No rate limiting.** No `slowapi`/throttling on `/api/auth/*`. Add
   per-IP + per-username limits on register/login to slow offline brute force
   (bcrypt cost already raises the bar).
5. **[LOW] Stateless logout.** `POST /api/auth/logout` echoes success but does
   not revoke the JWT server-side (the token is valid until `exp`). The client
   discards it, which satisfies the contract, but a stolen token stays valid
   for its TTL. Consider a short-lived token + a revocation allow-list in the
   (ephemeral) cache if the operator wants server-side revocation.
6. **[INFO] Error messages are constant.** All key-rejection paths return the
   same `"security keys rejected"` detail — no oracle. Good.

## Recommended response headers (frontend/nginx edge)

- `Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' blob:; style-src 'self'; connect-src 'self'; base-uri 'none'`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store` on all `/api/*` responses (already set on auth).
