# SecWeb — Threat Model (STRIDE)

> Scope: the SecWeb zero-knowledge media portal (backend `app/**`, frontend,
> Redis cache, SQLite store, on-disk ciphertext). Each entry: **Threat →
> Actor → Likelihood → Impact → Mitigation (code) → Residual risk**.

## System context

- **Assets:** (a) user media content, (b) metadata (names/paths), (c) the two
  per-user security keys (zero-knowledge — the server never holds them),
  (d) user identity (bcrypt hash), (e) availability (worker uptime).
- **Trusted:** the two security keys held by the user; `SECWEB_JWT_SECRET`.
- **Untrusted:** network clients, uploaded bytes, Redis/SQLite storage media.

---

### T1 — Wrong/absent security keys decrypt another user's data
- **Actor:** authenticated user (valid JWT) presenting wrong `X-Sec-Key-1/2`.
- **Likelihood:** Medium (a bug or a confused user).
- **Impact:** High (cross-tenant disclosure).
- **Mitigation:** `require_keys` derives the master key and *unwraps the
  per-user meta key before any plaintext is produced*; a mismatch raises
  `KeyRejected` → 403 (`app/api/deps.py`, `app/models/repo.py::derive_master`).
  Content is additionally wrapped with `aad=file_id`, so even a correct master
  key cannot read a *different* file's key. Proven by
  `test_content_requires_correct_keys_403`, `test_d4_cross_user_key_cannot_decrypt_other_user`.
- **Residual:** None found.

### T2 — Ciphertext swap between files/users (AAD bypass)
- **Actor:** attacker who can move ciphertext files.
- **Likelihood:** Low (needs FS access).
- **Impact:** High.
- **Mitigation:** GCM AAD binds `file_id` (content) and `b"meta"` (meta key),
  `app/core/crypto.py`. A swapped blob fails authentication → 403.
- **Residual:** None found.

### T3 — Nonce reuse (AES-GCM key stream reuse)
- **Actor:** implementation bug.
- **Likelihood:** Low (guarded by design + test).
- **Impact:** Critical (auth + confidentiality loss).
- **Mitigation:** `encrypt()` draws a fresh `os.urandom(12)` nonce per call
  (`app/core/crypto.py`). `test_fresh_nonce_per_encryption` asserts 16 distinct
  nonces over 16 encryptions of identical plaintext.
- **Residual:** None found.

### T4 — Server stores a security key (zero-knowledge breach)
- **Actor:** insider / DB dump / disk image.
- **Likelihood:** Low (no code path writes raw keys).
- **Impact:** Critical (end-to-end confidentiality loss).
- **Mitigation:** Only `wrapped_meta_key` + `key_salt` are persisted
  (`schema.py`). `test_d2_zero_knowledge_keys_never_persisted` scans the DB
  file for the raw keys. Derived buffers are zeroized by `key_scope`.
- **Residual:** The wrapped meta key + salt are on disk; without both security
  keys the attacker cannot derive the master key to unwrap it. Acceptable.

### T5 — Redis persistence leaks session/key material to disk
- **Actor:** disk image theft.
- **Likelihood:** Low.
- **Impact:** Medium.
- **Mitigation:** compose runs `redis-server --appendonly no --save ""`
  (lane/ops); `TTLCache` enforces a TTL on every SET so nothing outlives the
  cache window. The app stores no key material in Redis at all (identity only).
- **Residual:** None found.

### T6 — Plaintext media written to disk (temp file)
- **Actor:** disk image theft / malware on host.
- **Likelihood:** Low.
- **Impact:** High.
- **Mitigation:** uploads are encrypted in memory then written as ciphertext;
  downloads are decrypted and streamed to the socket with **no** temp file
  (`app/api/file_routes.py`, `app/core/storage.py::decrypt_stream`).
  `test_zero_plaintext_on_disk_R3` + `test_r3_no_temp_files_created` scan the
  storage tree and assert no plaintext and no new files after a download.
- **Residual:** Decrypted bytes exist transiently in process memory (required
  to serve them). Acceptable.

### T7 — Metadata plaintext leaked via SQLite
- **Actor:** DB file theft / SQL dump.
- **Likelihood:** Low.
- **Impact:** Medium (privacy — reveals names/paths).
- **Mitigation:** metadata columns store only AES-GCM hex (directive #3).
  `test_d3_metadata_encrypted_not_readable_without_keys` verifies absence of
  plaintext in the DB file.
- **Residual:** `Users.username` is plaintext (needed for login identity).
  Acceptable — it is not "media metadata".

### T8 — JWT forgery / replay
- **Actor:** network attacker.
- **Likelihood:** Low (needs `SECWEB_JWT_SECRET`).
- **Impact:** High (impersonation — but still requires the security keys to
  read data, see T1).
- **Mitigation:** HS256 with server-side `SECWEB_JWT_SECRET` (env, required by
  compose), `exp` enforced (`app/core/auth.py`). A valid JWT alone is
  insufficient for any key-bearing route (403 without the keys).
- **Residual:** token valid until `exp`; no server-side revocation (see
  SECURITY.md finding 5).

### T9 — Path traversal via file id
- **Actor:** attacker.
- **Likelihood:** Low.
- **Impact:** High (read arbitrary files).
- **Mitigation:** `app/core/storage.py::safe_file_uuid` parses the id with
  `uuid.UUID()` and rejects anything non-UUID; the store only ever joins
  `<user_id>/<uuid>.bin`.
- **Residual:** None found.

### T10 — Multipart upload DoS (memory exhaustion)
- **Actor:** abusive client.
- **Likelihood:** Medium.
- **Impact:** Medium (availability).
- **Mitigation:** *partial* — bcrypt + per-user isolation limit blast radius.
- **Residual:** **GAP** — no upload size cap (`file_routes.py::upload`). See
  SECURITY.md finding 2 / `patches/0002`.

### T11 — Thumbnail generation DoS (Pillow decompression bomb)
- **Actor:** abusive client uploading a crafted image.
- **Likelihood:** Medium.
- **Impact:** Medium-High (worker crash / memory exhaustion).
- **Mitigation:** *partial* — `make_thumbnail` downscales to 256px.
- **Residual:** **GAP** — no `MAX_IMAGE_PIXELS` cap before downscale. See
  SECURITY.md finding 1 / `patches/0001`.

### T12 — Brute-force of identity password
- **Actor:** online attacker.
- **Likelihood:** Medium.
- **Impact:** Medium (identity, not media — still needs the two security keys).
- **Mitigation:** bcrypt (cost 10) per user; constant 401 responses; username
  uniqueness.
- **Residual:** **GAP** — no rate limiting. See SECURITY.md finding 4.

### T13 — Cache poisoning / stale plaintext
- **Actor:** attacker or bug.
- **Likelihood:** Low.
- **Impact:** Medium.
- **Mitigation:** the app does **not** cache decrypted content or metadata in
  Redis (only identity/session). `TTLCache` guarantees any key expires.
- **Residual:** None found.

### T14 — Login-surface credential caching by browser
- **Actor:** shoulder-surfing / shared device.
- **Likelihood:** Low.
- **Impact:** Medium.
- **Mitigation:** `autocomplete="off"` + readonly-on-focus on key fields
  (`Login.tsx`); `Cache-Control: no-store` on auth responses; keys wiped on
  `beforeunload` (`main.tsx`).
- **Residual:** browser may still retain history/JS heap — inherent to a SPA;
  recommend a dedicated profile / private mode for high-sensitivity use.

### T15 — XSS leading to token/key theft
- **Actor:** supply-chain or injection bug.
- **Likelihood:** Low.
- **Impact:** High.
- **Mitigation:** React escaping by default, no `dangerouslySetInnerHTML`,
  no `eval`, CSP-recommended (SECURITY.md).
- **Residual:** recommend the CSP + `X-Content-Type-Options: nosniff` headers
  at the edge (not yet enforced server-side).

---

## Attack-surface notes

- **No CORS middleware** → browser default is same-origin only (secure default).
  If cross-origin is ever needed, add an explicit allow-list (SECURITY.md #3).
- **No `Sec-Web`-specific timing side-channels** were identified: bcrypt is the
  only variable-time compare and it is used for identity only; AES-GCM tag
  compare is constant-time inside `cryptography`.
- **Error messages** are uniform on key rejection (no plaintext leak).
