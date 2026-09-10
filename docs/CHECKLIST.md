# SecWeb — Release-Gate Checklist

> Run every item before shipping. Each maps to an IMMUTABLE directive or a
> standing default. **All must be GREEN.**

## 0. Toolchain
- [ ] `python --version` ≥ 3.10
- [ ] `node --version` ≥ 20 (frontend build)
- [ ] `docker --version` present (ops)

## 1. Backend tests (directives #1–#5 + R1–R3/R5)
- [ ] `cd <lane/backend> && pip install -r requirements.txt`
- [ ] `python -m pytest -q` → **79 passed, 0 failed**
  - `tests/test_crypto.py` (HKDF, AES-GCM, nonce-freshness **R2**, AAD, zeroize)
  - `tests/test_cache.py` (TTL enforcement **R5 / #5**)
  - `tests/test_directives.py` (#1–#6 + tenancy)
  - `tests/test_files.py` (R3 zero-plaintext-to-disk, storage layout **#4**)
  - `tests/test_folders.py` (#3 encrypted metadata)

## 2. Frontend build + tests
- [ ] `cd <lane/frontend> && npm install`
- [ ] `npm run typecheck` → **0 errors**
- [ ] `npm test` → **7 passed**
- [ ] `npm run build` → `dist/` produced

## 3. Directive #1 — dual-key
- [ ] `pytest -q tests/test_crypto.py::test_derive_master_key_requires_both_keys`
- [ ] Register with one key omitted → **422**

## 4. Directive #2 — zero-knowledge
- [ ] `pytest -q tests/test_directives.py::test_d2_zero_knowledge_keys_never_persisted`
- [ ] `pytest -q tests/test_directives.py::test_zeroize_on_exception`

## 5. Directive #3 — encrypted metadata
- [ ] `pytest -q tests/test_folders.py::test_folder_row_is_encrypted_in_db`
- [ ] `pytest -q tests/test_files.py::test_metadata_encrypted_in_db_directive3`

## 6. Directive #4 — obfuscated storage
- [ ] `pytest -q tests/test_files.py::test_storage_layout_directive4`

## 7. Directive #5 — ephemeral Redis
- [ ] `pytest -q tests/test_cache.py::test_set_requires_positive_ttl`
- [ ] `grep -F -- '--appendonly' docker-compose.yml && grep -F -- '"no"' docker-compose.yml` (lane/ops)

## 8. Directive #6 — no browser persistence
- [ ] `grep -rn 'autocomplete="off"' src/components/Login.tsx` (lane/frontend)
- [ ] `pytest -q tests/test_auth.py::test_register_success` (asserts `no-store`)
- [ ] `grep -n 'beforeunload' src/main.tsx` (lane/frontend)

## 9. Tenancy (D4)
- [ ] `pytest -q tests/test_files.py::test_cross_user_cannot_read_file`
- [ ] `pytest -q tests/test_directives.py::test_d4_cross_user_key_cannot_decrypt_other_user`

## 10. Hardening gaps (see docs/SECURITY.md Findings)
- [ ] Pillow decompression-bomb cap applied (`patches/0001`)
- [ ] Upload size limit applied (`patches/0002`)
- [ ] Strict base64 key decoding (`patches/0003`) — non-base64 → 400
- [ ] `SecretBytes.__repr__`/`__str__` redacted (`patches/0004`) — no key bytes in logs
- [ ] Weak/default JWT secret flagged at startup (`patches/0005`)
- [ ] RFC 6266 `Content-Disposition` (`patches/0006`) — no header breakout
- [ ] **All patches verify before ship:**
  ```bash
  for p in patches/000*.patch; do
    ( cd <lane/backend> && git apply --check "$p" ) || echo "FAIL $p"
  done
  ```
- [ ] (Recommended) explicit CORS allow-list if cross-origin
- [ ] (Recommended) rate limiting on `/api/auth/*`
- [ ] (Recommended) CSP + `X-Content-Type-Options: nosniff` at the edge

## 11. Deployment
- [ ] `SECWEB_JWT_SECRET` is set to a **random ≥ 32-byte** value (never the default)
- [ ] `docker compose config --quiet` (lane/ops)
- [ ] Health check: `GET /api/health` → `{"status":"ok","redis":"up"}`
