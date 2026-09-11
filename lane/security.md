# lane/security

Security review of the SecWeb backend (zero-knowledge, multi-user, encrypted
media portal) + hardening deliverables.

## Contents
- `docs/SECURITY.md` — directive-by-directive verdicts (#1–#6, tenancy, R1–R5),
  with `file:line` citations and a Findings section (findings 1–10).
- `docs/THREAT-MODEL.md` — STRIDE threat model (T1–T19) with mitigations +
  residual risk.
- `docs/CHECKLIST.md` — release-gate checklist (commands that PROVE compliance).
- `patches/` — non-blocking hardening patches for `lane/backend` (each verified
  to `git apply --check` against the live backend tree, and the full test suite
  still passes with all applied):
  - `0001-storage-pillow-bomb.patch` (Pillow decompression-bomb cap)
  - `0002-upload-size-limit.patch` (upload size limit)
  - `0003-strict-base64-keys.patch` (strict base64 security-key decode)
  - `0004-secretbytes-mask-repr.patch` (no key bytes in `repr`/`str`)
  - `0005-jwt-secret-enforcement.patch` (flag weak/default JWT secret)
  - `0006-content-disposition-sanitize.patch` (RFC 6266, no header breakout)

## Verdict
All 6 IMMUTABLE directives **PASS** (#6 with a documented reservation). Six
hardening GAPs are patched for the backend lane: two DoS caps (Pillow bomb,
upload size) and four found in an independent re-review (base64 key decode,
key-material repr leak, JWT-secret enforcement, Content-Disposition). None of
the six are directive violations; all are non-blocking but recommended before
production.

## Method (independent re-review, 2026-08-29)
- Static read of every module in `app/` plus the full pytest suite
  (79 passed) that encodes the directives; cross-checked each immutable
  directive and standing default (R1 AAD, R2 fresh nonce, R3 zero-plaintext-to-
  disk, R5 TTL).
- Verified the existing lane's citations against the actual code (all cited test
  names exist; the frontend code cited for directive #6 is present and correct).
- PoC-confirmed the four new findings against the live backend venv before
  writing them up; generated the four patches by diffing real file copies and
  proved them with `git apply --check` (original tree) + the 79-test suite
  (patched scratch tree) before committing them here.
