# lane/security

Security review of the SecWeb backend + hardening deliverables.

## Contents
- `docs/SECURITY.md` — directive-by-directive verdicts (#1–#6, tenancy, R1–R5),
  with `file:line` citations and a Findings section.
- `docs/THREAT-MODEL.md` — STRIDE threat model (T1–T15) with mitigations +
  residual risk.
- `docs/CHECKLIST.md` — release-gate checklist (commands that PROVE compliance).
- `patches/` — two non-blocking hardening patches for `lane/backend`:
  - `0001-storage-pillow-bomb.patch` (Pillow decompression-bomb cap)
  - `0002-upload-size-limit.patch` (upload size limit)

## Verdict
All 6 IMMUTABLE directives **PASS** (#6 with a documented reservation). Two
hardening GAPs (Pillow bomb, upload size) are patched for the backend lane.
