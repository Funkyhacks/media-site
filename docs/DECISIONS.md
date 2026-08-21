# SecWeb — Accepted Decisions

> Operator **Funkyhacks** accepted these on **2026-08-20**. All other defaults
> follow the CTO loop's standing recommendations (recorded in `docs/ARCHITECTURE.md`).

| # | Question | Decision |
|---|---|---|
| 1 | Cipher | **AES-256-GCM** |
| 2 | Key derivation | **HKDF-SHA256** |
| 3 | Metadata key | **Separate wrapped key** |
| 4 | Tenancy | **Multi-user** (per-user key isolation) |
| 5 | CI | **Yes — GitHub Actions** |

Standing defaults approved: fresh 12-byte nonce per op + AAD binding; key
zeroization after use; bcrypt for password identity; HS256 JWT (server
`JWT_SECRET`, independent of security keys); chunked streaming with zero plaintext
to disk; Redis ephemeral (`appendonly no`, `save ""`, TTL on every set); thumbnails
encrypted to `UUID_thumb.bin`.

## Next observable action
Dispatch the P0 build lanes (Dev backend+tests · Frontend · Security · Ops CI+Docker)
into `Funkyhacks/media-site` per `docs/ARCHITECTURE.md`.
