# cloud-r2pan

A file-sharing system styled after the iOS 26 liquid-glass aesthetic, built on
**Cloudflare Workers + R2 + D1** with **zero runtime dependencies**.

Features: uploads with folders, share links (expiry / download cap / access password), standalone
direct links, a public download marketplace, activation-code quotas, monthly traffic limits,
per-IP duplicate-download blocking with auto-ban, download logs and a world map, login audit with
optional 2FA, Turnstile human verification, OAuth-gated downloads, **WebDAV mounting**, and a
Chinese/English UI.

The detailed architecture doc is [README.md](README.md) (Chinese); deployment walkthroughs are
[DEPLOY.md](DEPLOY.md) and [DEPLOY-S3.md](DEPLOY-S3.md) for any S3-compatible backend instead of R2.
This file is the short English version.

## Layout

```
src/index.ts          routing + public-endpoint rate limiting
src/admin.ts          every /api/admin/* endpoint
src/public.ts         visitor side: share info, password verify, download gates, direct links
src/market.ts         marketplace queries (pagination / search / sort)
src/webdav.ts         PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY
src/folders.ts        the folder tree: path <-> id resolution and mutation
src/storage.ts        storage abstraction — R2 or any S3-compatible endpoint (own SigV4 signer)
src/db.ts             D1 schema, versioned migrations, legacy folder-data migration
src/limits.ts         upload size gate (per-file cap + total quota)
public/*.html         single-file SPAs served by the Worker as text modules
```

## Bindings

Declared in `wrangler.jsonc` (create them first, then paste the D1 id in):

| Binding | Type | Required | Purpose |
| --- | --- | --- | --- |
| `db` | D1 database `cloud-r2pan` | yes | metadata, shares, logs, settings |
| `r2` | R2 bucket `cloud-r2pan` | yes, unless you configure S3 in the admin UI | file storage |
| `admin` | Secret | yes | admin login key and the key material for HMAC / AES-GCM |
| `analytics` | Analytics Engine dataset `r2pan_downloads` | no | world map; falls back to `download_logs` |
| `turnstile_sitekey` / `turnstile_secret` | Secret | no | human verification |
| `totp_recovery` | Secret | no | fixed recovery code |

`database_id` is the only value you must fill in by hand; everything else is created automatically
on first request (tables, migrations, settings).

## Data model

One folder tree: `folders(id, name, parent_id)` with `files.folder_id` pointing at it, unique per
level and reusable across levels. Paths in URLs are resolved on the fly and are not stored —
renaming or moving a directory updates one row instead of rewriting a subtree. The legacy
`directories` table and `files.path` column are read only by the idempotent migration that moves old
data into the tree.

## Download pipeline

```
banned IP → link exists / not revoked / not expired / cap not hit → password → OAuth
→ Turnstile → monthly traffic quota → per-IP duplicate check → atomic slot decrement → Range stream
```

The slot decrement happens **after** every gate, so blocked requests (including wrong passwords)
can never burn a share's download allowance.

## Security notes

- Session cookie `cd_admin` is `expiry.HMAC-SHA256(admin, expiry)`, HttpOnly, SameSite=Strict,
  Secure over HTTPS; login is rate limited per IP and every attempt is audited.
- Share passwords are stored twice: a hash for verification and an AES-GCM (HKDF from `admin`)
  ciphertext so the owner can look at it again. The share list no longer ships every password —
  the console fetches one at a time on demand.
- WebDAV credentials are PBKDF2-SHA256 (50k iterations; workerd caps PBKDF2 at 100k), with 8 failed
  attempts per minute per IP before the expensive derivation is skipped entirely.
- `max_upload_mb` (default 100; raising it is pointless — the Workers request body caps there):
  the declared `Content-Length` is checked first, then the real size reported by the storage
  layer is re-checked after the write and the object is deleted if it was over. `req.body` must be
  handed to storage untouched — R2 only accepts streams of known length (the request body itself
  or a `FixedLengthStream`), so a `pipeThrough` counting wrapper would be rejected outright.
- OAuth `?redirect=` accepts in-site paths only; all HTML output is escaped and served with CSP,
  `X-Frame-Options` and `Referrer-Policy`.
- Admin errors return a short `ref`; the stack trace stays in the Worker log.

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit, strict, no errors
npm test            # esbuild-bundled assertion suites on an in-memory fake D1
npx wrangler dev    # put admin=... in .dev.vars
```

Each file in `test/` is a standalone assertion script (no test framework): SigV4 signatures checked
against an independent `node:crypto` implementation, download-gate ordering, folder-tree parsing and
migration, every WebDAV method, and admin endpoint edge cases.
