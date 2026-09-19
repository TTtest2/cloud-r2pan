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

`files` also carries `deleted_at` (non-null = in the trash), `sha256` (browser-computed, enables
instant upload) and `etag` (the storage receipt, used for post-write dedupe). `shares.folder_id`
marks a directory share, in which case `file_id` is the `''` sentinel. `upload_sessions` tracks
in-flight multipart uploads so stale ones can be aborted.

## Download pipeline

```
banned IP → link exists / not revoked / not expired / cap not hit → password → OAuth
→ Turnstile → monthly traffic quota → per-IP duplicate check → atomic slot decrement → Range stream
```

The slot decrement happens **after** every gate, so blocked requests (including wrong passwords)
can never burn a share's download allowance. Shares and direct links with **no** cap take the same
column anyway (a second, unguarded `UPDATE`), because that is what the console and marketplace
display as "times downloaded" — skipping it would leave them showing 0 forever.

A `206` carries exactly the requested bytes. R2 wants the slice nested — `get(key, { range: {
offset, length } })`; the legacy top-level `offset`/`length` keys are silently ignored and push the
whole object back under a correct-looking `Content-Range`. The S3 backend sends a real `Range:`
header. `test/storage-range.ts` pins both shapes.

> Heads-up for your own testing: the duplicate gate counts per *share/direct-link + IP*, so tapping
> download twice on one link with `max_downloads_per_ip` and auto-ban on will lock your own egress
> IP in `banned_ips` (24 h by default). Unban it from the console afterwards.

## Security notes

- Session cookie `cd_admin` is `expiry.HMAC-SHA256(admin, expiry)`, HttpOnly, SameSite=Strict,
  Secure over HTTPS; login is rate limited per IP and every attempt is audited.
- Share passwords are stored twice: a hash for verification and an AES-GCM (HKDF from `admin`)
  ciphertext so the owner can look at it again. The share list no longer ships every password —
  the console fetches one at a time on demand.
- WebDAV credentials are PBKDF2-SHA256 (50k iterations; workerd caps PBKDF2 at 100k), with 8 failed
  attempts per minute per IP before the expensive derivation is skipped entirely.
- Uploads go through `limits.ts`: `max_upload_mb` (default 100, configurable up to 50 GB) is checked
  against the declared `Content-Length` first and re-checked against the real size reported by
  storage after the write, deleting the object when it was over. `req.body` must be handed to
  storage untouched — R2 only accepts streams of known length (the request body itself or a
  `FixedLengthStream`), so a `pipeThrough` counting wrapper would be rejected outright.
  Files over 64 MB upload in 8 MiB chunks (`init` → `part` → `complete`), which is what lifts the
  old single-request 100 MB ceiling.
- OAuth `?redirect=` accepts in-site paths only; all HTML output is escaped and served with CSP,
  `X-Frame-Options` and `Referrer-Policy`.
- Admin errors return a short `ref`; the stack trace stays in the Worker log.

## Sharing a directory

A share points at either one file or one folder. Directory shares are browsable
(`GET /s/:token/children`) inside the shared subtree only — the breadcrumb never escapes the shared
root — and files download one by one via `?file=<id>`; expiry, password and the download cap apply
to the whole link. Because the marketplace and `/d/:id` direct links are single-file concepts,
directory shares are excluded from both.

## Recycle bin and scheduled cleanup

Deleting sets `files.deleted_at` instead of destroying anything: objects stay, shares and direct
links stay (so restoring brings them back), and purge happens after `trash_retention_days`
(default 7, max 90, 0 disables the bin). Trashed objects still count against storage, so the
overview reports both total bytes and reclaimable trash bytes. An hourly cron (one of the five the
free plan allows) revokes expired shares, drops expired direct links, purges expired trash, aborts
stale multipart uploads and samples objects to report any whose bytes vanished — reporting only.
The destructive "files with no share reference" sweep stays manual and now merely fills the bin.

## Content dedupe and instant upload

Two namespaced fingerprints, `sha256:` (computed in the browser for files up to 256 MB; WebCrypto
has no streaming digest) and `etag:` (the receipt storage hands back for free). A hit on
`upload/check` lets `upload/claim` add a row without transferring a byte; otherwise a duplicate
found after the write is discarded and the row repointed to the surviving key. From then on several
rows can share one object key, so deleting an object is decided by the remaining reference count and
all quota maths groups by key. Claiming is still subject to the per-file cap — reuse must not become
a way around it.

## Free-plan quotas these constants come from

Verified September 2026 against Cloudflare's own docs:

| Limit | Free tier | What this codebase chose |
|---|---|---|
| R2 storage | 10 GB-month | trash capped at 90 days, default 7 (soft deletes still occupy storage) |
| R2 Class A (writes, lists, part uploads) | 1M/month | 8 MiB chunks → a 1 GB file ≈ 128 writes |
| R2 Class B (reads) | 10M/month | one read per download; cron samples 20 objects per run |
| R2 object / parts | 5 TiB / 10,000 parts | per-file cap configurable to 50 GB (10,000 × 8 MiB ≈ 80 GB is the protocol wall) |
| Workers request body | 100 MB (same on paid) | why the chunked channel exists; each part ≤96 MiB |
| Workers CPU | **10 ms/invocation** | no in-Worker zip packaging, no server-side hashing of large files, batched cron |
| Workers subrequests | 50/invocation | `CLEANUP_BATCH = 50`, `UPLOAD_REAP_BATCH = 20` (one abort = one subrequest) |
| Workers cron triggers | 5 | exactly one, hourly |
| D1 queries | 50/invocation | every cleanup step is batched |
| D1 bound parameters | 100/query | every `IN (...)` is sliced at 50 (soft delete binds a timestamp too) |
| D1 database size | 500 MB | metadata is tiny; `download_logs` is what grows, and the console can purge it |

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
