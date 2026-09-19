/**
 * 目录分享测试（分享整个文件夹）
 *
 * 关键契约：
 *   1. 一条分享要么指向文件要么指向目录；目录分享 file_id = '' 哨兵 + folder_id
 *   2. 浏览/下载都必须落在被分享的子树内 —— 越界（../别的目录）一律拒绝
 *   3. 闸门（口令/过期/撤销/名额）对目录分享同样成立，且失败时不烧名额
 *   4. 目录分享不进市场、不派生直链（那两个概念都按"单个可下载文件"设计）
 *   5. 回收站里的文件对外不可见这条，目录分享也不例外
 *
 * 运行：
 *   npx esbuild test/share-folder.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/share-folder.mjs
 *   node .dev/share-folder.mjs
 */
import { handleAdminApi } from "../src/admin";
import { handleShareChildren, handleDownload, handleShareInfo, handleVerify } from "../src/public";
import { queryMarket, parseMarketParams } from "../src/market";
import { createSession } from "../src/auth";
import { invalidateFolderTree } from "../src/folders";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const ADMIN_SECRET = "test-admin-secret";
const NEW_TABLE_SQL =
  "CREATE TABLE \"folders\"(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)";

interface Folder { id: string; name: string; parent_id: string | null }
interface File { id: string; key: string; name: string; size: number; mime: string; folder_id: string | null; deleted_at: number | null }
interface Share {
  id: string; file_id: string; folder_id: string | null; created_at: number;
  expires_at: number | null; max_downloads: number | null; download_count: number;
  revoked: number; password_hash: string | null; password_cipher: string | null;
  download_name: string | null; is_market: number; market_views: number;
  market_title: string | null; market_desc: string | null; direct_id: string | null;
}

class Db {
  folders: Folder[] = [
    { id: "root", name: "docs", parent_id: null },
    { id: "sub", name: "2024", parent_id: "root" },
    { id: "deep", name: "deep", parent_id: "sub" },
    { id: "elsewhere", name: "secret", parent_id: null },
  ];
  files: File[] = [
    { id: "fa", key: "files/fa", name: "a.txt", size: 11, mime: "text/plain", folder_id: "root", deleted_at: null },
    { id: "fb", key: "files/fb", name: "b.txt", size: 22, mime: "text/plain", folder_id: "sub", deleted_at: null },
    { id: "fc", key: "files/fc", name: "c.bin", size: 33, mime: "application/octet-stream", folder_id: "deep", deleted_at: null },
    { id: "fd", key: "files/fd", name: "d.txt", size: 44, mime: "text/plain", folder_id: "sub", deleted_at: 1 },
    { id: "fx", key: "files/fx", name: "x.txt", size: 55, mime: "text/plain", folder_id: "elsewhere", deleted_at: null },
  ];
  shares: Share[] = [];
  links: { id: string; file_id: string }[] = [];
  logs: number = 0;
  trafficDays: number = 0;
  settings: Record<string, string> = { turnstile_mode: "off", traffic_limit_bytes: "0", max_downloads_per_ip: "0", oauth_enabled: "0", admin_ips: "" };
  sqlLog: string[] = [];

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    let binds: any[] = [];
    const self = this;
    const stmt: any = {
      bind(...vals: unknown[]) {
        binds = vals as any[];
        return stmt;
      },
      async first() {
        return self.run(norm, binds, "first");
      },
      async all() {
        return { results: self.run(norm, binds, "all") ?? [], success: true, meta: {} };
      },
      async run() {
        self.run(norm, binds, "run");
        return { success: true, meta: { changes: 1 } };
      },
    };
    return stmt;
  }
  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }

  /** 分享行的投影（按 SQL 里出现的 s.xxx 列给值，避免伪造字段） */
  private project(s: Share, sql: string): any {
    const cols = [...new Set([...sql.matchAll(/\bs\.([a-z_]+)/g)].map((m) => m[1]))];
    const row: any = {};
    for (const c of cols) row[c] = (s as any)[c];
    return row;
  }

  private run(sql: string, binds: any[], mode: string): any {
    this.sqlLog.push(sql);
    // 真 D1 会拒绝"占位符个数 ≠ 绑定值个数"，假库必须一样严格
    const numbered = new Set([...sql.matchAll(/\?(\d+)/g)].map((m) => Number(m[1])));
    if (numbered.size && numbered.size !== binds.length) {
      throw new Error(`占位符与绑定不匹配（${numbered.size} vs ${binds.length}）: ${sql}`);
    }
    /* ensureSchema 冷启动 */
    if (/sqlite_master/.test(sql)) return /name='settings'/.test(sql) ? { name: "settings" } : { sql: NEW_TABLE_SQL };
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "9999" };
    if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path IS NOT NULL/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^CREATE INDEX|^DROP TABLE/.test(sql)) throw new Error("冷启动不该跑 DDL: " + sql);

    if (/^SELECT key, value FROM settings/.test(sql)) {
      return Object.entries(this.settings).map(([key, value]) => ({ key, value }));
    }
    if (/^SELECT id, name, parent_id, created_at FROM folders/.test(sql)) {
      return this.folders.map((f) => ({ ...f }));
    }
    if (/^SELECT id FROM files WHERE id = \?1/.test(sql)) {
      const f = this.files.find((x) => x.id === String(binds[0]) && !x.deleted_at);
      return f ? { id: f.id } : null;
    }
    if (/^SELECT id FROM folders WHERE id = \?1/.test(sql)) {
      const f = this.folders.find((x) => x.id === String(binds[0]));
      return f ? { id: f.id } : null;
    }
    if (/^INSERT INTO shares\(/.test(sql)) {
      const cols = /VALUES\(([^)]*)\)/.exec(sql)?.[1] ?? "";
      const names = /INSERT INTO shares\(([^)]*)\)/.exec(sql)![1].split(",").map((c) => c.trim());
      const row: any = {
        id: "", file_id: "", folder_id: null, created_at: Date.now(), expires_at: null, max_downloads: null,
        download_count: 0, revoked: 0, password_hash: null, password_cipher: null, download_name: null,
        is_market: 0, market_views: 0, market_title: null, market_desc: null, direct_id: null,
      };
      names.forEach((n, i) => (row[n] = binds[i]));
      // 占位符个数必须与列数一致（漏一个绑定就会在这里炸）
      if (cols.split(",").length !== names.length) throw new Error("shares 插入列数与占位符不符: " + sql);
      this.shares.push(row as Share);
      return null;
    }
    if (/^INSERT INTO direct_links|^UPDATE shares SET direct_id|^INSERT INTO download_logs|^INSERT INTO traffic_stats|^INSERT INTO banned_ips|^UPDATE settings SET|^INSERT INTO settings/.test(sql)) {
      if (/download_logs/.test(sql)) this.logs++;
      if (/traffic_stats/.test(sql)) this.trafficDays++;
      return null;
    }
    if (/^UPDATE shares SET download_count = download_count \+ 1/.test(sql)) {
      const [id, max] = binds;
      const s = this.shares.find((x) => x.id === id);
      if (!s) return { meta: { changes: 0 } };
      // 没有上限的分享只计数（单绑定），有上限的才带 download_count < ?2 守卫
      if (max === undefined || s.download_count < Number(max)) {
        s.download_count++;
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (/^UPDATE shares SET /.test(sql)) {
      const id = String(binds[binds.length - 1]);
      const s = this.shares.find((x) => x.id === id);
      if (!s) return null;
      const setPart = sql.slice(sql.indexOf("SET ") + 4, sql.indexOf(" WHERE "));
      [...setPart.matchAll(/([a-z_]+) = \?\d/g)].forEach((m, i) => ((s as any)[m[1]] = binds[i]));
      return null;
    }
    if (/^SELECT COUNT\(\*\) AS c FROM download_logs/.test(sql)) return { c: 0 };
    if (/^SELECT reason, expires_at FROM banned_ips/.test(sql)) return null;
    if (/^SELECT COUNT\(\*\) AS c FROM shares$/.test(sql)) return { c: this.shares.length };

    /* ── 文件分享（ INNER JOIN，回收站里的文件不可见）── */
    if (/FROM shares s JOIN files f/.test(sql) && /WHERE s\.id = \?1/.test(sql)) {
      const s = this.shares.find((x) => x.id === String(binds[0]));
      const f = s && this.files.find((x) => x.id === s.file_id && !x.deleted_at);
      if (!s || !f) return null;
      return { ...this.project(s, sql), key: f.key, name: f.name, size: f.size, mime: f.mime };
    }
    /* ── 目录分享 ── */
    if (/FROM shares s JOIN folders fo/.test(sql)) {
      const s = this.shares.find((x) => x.id === String(binds[0]) && x.file_id === "");
      const fo = s && this.folders.find((x) => x.id === s.folder_id);
      if (!s || !fo) return null;
      return { ...this.project(s, sql), name: fo.name };
    }
    /* ── 子树内的某个文件 ── */
    if (/^SELECT id, key, name, size, mime, folder_id FROM files WHERE id = \?\d+ AND deleted_at IS NULL AND folder_id IN/.test(sql)) {
      const fileId = String(binds[binds.length - 1]);
      const ids = binds.slice(0, -1).map(String);
      const f = this.files.find((x) => x.id === fileId && !x.deleted_at && x.folder_id && ids.includes(x.folder_id));
      return f ? { id: f.id, key: f.key, name: f.name, size: f.size, mime: f.mime, folder_id: f.folder_id } : null;
    }
    /* ── 目录里的文件列表 ── */
    if (/^SELECT id, name, size, mime FROM files WHERE folder_id = \?1/.test(sql)) {
      const dir = String(binds[0]);
      return this.files
        .filter((f) => f.folder_id === dir && !f.deleted_at)
        .sort((a, b) => (a.name < b.name ? -1 : 1))
        .map((f) => ({ id: f.id, name: f.name, size: f.size, mime: f.mime }));
    }
    /* ── 市场 ── */
    if (/SELECT COUNT\(\*\) AS c FROM shares s JOIN files f/.test(sql)) {
      return { c: this.marketRows(sql).length };
    }
    if (/SELECT s\.id AS share_id/.test(sql)) {
      return this.marketRows(sql).map((r) => r.row);
    }
    /* ── 后台分享列表（LEFT JOIN，目录分享也要在）── */
    if (/FROM shares s.*LEFT JOIN files f/.test(sql) && mode === "all") {
      const [limit, offset] = binds as number[];
      return [...this.shares]
        .sort((a, b) => b.created_at - a.created_at)
        .slice(offset, offset + limit)
        .map((s) => {
          const f = this.files.find((x) => x.id === s.file_id);
          const fo = s.folder_id ? this.folders.find((x) => x.id === s.folder_id) : null;
          return { ...this.project(s, sql), file_name: f?.name ?? null, file_size: f?.size ?? null, file_mime: f?.mime ?? null, folder_name: fo?.name ?? null };
        });
    }
    if (/^SELECT id, password_hash, folder_id FROM shares WHERE id = \?1/.test(sql)) {
      const s = this.shares.find((x) => x.id === String(binds[0]));
      return s ? { id: s.id, password_hash: s.password_hash, folder_id: s.folder_id } : null;
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }

  /** 市场行：目录分享（file_id='' ）天然被 INNER JOIN 排除 */
  private marketRows(sql: string) {
    return this.shares
      .map((s) => {
        const f = this.files.find((x) => x.id === s.file_id && !x.deleted_at);
        return f && s.is_market === 1 && s.revoked === 0
          ? { s, row: { ...this.project(s, sql), file_name: f.name, file_size: f.size, file_mime: f.mime } }
          : null;
      })
      .filter((x): x is { s: Share; row: any } => !!x);
  }
}

function newShare(db: Db, over: Partial<Share> = {}): Share {
  const s: Share = {
    id: "sh" + (db.shares.length + 1), file_id: "", folder_id: null, created_at: Date.now(), expires_at: null,
    max_downloads: null, download_count: 0, revoked: 0, password_hash: null, password_cipher: null,
    download_name: null, is_market: 0, market_views: 0, market_title: null, market_desc: null, direct_id: null, ...over,
  };
  db.shares.push(s);
  return s;
}

async function admin(db: Db, path: string, init: { method?: string; body?: unknown } = {}) {
  const env: any = { db, admin: ADMIN_SECRET, r2: r2 };
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    method: init.method ?? "GET",
    headers: { cookie, "cf-connecting-ip": "203.0.113.1", ...(init.body ? { "content-type": "application/json" } : {}) },
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  const res = await handleAdminApi(req, env, { waitUntil() {}, props: {} } as any, new URL(req.url).pathname);
  return { status: res.status, body: await res.json().catch(() => null) };
}

const r2 = {
  async get(key: string) {
    return { body: new Uint8Array(8), size: 8, httpEtag: "e", httpMetadata: { contentType: "text/plain" }, key };
  },
  async head(key: string) {
    return { size: 8, httpMetadata: { contentType: "text/plain" }, key };
  },
};

const waited: Promise<any>[] = [];
const ctx: any = { waitUntil: (p: Promise<any>) => void waited.push(Promise.resolve(p)), props: {} };

async function pub(db: Db, path: string, init: { method?: string; body?: unknown } = {}) {
  const env: any = { db, admin: ADMIN_SECRET, r2 };
  const req = new Request("https://pan.test" + path, {
    method: init.method ?? "GET",
    headers: { "cf-connecting-ip": "203.0.113.9", ...(init.body ? { "content-type": "application/json" } : {}) },
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  const token = path.split("/")[2];
  const sub = new URL("https://pan.test" + path).pathname.split("/").slice(3).join("/");
  let res: Response;
  if (sub === "info") res = await handleShareInfo(req, env, token);
  else if (sub === "children") res = await handleShareChildren(req, env, token);
  else if (sub === "verify") res = await handleVerify(req, env, token);
  else res = await handleDownload(req, env, ctx, token);
  await Promise.all(waited.splice(0));
  const body = await res.clone().json().catch(() => null);
  return { status: res.status, body, headers: res.headers };
}

function fresh(): Db {
  invalidateSettingsCache();
  invalidateFolderTree();
  return new Db();
}

async function main() {
  console.log("\n[1] 创建目录分享");
  {
    const db = fresh();
    const ok = await admin(db, "/api/admin/shares", { method: "POST", body: { folder_id: "root", expires_hours: null, max_downloads: null, password: null } });
    check("目录分享 201", ok.status === 201, JSON.stringify(ok.body));
    const s = db.shares[0];
    check("file_id 落 '' 哨兵 + folder_id 落目录", s.file_id === "" && s.folder_id === "root", JSON.stringify({ f: s.file_id, d: s.folder_id }));
    check("目录分享不派生直链", ok.body?.direct_url === null && db.links.length === 0, JSON.stringify(ok.body));
    const both = await admin(db, "/api/admin/shares", { method: "POST", body: { file_id: "fa", folder_id: "root", expires_hours: null, max_downloads: null, password: null } });
    check("文件与目录同时给 → 400", both.status === 400, String(both.status));
    const neither = await admin(db, "/api/admin/shares", { method: "POST", body: { expires_hours: null, max_downloads: null, password: null } });
    check("两个都不给 → 400", neither.status === 400, String(neither.status));
    const ghost = await admin(db, "/api/admin/shares", { method: "POST", body: { folder_id: "nope", expires_hours: null, max_downloads: null, password: null } });
    check("目录不存在 → 404", ghost.status === 404, String(ghost.status));
    const market = await admin(db, "/api/admin/shares", { method: "POST", body: { folder_id: "sub", expires_hours: null, max_downloads: null, password: null, is_market: true } });
    check("目录分享不上架市场", market.status === 201 && db.shares[1].is_market === 0, JSON.stringify(db.shares[1]));
  }

  console.log("\n[2] 浏览 /children");
  {
    const db = fresh();
    const s = newShare(db, { folder_id: "root" });
    const root = await pub(db, `/s/${s.id}/children`);
    check("根层：一个文件 + 一个子目录", root.status === 200 && root.body?.files?.length === 1 && root.body?.dirs?.length === 1, JSON.stringify(root.body));
    check("回收站里的文件不出现", !(root.body?.files ?? []).some((f: any) => f.id === "fd"), JSON.stringify(root.body?.files));
    check("下载链接带上 file 参数", root.body?.files?.[0]?.url === `/s/${s.id}/download?file=fa`, root.body?.files?.[0]?.url);
    const sub = await pub(db, `/s/${s.id}/children?dir=sub`);
    check("进入子目录可看到更深的目录", sub.status === 200 && sub.body?.dirs?.some((d: any) => d.id === "deep"), JSON.stringify(sub.body));
    check("面包屑从分享根开始", JSON.stringify(sub.body?.trail?.map((t: any) => t.name)) === JSON.stringify(["docs", "2024"]), JSON.stringify(sub.body?.trail));
    check("面包屑不含分享外的祖先", !(sub.body?.trail ?? []).some((t: any) => t.id === "elsewhere"));
    const outside = await pub(db, `/s/${s.id}/children?dir=elsewhere`);
    check("跳到别人的目录 → 403", outside.status === 403 && outside.body?.error === "not_in_share", JSON.stringify(outside.body));
    const otherRoot = await pub(db, `/s/${s.id}/children?dir=deep`);
    check("分享内更深一层可以（sub 之下）", otherRoot.status === 200, String(otherRoot.status));
    const fileShare = newShare(db, { file_id: "fa", folder_id: null });
    const notFolder = await pub(db, `/s/${fileShare.id}/children`);
    check("文件分享不能被浏览 → 400", notFolder.status === 400, String(notFolder.status));
    const gone = newShare(db, { folder_id: "root", revoked: 1 });
    check("撤销后浏览 → 410", (await pub(db, `/s/${gone.id}/children`)).status === 410);
    const expired = newShare(db, { folder_id: "root", expires_at: Date.now() - 1000 });
    check("过期后浏览 → 410", (await pub(db, `/s/${expired.id}/children`)).status === 410);
  }

  console.log("\n[3] 口令闸门对浏览同样生效");
  {
    const db = fresh();
    const hash = "salt:" + "0".repeat(64); // 只要非空即代表"需要口令"
    const s = newShare(db, { folder_id: "root", password_hash: hash });
    const denied = await pub(db, `/s/${s.id}/children`);
    check("没口令不能列目录", denied.status === 403 && denied.body?.error === "password_required", JSON.stringify(denied.body));
    const info = await pub(db, `/s/${s.id}/info`);
    check("info 仍可用并标记需要口令", info.status === 200 && info.body?.needs_password === true && info.body?.kind === "folder", JSON.stringify(info.body?.kind));
    const bad = await pub(db, `/s/${s.id}/verify`, { method: "POST", body: { password: "wrong" } });
    check("错口令 401", bad.status === 401, String(bad.status));
    const right = await pub(db, `/s/${s.id}/verify`, { method: "POST", body: { password: "x" } });
    check("口令不匹配时不会给出令牌", right.status === 401, JSON.stringify(right.body));
  }

  console.log("\n[4] 下载子树内的文件");
  {
    const db = fresh();
    const s = newShare(db, { folder_id: "root", max_downloads: 3 });
    const ok = await pub(db, `/s/${s.id}/download?file=fb`);
    check("子树内文件可下载", ok.status === 200, String(ok.status));
    check("用文件自己的名字与体积", (ok.headers.get("content-disposition") ?? "").includes(encodeURIComponent("b.txt")), ok.headers.get("content-disposition") ?? "");
    check("扣掉一次名额", db.shares[0].download_count === 1, String(db.shares[0].download_count));
    const noFile = await pub(db, `/s/${s.id}/download`);
    check("不带 file 直接下载目录 → 404", noFile.status === 404, String(noFile.status));
    const outside = await pub(db, `/s/${s.id}/download?file=fx`);
    check("分享外的文件下不到", outside.status === 404, String(outside.status));
    const trashed = await pub(db, `/s/${s.id}/download?file=fd`);
    check("回收站里的文件下不到", trashed.status === 404, String(trashed.status));
  }
  {
    const db = fresh();
    const s = newShare(db, { folder_id: "root", max_downloads: 5 });
    const before = await pub(db, `/s/${s.id}/download?file=nope`);
    check("无效 file 不烧名额", before.status === 404 && db.shares[0].download_count === 0, String(db.shares[0].download_count));
  }
  {
    const db = fresh();
    const s = newShare(db, { folder_id: "root" }); // 无上限
    const ok = await pub(db, `/s/${s.id}/download?file=fa`);
    check("无上限的分享也会计数", ok.status === 200 && db.shares[0].download_count === 1, String(db.shares[0].download_count));
    const bad = await pub(db, `/s/${s.id}/download?file=nope`);
    check("无上限时被拒的请求不计数", bad.status === 404 && db.shares[0].download_count === 1, String(db.shares[0].download_count));
  }

  console.log("\n[5] 文件分享的既有行为不受影响");
  {
    const db = fresh();
    const s = newShare(db, { file_id: "fa", download_name: "改名.txt" });
    const r = await pub(db, `/s/${s.id}/download`);
    check("单文件分享免 file 直接下", r.status === 200, String(r.status));
    check("download_name 仍然生效", (r.headers.get("content-disposition") ?? "").includes(encodeURIComponent("改名.txt")), r.headers.get("content-disposition") ?? "");
    const info = await pub(db, `/s/${s.id}/info`);
    check("info 报 kind=file 并带体积", info.body?.kind === "file" && info.body?.size === 11, JSON.stringify(info.body));
  }

  console.log("\n[6] 市场与后台列表");
  {
    const db = fresh();
    newShare(db, { folder_id: "root", is_market: 0 });
    newShare(db, { file_id: "fa", is_market: 1 });
    const m = await queryMarket({ db, admin: ADMIN_SECRET } as any, parseMarketParams(new URL("https://pan.test/api/market").searchParams));
    check("市场只出单文件分享", m.total === 1 && m.items.length === 1, JSON.stringify(m.items.map((i: any) => i.share_id)));
    const list = await admin(db, "/api/admin/shares");
    const rows: any[] = list.body?.shares ?? [];
    check("后台列表两种分享都在", rows.length === 2, JSON.stringify(rows.map((r) => r.kind)));
    check("目录分享标出 kind 与目录名", rows.some((r) => r.kind === "folder" && String(r.display_name).includes("docs")), JSON.stringify(rows.map((r) => r.display_name)));
    check("列表仍不下发 password_cipher", !db.sqlLog.some((q) => /SELECT .*password_cipher.*JOIN files/.test(q)), "");
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
