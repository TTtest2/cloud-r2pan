/**
 * 回收站端到端测试
 *
 * 覆盖三件事：
 *   1. 删除默认只打标记 —— 行、分享、对象都还在
 *   2. 打标记之后**所有对外读路径**都必须看不见它（分享页/直链/市场/后台默认列表），
 *      漏一处就是"删掉的文件还能被下载"
 *   3. 恢复要能原样复活（含分享），彻底删除才会动对象与级联
 *
 * 运行：
 *   npx esbuild test/trash-recycle-bin.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/trash-recycle-bin.mjs
 *   node .dev/trash-recycle-bin.mjs
 */
import { handleAdminApi } from "../src/admin";
import { handleShareInfo } from "../src/public";
import { queryMarket, parseMarketParams } from "../src/market";
import { createSession } from "../src/auth";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

interface Row {
  id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  folder_id: string | null;
  uploaded_at: number;
  deleted_at: number | null;
}

const NEW_TABLE_SQL =
  "CREATE TABLE \"folders\"(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)";

/** storage.ts 按设置指纹只造一个 provider，绑的是第一次见到的 r2 —— 所以删除记录要放全局 */
const OBJECT_DELETES: string[] = [];

class Db {
  files: Row[] = [];
  folders: { id: string }[] = [];
  shares: { id: string; file_id: string; download_count: number; revoked: number; is_market: number }[] = [];
  directLinks: { id: string; file_id: string }[] = [];
  deletedLogs: number = 0;
  /** 设置表：trash_retention_days 等 */
  settings: Record<string, string> = { turnstile_mode: "off", admin_ips: "" };
  get objectDeletes(): string[] {
    return OBJECT_DELETES;
  }

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

  private run(sql: string, binds: any[], mode: string): any {
    /* ── ensureSchema 冷启动 ── */
    if (/sqlite_master/.test(sql)) return mode === "all" ? [] : { name: "settings", sql: NEW_TABLE_SQL };
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "999" };
    if (/^SELECT 1 FROM directories LIMIT 1/.test(sql) || /FROM files WHERE folder_id IS NULL AND path IS NOT NULL/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^CREATE INDEX/.test(sql)) throw new Error("冷启动不该跑 DDL: " + sql);
    if (/^SELECT key, value FROM settings/.test(sql)) {
      return Object.entries({ ...this.settings }).map(([key, value]) => ({ key, value }));
    }

    /* ── 市场：COUNT / 分页（都要按 SQL 是否要求 deleted_at IS NULL 过滤）── */
    if (/SELECT COUNT\(\*\) AS c FROM shares s JOIN files f/.test(sql)) {
      const live = /f\.deleted_at IS NULL/.test(sql);
      const n = this.shares.filter((s) => {
        const f = this.files.find((x) => x.id === s.file_id);
        return f && s.is_market === 1 && s.revoked === 0 && (!live || !f.deleted_at);
      }).length;
      return { c: n };
    }
    if (/SELECT s\.id AS share_id/.test(sql)) {
      const live = /f\.deleted_at IS NULL/.test(sql);
      return this.shares
        .map((s) => ({ ...s, ...(this.files.find((x) => x.id === s.file_id) ?? {}) }))
        .filter((r) => r.share_id !== undefined)
        .filter((r: any) => {
          const f = this.files.find((x) => x.id === r.file_id);
          return f && r.is_market === 1 && r.revoked === 0 && (!live || !f.deleted_at);
        })
        .map((r: any) => ({
          share_id: r.id,
          created_at: 1,
          download_count: r.download_count,
          market_views: 0,
          market_title: null,
          market_desc: null,
          file_name: r.name,
          file_size: r.size,
          file_mime: r.mime,
        }));
    }

    /* ── 目录分享（本测试里不存在）── */
    if (/FROM shares s JOIN folders fo/.test(sql)) return null;

    /* ── 分享/直链 单条读 ── */
    if (/FROM shares s JOIN files f/.test(sql) && /WHERE s\.id = \?1/.test(sql)) {
      const live = /f\.deleted_at IS NULL/.test(sql);
      const j = this.shares.find((s) => s.id === binds[0]);
      const f = j && this.files.find((x) => x.id === j.file_id);
      if (!f || (live && f.deleted_at)) return null;
      return { ...j, ...f, created_at: 1, expires_at: null, max_downloads: null, download_name: null, password_hash: null };
    }
    if (/FROM direct_links dl JOIN files f/.test(sql)) {
      const live = /f\.deleted_at IS NULL/.test(sql);
      const j = this.directLinks.find((d) => d.id === binds[0]);
      const f = j && this.files.find((x) => x.id === j.file_id);
      if (!f || (live && f.deleted_at)) return null;
      return { ...j, ...f, created_at: 1, expires_at: null, max_downloads: null, download_count: 0, revoked: 0, download_name: null };
    }

    /* ── 后台文件列表（含回收站视图）── */
    if (/^SELECT COUNT\(\*\) AS c FROM files f WHERE/.test(sql)) {
      const wantTrash = /f\.deleted_at IS NOT NULL/.test(sql);
      return { c: this.files.filter((f) => (wantTrash ? !!f.deleted_at : !f.deleted_at)).length };
    }
    if (/^SELECT f\.id, f\.name, f\.size, f\.mime, f\.uploaded_at, f\.folder_id, f\.deleted_at/.test(sql)) {
      const wantTrash = /f\.deleted_at IS NOT NULL/.test(sql);
      return this.files.filter((f) => (wantTrash ? !!f.deleted_at : !f.deleted_at));
    }

    /* ── 统计 ── */
    if (/^SELECT COUNT\(\*\) AS c FROM files WHERE deleted_at IS NULL/.test(sql)) {
      return { c: this.files.filter((f) => !f.deleted_at).length };
    }
    if (/^SELECT COUNT\(\*\) AS c FROM files WHERE deleted_at IS NOT NULL/.test(sql)) {
      return { c: this.files.filter((f) => f.deleted_at).length };
    }
    if (/AS bytes FROM \(SELECT MIN\(size\) AS s FROM files WHERE deleted_at IS NOT NULL GROUP BY key\)/.test(sql)) {
      const seen = new Set<string>();
      const bytes = this.files.filter((f) => f.deleted_at && !seen.has(f.key) && seen.add(f.key)).reduce((a, b) => a + b.size, 0);
      return { bytes };
    }
    if (/AS bytes FROM \(SELECT MIN\(size\) AS s FROM files GROUP BY key\)/.test(sql)) {
      const seen = new Set<string>();
      const bytes = this.files.filter((f) => !seen.has(f.key) && seen.add(f.key)).reduce((a, b) => a + b.size, 0);
      return { bytes };
    }
    if (/^SELECT key, COUNT\(\*\) AS c FROM files WHERE key IN/.test(sql)) {
      return binds.map(String)
        .map((k) => ({ key: k, c: this.files.filter((f) => f.key === k).length }))
        .filter((r) => r.c > 0);
    }
    if (/COUNT\(\*\) AS c FROM shares/.test(sql)) return { c: this.shares.length };
    if (/COALESCE\(SUM\(downloads\), 0\) AS c FROM traffic_stats/.test(sql)) return { c: 0 };
    if (/FROM traffic_stats WHERE day/.test(sql)) return mode === "all" ? [] : { bytes: 0, downloads: 0 };
    if (/FROM download_logs ORDER BY id DESC LIMIT 10/.test(sql)) return [];
    if (/COUNT\(\*\) AS c FROM banned_ips/.test(sql)) return { c: 0 };

    /* ── 回收站写入路径 ── */
    const byIds = /^SELECT id, key, folder_id FROM files WHERE id IN \(([^)]*)\)( AND deleted_at IS NULL| AND deleted_at IS NOT NULL)?/.exec(sql);
    if (byIds) {
      const n = byIds[1].split(",").length;
      const ids = binds.slice(0, n).map(String);
      const scope = byIds[2] || "";
      return this.files
        .filter((f) => ids.includes(f.id))
        .filter((f) => (scope.includes("IS NULL") ? !f.deleted_at : scope.includes("IS NOT NULL") ? !!f.deleted_at : true))
        .map((f) => ({ id: f.id, key: f.key, folder_id: f.folder_id }));
    }
    const soft = /^UPDATE files SET deleted_at = \?1 WHERE id IN \(([^)]*)\) AND deleted_at IS NULL/.exec(sql);
    if (soft) {
      const ts = Number(binds[0]);
      const ids = binds.slice(1).map(String);
      for (const f of this.files) if (ids.includes(f.id) && !f.deleted_at) f.deleted_at = ts;
      return null;
    }
    if (/^UPDATE files SET deleted_at = NULL WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      for (const f of this.files) if (ids.includes(f.id)) f.deleted_at = null;
      return null;
    }
    if (/^UPDATE files SET folder_id = NULL WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      for (const f of this.files) if (ids.includes(f.id)) f.folder_id = null;
      return null;
    }
    if (/^SELECT id FROM folders WHERE id = \?1/.test(sql)) {
      return this.folders.find((f) => f.id === String(binds[0])) ?? null;
    }
    if (/AS files,.*AS subfolders/.test(sql)) {
      return {
        files: this.files.filter((f) => f.folder_id === String(binds[0]) && !f.deleted_at).length,
        subfolders: 0,
      };
    }
    if (/^DELETE FROM folders WHERE id = \?1/.test(sql)) {
      this.folders = this.folders.filter((f) => f.id !== String(binds[0]));
      return null;
    }
    if (/^SELECT id FROM folders WHERE id IN/.test(sql)) {
      return binds.map(String).filter((id) => this.folders.some((f) => f.id === id)).map((id) => ({ id }));
    }
    if (/^DELETE FROM shares WHERE file_id IN/.test(sql)) {
      const ids = binds.map(String);
      this.shares = this.shares.filter((s) => !ids.includes(s.file_id));
      return null;
    }
    if (/^DELETE FROM direct_links WHERE file_id IN/.test(sql)) {
      const ids = binds.map(String);
      this.directLinks = this.directLinks.filter((d) => !ids.includes(d.file_id));
      return null;
    }
    if (/^DELETE FROM download_logs WHERE file_id IN/.test(sql)) {
      this.deletedLogs++;
      return null;
    }
    if (/^DELETE FROM files WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      this.files = this.files.filter((f) => !ids.includes(f.id));
      return null;
    }
    if (/^SELECT id FROM files WHERE deleted_at IS NOT NULL/.test(sql)) {
      return this.files.filter((f) => f.deleted_at).map((f) => ({ id: f.id }));
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }
}

function seed(): Db {
  invalidateSettingsCache();
  OBJECT_DELETES.length = 0;
  const db = new Db();
  db.folders = [{ id: "d1" }];
  db.files = [
    { id: "f1", key: "files/f1", name: "a.txt", size: 100, mime: "text/plain", folder_id: "d1", uploaded_at: 1, deleted_at: null },
    { id: "f2", key: "files/f2", name: "b.txt", size: 200, mime: "text/plain", folder_id: null, uploaded_at: 2, deleted_at: null },
  ];
  db.shares = [
    { id: "s1", file_id: "f1", download_count: 0, revoked: 0, is_market: 1 },
    { id: "s2", file_id: "f2", download_count: 0, revoked: 0, is_market: 1 },
  ];
  db.directLinks = [{ id: "dl1", file_id: "f1" }];
  return db;
}

async function admin(db: Db, path: string, init: { method?: string; body?: unknown } = {}) {
  const env: any = { db, admin: "sekret", r2: r2fake(db) };
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    method: init.method ?? "GET",
    headers: { cookie, "cf-connecting-ip": "203.0.113.1", ...(init.body ? { "content-type": "application/json" } : {}) },
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  const bg: Promise<void>[] = [];
  const res = await handleAdminApi(req, env, { waitUntil: (p: Promise<any>) => void bg.push(p), props: {} } as any, new URL(req.url).pathname);
  await Promise.all(bg);
  return { status: res.status, body: await res.json().catch(() => null) };
}

function r2fake(db: Db) {
  return {
    async get(key: string) {
      return { body: new Uint8Array(10), size: 10, httpEtag: "e", httpMetadata: { contentType: "text/plain" }, key };
    },
    async head(key: string) {
      return { size: 10, httpMetadata: { contentType: "text/plain" }, key };
    },
    async delete(key: string) {
      db.objectDeletes.push(key);
    },
  };
}

async function main() {
  console.log("\n[1] 删除默认进回收站");
  {
    const db = seed();
    const r = await admin(db, "/api/admin/files/f1", { method: "DELETE" });
    check("200 且标记为已回收", r.status === 200 && r.body?.trashed === true, JSON.stringify(r.body));
    check("行还在，只打了 deleted_at", db.files.some((f) => f.id === "f1" && f.deleted_at !== null));
    check("没有删存储对象", db.objectDeletes.length === 0, JSON.stringify(db.objectDeletes));
    check("分享行保留（恢复后链接要能用）", db.shares.some((s) => s.id === "s1"));
    check("直链行保留", db.directLinks.some((d) => d.id === "dl1"));
  }

  console.log("\n[2] 对外读路径必须全部看不见");
  {
    const db = seed();
    await admin(db, "/api/admin/files/f1", { method: "DELETE" });
    const live = await admin(db, "/api/admin/files");
    check("后台默认列表不含回收站条目", (live.body?.files ?? []).every((f: any) => f.id !== "f1"), JSON.stringify(live.body?.files?.map((f: any) => f.id)));
    check("total 也不算它", live.body?.total === 1, String(live.body?.total));
    const trashView = await admin(db, "/api/admin/files?trash=1");
    const rows = trashView.body?.files ?? [];
    check("trash=1 只看得到它", rows.length === 1 && rows[0].id === "f1", JSON.stringify(rows.map((f: any) => f.id)));
    check("回收站视图带回 deleted_at", typeof rows[0]?.deleted_at === "number", JSON.stringify(rows[0]));

    const info = await handleShareInfo(
      new Request("https://pan.test/s/s1/info", { headers: { "cf-connecting-ip": "203.0.113.5" } }),
      { db, admin: "sekret", r2: r2fake(db) } as any,
      "s1"
    );
    check("它的分享页 404", info.status === 404, String(info.status));

    const market = await queryMarket({ db, admin: "sekret" } as any, parseMarketParams(new URL("https://pan.test/api/market").searchParams));
    check("市场里不再出现", market.items.every((i: any) => i.share_id !== "s1"), JSON.stringify(market.items.map((i: any) => i.share_id)));
    check("市场 total 同步变小", market.total === 1, String(market.total));
  }

  console.log("\n[3] 统计口径");
  {
    const db = seed();
    const before = (await admin(db, "/api/admin/stats")).body;
    await admin(db, "/api/admin/files/f1", { method: "DELETE" });
    const after = (await admin(db, "/api/admin/stats")).body;
    check("counts.files 排除回收站", before.counts.files === 2 && after.counts.files === 1, JSON.stringify([before.counts, after.counts]));
    check("counts.trash_files 记它", after.counts.trash_files === 1, String(after.counts.trash_files));
    check("storage.bytes 仍含回收站（对象还占着 R2）", before.storage.bytes === 300 && after.storage.bytes === 300, JSON.stringify(after.storage));
    check("storage.trash_bytes 报出可回收体积", after.storage.trash_bytes === 100, String(after.storage.trash_bytes));
  }

  console.log("\n[4] 恢复");
  {
    const db = seed();
    await admin(db, "/api/admin/files/f1", { method: "DELETE" });
    const r = await admin(db, "/api/admin/files/batch-restore", { method: "POST", body: { ids: ["f1"] } });
    check("200 且恢复一条", r.status === 200 && r.body?.restored === 1, JSON.stringify(r.body));
    check("deleted_at 清空", db.files.find((f) => f.id === "f1")?.deleted_at === null);
    check("原目录还在就不动 folder_id", db.files.find((f) => f.id === "f1")?.folder_id === "d1");
    const info = await handleShareInfo(
      new Request("https://pan.test/s/s1/info", { headers: { "cf-connecting-ip": "203.0.113.5" } }),
      { db, admin: "sekret", r2: r2fake(db) } as any,
      "s1"
    );
    check("分享页复活", info.status === 200, String(info.status));

    // 目录已删的情况下恢复 → 退回根目录，不留幽灵引用
    const db2 = seed();
    await admin(db2, "/api/admin/files/f1", { method: "DELETE" });
    db2.folders = [];
    const r2 = await admin(db2, "/api/admin/files/batch-restore", { method: "POST", body: { ids: ["f1"] } });
    check("目录没了也能恢复", r2.body?.restored === 1 && r2.body?.moved_to_root === 1, JSON.stringify(r2.body));
    check("恢复后挂在根目录", db2.files.find((f) => f.id === "f1")?.folder_id === null);

    const nothing = await admin(seed(), "/api/admin/files/batch-restore", { method: "POST", body: { ids: ["f1"] } });
    check("没进回收站的恢复 → 404", nothing.status === 404, String(nothing.status));
  }

  console.log("\n[5] 彻底删除");
  {
    const db = seed();
    await admin(db, "/api/admin/files/f1", { method: "DELETE" });
    const r = await admin(db, "/api/admin/trash/cleanup", { method: "POST", body: { ids: ["f1"] } });
    check("purged=1", r.status === 200 && r.body?.purged === 1, JSON.stringify(r.body));
    check("行没了", !db.files.some((f) => f.id === "f1"));
    check("分享与直链级联清掉", !db.shares.some((s) => s.id === "s1") && !db.directLinks.some((d) => d.id === "dl1"));
    check("下载记录也清了", db.deletedLogs === 1, String(db.deletedLogs));
  }
  {
    const db = seed();
    const r = await admin(db, "/api/admin/files/batch-delete", { method: "POST", body: { ids: ["f2"], mode: "purge" } });
    check("批量 mode=purge 直接彻底删", r.status === 200 && r.body?.purged === 1 && r.body?.trashed === 0, JSON.stringify(r.body));
    check("彻底删要动对象", db.objectDeletes.includes("files/f2"), JSON.stringify(db.objectDeletes));
  }
  {
    const db = seed();
    db.settings.trash_retention_days = "0";
    const r = await admin(db, "/api/admin/files/f1", { method: "DELETE" });
    check("保留期 0 = 关闭回收站", r.status === 200 && r.body?.trashed === false, JSON.stringify(r.body));
    check("此时删除即物理删", !db.files.some((f) => f.id === "f1"));
  }

  console.log("\n[6] 目录判空把回收站当不存在");
  {
    const db = seed(); // f1 在 d1 里
    await admin(db, "/api/admin/files/f1", { method: "DELETE" });
    const del = await admin(db, "/api/admin/folders/d1", { method: "DELETE" });
    check("只剩回收站条目的目录可以删", del.status === 200, JSON.stringify(del.body));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
