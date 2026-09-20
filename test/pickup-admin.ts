/**
 * 后台"投递箱"端点测试 —— 这一组的存在理由其实很具体：promote 那条 SQL 的占位符
 * 是算出来的（folder_id 要排在 id 列表之后），正是软删除那次线上 500 的同一类错误。
 * 所以假库对每条语句都校验"占位符个数 == 绑定个数"，不匹配直接抛。
 *
 * 覆盖：列表与总量统计、取件码单条解密（不随列表下发）、入库（文件挪出投递箱 +
 * 投递行连带码一起消失）、销毁（连对象一起清），以及权限边界（非 drop 行动不了）。
 *
 * 运行：
 *   npx esbuild test/pickup-admin.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/pickup-admin.mjs
 *   node .dev/pickup-admin.mjs
 */
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import { encryptSecret } from "../src/crypto";
import { invalidateSettingsCache } from "../src/settings";
import type { Env } from "../src/types";

let failures = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const ADMIN = "pickup-admin-secret";
const CODE = "ab3dk9fq";

type Row = Record<string, any>;

class Db {
  files: Row[] = [];
  shares: Row[] = [];
  folders: Row[] = [];
  sqlLog: string[] = [];
  deletedKeys: string[] = [];
  constructor(public settings: Record<string, string> = {}) {}

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    const self = this;
    const stmt: any = {
      _binds: [] as any[],
      bind(...b: any[]) { stmt._binds = b; return stmt; },
      async first() { return self.exec(norm, stmt._binds, "first"); },
      async all() {
        const r = self.exec(norm, stmt._binds, "all");
        return Array.isArray(r) ? { results: r, success: true, meta: {} } : { results: [], success: true, meta: {} };
      },
      async run() { self.exec(norm, stmt._binds, "run"); return { success: true, meta: { changes: 1 }, results: [] }; },
    };
    return stmt;
  }
  async batch(stmts: any[]) { for (const s of stmts) await s.run(); return []; }

  private exec(sql: string, binds: any[], mode: string): any {
    const numbered = new Set([...sql.matchAll(/\?(\d+)/g)].map((m) => Number(m[1])));
    if (numbered.size && numbered.size !== binds.length)
      throw new Error(`占位符与绑定不匹配（${numbered.size} vs ${binds.length}）: ${sql}`);
    this.sqlLog.push(sql);

    if (/sqlite_master/.test(sql)) return mode === "all" ? [] : { name: "settings", sql: "CREATE TABLE settings" };
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "9999" };
    if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path IS NOT NULL/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^CREATE INDEX|^DROP TABLE/.test(sql)) throw new Error("冷启动不该跑 DDL: " + sql);
    if (/^SELECT key, value FROM settings/.test(sql)) {
      return Object.entries({ pickup_total_quota_mb: "1024", turnstile_mode: "off", max_upload_mb: "100", trash_retention_days: "7", ...this.settings })
        .map(([key, value]) => ({ key, value }));
    }
    if (/^SELECT id, name, parent_id, created_at FROM folders/.test(sql)) return this.folders.map((f) => ({ ...f }));
    if (/^SELECT id FROM folders WHERE id = \?1/.test(sql)) return this.folders.find((f) => f.id === String(binds[0])) ? { id: binds[0] } : null;

    /* 列表 */
    if (/^SELECT sh\.id AS share_id, f\.id AS file_id/.test(sql)) {
      return this.shares.filter((s) => s.origin === "drop")
        .map((s) => {
          const f = this.files.find((x) => x.id === s.file_id && x.deleted_at == null);
          return f ? { share_id: s.id, file_id: f.id, name: f.name, size: f.size, mime: f.mime, key: f.key,
            created_at: s.created_at, expires_at: s.expires_at, origin_ip: s.origin_ip, download_count: s.download_count,
            pickup_claims: s.pickup_claims, revoked: s.revoked, one_shot: s.max_downloads === 1 ? 1 : 0 } : null;
        })
        .filter(Boolean);
    }
    if (/^SELECT COUNT\(\*\) AS c, COALESCE\(SUM\(size\), 0\) AS bytes FROM \( SELECT DISTINCT f\.key/.test(sql)) {
      const live = this.shares.filter((s) => s.origin === "drop").map((s) => this.files.find((f) => f.id === s.file_id && f.deleted_at == null)).filter(Boolean) as Row[];
      const byKey = new Map<string, number>();
      for (const f of live) byKey.set(f.key, f.size);
      let bytes = 0;
      for (const v of byKey.values()) bytes += v;
      return { c: live.length, bytes };
    }
    /* 单条回看码 */
    if (/^SELECT pickup_cipher FROM shares WHERE id = \?1 AND origin = 'drop'/.test(sql)) {
      const s = this.shares.find((x) => x.id === String(binds[0]) && x.origin === "drop");
      return s ? { pickup_cipher: s.pickup_cipher } : null;
    }
    /* 入库/销毁的前置查询：只认 drop 行 */
    if (/^SELECT f\.id FROM shares sh JOIN files f ON f\.id = sh\.file_id WHERE sh\.origin = 'drop' AND f\.id IN/.test(sql)) {
      const ids = binds.map(String);
      return this.shares.filter((s) => s.origin === "drop" && ids.includes(String(s.file_id)))
        .map((s) => ({ id: s.file_id }));
    }
    if (/^UPDATE files SET folder_id = \?\d+ WHERE id IN/.test(sql)) {
      const target = binds[binds.length - 1];
      const ids = binds.slice(0, -1).map(String);
      for (const f of this.files) if (ids.includes(f.id)) f.folder_id = target;
      return null;
    }
    if (/^DELETE FROM shares WHERE origin = 'drop' AND file_id IN/.test(sql)) {
      const ids = binds.map(String);
      this.shares = this.shares.filter((s) => !(s.origin === "drop" && ids.includes(String(s.file_id))));
      return null;
    }
    /* purgeFiles 走的那几条 */
    if (/^SELECT id, key, folder_id FROM files WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      return this.files.filter((f) => ids.includes(f.id)).map((f) => ({ id: f.id, key: f.key, folder_id: f.folder_id ?? null }));
    }
    if (/^SELECT key, COUNT\(\*\) AS c FROM files WHERE key IN/.test(sql)) {
      return binds.map((k) => ({ key: String(k), c: this.files.filter((f) => f.key === k).length })).filter((r) => r.c > 0);
    }
    if (/^DELETE FROM files WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      this.files = this.files.filter((f) => !ids.includes(f.id));
      return null;
    }
    if (/^DELETE FROM (shares|download_logs|direct_links) WHERE file_id IN/.test(sql)) {
      const ids = binds.map(String);
      if (/shares/.test(sql)) this.shares = this.shares.filter((s) => !ids.includes(String(s.file_id)));
      return null;
    }
    return null;
  }
}

const r2 = {
  async get(key: string) { return { body: new Uint8Array(8), size: 8, httpEtag: "e", httpMetadata: {}, key }; },
  async head(key: string) { return { size: 8, httpMetadata: {}, key }; },
  async delete(key: string) { DELETED.push(key); },
};
const DELETED: string[] = [];

async function admin(db: Db, path: string, init: { method?: string; body?: unknown } = {}) {
  invalidateSettingsCache();
  const env: Env = { db, admin: ADMIN, r2: r2 as any } as any;
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    method: init.method ?? "GET",
    headers: { cookie, "cf-connecting-ip": "203.0.113.9", ...(init.body ? { "content-type": "application/json" } : {}) },
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  const waited: Promise<any>[] = [];
  const res = await handleAdminApi(req, env, { waitUntil: (p: Promise<any>) => void waited.push(Promise.resolve(p)), props: {} } as any, new URL(req.url).pathname);
  await Promise.all(waited);
  return { status: res.status, body: await res.json().catch(() => null) as any };
}

function fixture(): Db {
  const db = new Db();
  db.folders.push({ id: "DROP_DIR", name: "投递箱", parent_id: null, created_at: 1 });
  db.folders.push({ id: "F_DOC", name: "文档", parent_id: null, created_at: 1 });
  db.files.push(
    { id: "f_drop", key: "drops/f_drop", name: "陌生人投的.zip", size: 4096, mime: "application/zip", folder_id: "DROP_DIR", deleted_at: null },
    { id: "f_own", key: "files/f_own", name: "自己的.zip", size: 8192, mime: "application/zip", folder_id: null, deleted_at: null }
  );
  db.shares.push(
    { id: "SH_DROP", file_id: "f_drop", created_at: 1000, expires_at: Date.now() + 86_400_000, max_downloads: null,
      download_count: 0, revoked: 0, origin: "drop", origin_ip: "198.51.100.7", pickup_claims: 2, pickup_cipher: null },
    { id: "SH_OWN", file_id: "f_own", created_at: 1000, expires_at: null, max_downloads: 5,
      download_count: 1, revoked: 0, origin: "admin", origin_ip: null, pickup_claims: 0, pickup_cipher: null }
  );
  return db;
}

async function main() {
  console.log("\n[1] 投递箱列表");
  {
    const db = fixture();
    const r = await admin(db, "/api/admin/pickups");
    check("列表只回投件", r.status === 200 && r.body?.drops?.length === 1 && r.body.drops[0].file_id === "f_drop", JSON.stringify(r.body));
    check("带来源 IP、已取次数与有效期", !!r.body?.drops?.[0]?.origin_ip && r.body.drops[0].pickup_claims === 2 && r.body.drops[0].expires_at > Date.now());
    check("统计给件数/字节/总配额", r.body?.total === 1 && r.body?.bytes === 4096 && r.body?.quota_bytes === 1024 * 1024 ** 2, JSON.stringify({ t: r.body?.total, b: r.body?.bytes, q: r.body?.quota_bytes }));
    check("列表里绝不含明文码", !JSON.stringify(r.body).includes(CODE));
  }

  console.log("\n[2] 单条回看取件码");
  {
    const db = fixture();
    db.shares[0].pickup_cipher = await encryptSecret(CODE, ADMIN);
    const r = await admin(db, "/api/admin/pickups/SH_DROP/code");
    check("点查看才解密，并按分组显示", r.status === 200 && r.body?.code === "ab3d-k9fq", JSON.stringify(r.body));
    const notDrop = await admin(db, "/api/admin/pickups/SH_OWN/code");
    check("普通分享不在这个接口里", notDrop.status === 404, String(notDrop.status));
    const gone = await admin(db, "/api/admin/pickups/SH_NONE/code");
    check("不存在的投件 404", gone.status === 404, String(gone.status));
  }

  console.log("\n[3] 入库：文件归位，码随之失效");
  {
    const db = fixture();
    const bad = await admin(db, "/api/admin/pickups/promote", { method: "POST", body: { ids: ["f_drop"], folder_id: "NOPE" } });
    check("目标文件夹不存在就拒绝", bad.status === 404 && db.files[0].folder_id === "DROP_DIR", JSON.stringify(bad.body));
    const own = await admin(db, "/api/admin/pickups/promote", { method: "POST", body: { ids: ["f_own"], folder_id: "F_DOC" } });
    check("拿它当普通文件入库被拒", own.status === 404 && db.files[1].folder_id === null, String(own.status));
    const ok = await admin(db, "/api/admin/pickups/promote", { method: "POST", body: { ids: ["f_drop"], folder_id: "F_DOC" } });
    check("入库成功并回报码已失效", ok.status === 200 && ok.body?.promoted === 1 && ok.body?.code_revoked === true, JSON.stringify(ok.body));
    check("文件挂进目标目录", db.files[0].folder_id === "F_DOC", JSON.stringify(db.files[0]));
    check("投递行被删（于是按码找不到任何东西）", !db.shares.some((s) => s.id === "SH_DROP"));
    check("自己的分享行不受牵连", db.shares.some((s) => s.id === "SH_OWN"));
  }

  console.log("\n[4] 销毁：连对象一起清");
  {
    const db = fixture();
    DELETED.length = 0;
    const r = await admin(db, "/api/admin/pickups/destroy", { method: "POST", body: { ids: ["f_drop"] } });
    check("销毁回报件数", r.status === 200 && r.body?.destroyed === 1, JSON.stringify(r.body));
    check("行与对象一起没了", !db.files.some((f) => f.id === "f_drop") && DELETED.includes("drops/f_drop"), JSON.stringify(DELETED));
    check("机主自己的文件毫发无伤", db.files.some((f) => f.id === "f_own") && !DELETED.includes("files/f_own"));
    const empty = await admin(db, "/api/admin/pickups/destroy", { method: "POST", body: { ids: [] } });
    check("没选东西时 400", empty.status === 400, String(empty.status));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
