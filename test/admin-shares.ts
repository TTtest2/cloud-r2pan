/**
 * 分享列表与口令查看测试 —— 列表不再批量下发口令明文，只看单条时才解密。
 *
 * 运行：
 *   npx esbuild test/admin-shares.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/admin-shares.mjs
 *   node .dev/admin-shares.mjs
 */
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import { encryptSecret } from "../src/crypto";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const ADMIN_KEY = "sekret";
const NEW_TABLE_SQL =
  "CREATE TABLE \"folders\"(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)";

interface ShareRow {
  id: string;
  file_id: string;
  created_at: number;
  expires_at: number | null;
  max_downloads: number | null;
  download_count: number;
  revoked: number;
  password_hash: string | null;
  password_cipher: string | null;
  download_name: string | null;
  direct_id: string | null;
  is_market: number;
  market_views: number;
  market_title: string | null;
  market_desc: string | null;
}

class FakeDb {
  shares: ShareRow[] = [];
  queries: string[] = [];

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    let binds: unknown[] = [];
    const self = this;
    const stmt: any = {
      bind(...vals: unknown[]) {
        binds = vals;
        return stmt;
      },
      async first() {
        return self.dispatch(norm, binds, "first");
      },
      async all() {
        return { results: self.dispatch(norm, binds, "all") ?? [] };
      },
      async run() {
        return { success: true, meta: { changes: 1 } };
      },
    };
    return stmt;
  }

  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }

  private dispatch(sql: string, binds: unknown[], mode: string): any {
    this.queries.push(sql);
    if (/sqlite_master/.test(sql)) {
      return /name='settings'/.test(sql) ? { name: "settings" } : { sql: NEW_TABLE_SQL };
    }
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "999" };
    if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^DROP TABLE|^CREATE (UNIQUE )?INDEX/.test(sql)) {
      throw new Error("冷启动不该再跑 DDL: " + sql);
    }
    if (/^SELECT key, value FROM settings/.test(sql)) {
      return mode === "all" ? [{ key: "admin_ips", value: "" }] : null;
    }
    if (/^SELECT COUNT\(\*\) AS c FROM shares$/.test(sql)) return { c: this.shares.length };
    if (/FROM shares s JOIN files f/.test(sql)) {
      if (mode !== "all") return null;
      const [limit, offset] = binds as number[];
      // 只返回 SQL 真正投影的 s.xxx 列 —— 这样别人把 password_cipher 加回 SELECT 时测试才会红
      const projected = [...sql.matchAll(/\bs\.([a-z_]+)/g)].map((m) => m[1]);
      return this.shares.slice(offset, offset + limit).map((s) => {
        const row: Record<string, unknown> = { file_name: "f-" + s.id, file_size: 10, file_mime: "text/plain" };
        for (const col of projected) {
          if (col in s) row[col] = (s as any)[col];
        }
        return row;
      });
    }
    if (/^SELECT password_cipher FROM shares WHERE id = \?1/.test(sql)) {
      const row = this.shares.find((s) => s.id === binds[0]);
      if (!row) return null;
      return { password_cipher: row.password_cipher };
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }
}

async function call(db: FakeDb, path: string) {
  const env: any = { db, admin: ADMIN_KEY };
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    method: "GET",
    headers: { cookie, "cf-connecting-ip": "203.0.113.1" },
  });
  const res = await handleAdminApi(req, env, { waitUntil() {}, props: {} } as any, new URL(req.url).pathname);
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function seedDb(count = 150) {
  invalidateSettingsCache();
  const db = new FakeDb();
  const secretPw = "s3cr3t-pw";
  const cipher = await encryptSecret(secretPw, ADMIN_KEY);
  for (let i = 0; i < count; i++) {
    const protectedOne = i === 0;
    db.shares.push({
      id: "sh" + i,
      file_id: "fl" + i,
      created_at: 1_700_000_000_000 - i,
      expires_at: null,
      max_downloads: null,
      download_count: 0,
      revoked: 0,
      password_hash: protectedOne ? "salt:hash" : null,
      password_cipher: protectedOne ? cipher : null,
      download_name: null,
      direct_id: "dl" + i, // 都有直链，避开列表里的补建分支
      is_market: 0,
      market_views: 0,
      market_title: null,
      market_desc: null,
    });
  }
  return { db, secretPw };
}

async function main() {
  console.log("\n[1] 列表分页且不再下发口令");
  {
    const { db } = await seedDb(150);
    const r = await call(db, "/api/admin/shares");
    const body: any = r.body;
    check("200", r.status === 200, String(r.status));
    check("默认一页 100 条", body?.shares?.length === 100, String(body?.shares?.length));
    check("回报 total", body?.total === 150, String(body?.total));
    check("没有任何一行带 password_plain", !JSON.stringify(body).includes("password_plain"), JSON.stringify(body).slice(0, 200));
    check("没有任何一行带 password_hash/cipher/plain",
      !/password_(hash|cipher|plain)/.test(JSON.stringify(body)),
      JSON.stringify(body).slice(0, 200));
    check("has_password 仍然正确", body.shares[0].has_password === true && body.shares[1].has_password === false);
    check("status 计算正确", body.shares[0].status === "active", body.shares[0].status);
    check("url 与直链都在", body.shares[0].url === "/s/sh0" && body.shares[0].direct_url === "/d/dl0");

    const second = await call(db, "/api/admin/shares?offset=100");
    check("第二页 50 条", (second.body as any)?.shares?.length === 50, String((second.body as any)?.shares?.length));
    check("第二页 offset 回显", (second.body as any)?.offset === 100);
    const clamped = await call(db, "/api/admin/shares?limit=99999");
    check("limit 夹到 500", (clamped.body as any).limit === 500, String((clamped.body as any).limit));
    const tiny = await call(db, "/api/admin/shares?limit=0&offset=-5");
    const tl = (tiny.body as any);
    check("非法分页参数被夹进合法区间", tl.limit >= 1 && tl.limit <= 500 && tl.offset === 0, JSON.stringify({ l: tl.limit, o: tl.offset }));
    check("列表查询带 LIMIT/OFFSET", db.queries.some((q) => /LIMIT \?1 OFFSET \?2/.test(q)));
    check("列表 SQL 根本不选 password_cipher", !db.queries.some((q) => /^SELECT .*password_cipher.*JOIN files/.test(q)));
  }

  console.log("\n[2] 单条查看口令");
  {
    const { db, secretPw } = await seedDb(3);
    const got = await call(db, "/api/admin/shares/sh0/password");
    check("200", got.status === 200, String(got.status));
    check("解密回原口令", (got.body as any)?.password === secretPw, JSON.stringify(got.body));
    const none = await call(db, "/api/admin/shares/sh1/password");
    check("没设口令返回 null", (none.body as any)?.password === null, JSON.stringify(none.body));
    const ghost = await call(db, "/api/admin/shares/nope/password");
    check("未知分享 404", ghost.status === 404, String(ghost.status));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
