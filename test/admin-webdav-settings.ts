/**
 * WebDAV 设置端点测试 —— 此前 webdav_enabled / webdav_username / webdav_password_hash
 * 三个设置只有直接改 D1 才写进去（页面上写"在管理后台设置"其实是假的），
 * 这里把写入路径钉住：只存拉伸后的哈希、口令强度有下限、用户名有字符集限制。
 *
 * 运行：
 *   npx esbuild test/admin-webdav-settings.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/admin-webdav-settings.mjs
 *   node .dev/admin-webdav-settings.mjs
 */
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import { verifyWebDAVPassword } from "../src/crypto";
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

class FakeDb {
  settings = new Map<string, string>();
  upserts: { key: string; value: string }[] = [];

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
        const r = self.dispatch(norm, binds, "all");
        return { results: Array.isArray(r) ? r : [] };
      },
      async run() {
        self.dispatch(norm, binds, "run");
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
    if (/sqlite_master/.test(sql)) {
      return /name='settings'/.test(sql) ? { name: "settings" } : { sql: NEW_TABLE_SQL };
    }
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "999" };
    if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^DROP TABLE|^CREATE (UNIQUE )?INDEX/.test(sql)) {
      throw new Error("冷启动不该再跑 DDL: " + sql);
    }
    if (/^SELECT key, value FROM settings/.test(sql)) {
      if (mode !== "all") return null;
      return [...this.settings.entries()].map(([key, value]) => ({ key, value }));
    }
    if (/^SELECT COUNT\(\*\) AS c FROM oauth_providers/.test(sql)) return { c: 0 };
    if (/FROM oauth_providers/.test(sql)) return mode === "all" ? [] : null;
    if (/^INSERT INTO settings\(key, value\)/.test(sql)) {
      const [key, value] = binds as string[];
      this.settings.set(key, value);
      this.upserts.push({ key, value });
      return null;
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }
}

async function call(db: FakeDb, method: string, path: string, body?: unknown) {
  const env: any = { db, admin: ADMIN_KEY };
  const cookie = (await createSession(env)).split(";")[0];
  invalidateSettingsCache();
  const req = new Request("https://pan.test" + path, {
    method,
    headers: { cookie, "cf-connecting-ip": "203.0.113.1", ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const res = await handleAdminApi(req, env, { waitUntil() {}, props: {} } as any, new URL(req.url).pathname);
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function main() {
  console.log("\n[1] 开启 WebDAV 并设置凭据");
  {
    const db = new FakeDb();
    const r = await call(db, "PUT", "/api/admin/settings", {
      webdav_enabled: true,
      webdav_username: "mounter",
      webdav_password: "a-good-long-pass",
    });
    check("保存成功", r.status === 200, String(r.status) + JSON.stringify(r.body));
    check("开关写入", db.settings.get("webdav_enabled") === "1");
    check("用户名写入", db.settings.get("webdav_username") === "mounter");
    const hash = db.settings.get("webdav_password_hash") ?? "";
    check("口令以 PBKDF2 哈希存储", hash.startsWith("pbkdf2$50000$"), hash.slice(0, 30));
    check("绝不存明文", !JSON.stringify([...db.settings.entries()]).includes("a-good-long-pass"));
    check("哈希能验回原口令", (await verifyWebDAVPassword(hash, "a-good-long-pass")).ok === true);
    check("错误口令验不过", (await verifyWebDAVPassword(hash, "guess")).ok === false);

    const get = await call(db, "GET", "/api/admin/settings");
    check("读取接口只报状态", (get.body as any)?.webdav_enabled === true && (get.body as any).webdav_has_password === true);
    check("读取接口不下发哈希", !JSON.stringify(get.body).includes("pbkdf2$"), JSON.stringify(get.body).slice(0, 160));
  }

  console.log("\n[2] 输入校验");
  {
    const db = new FakeDb();
    const short = await call(db, "PUT", "/api/admin/settings", { webdav_password: "tiny" });
    check("口令太短 400", short.status === 400, String(short.status));
    check("太短时不写哈希", !db.upserts.some((u) => u.key === "webdav_password_hash"));

    const badUser = await call(db, "PUT", "/api/admin/settings", { webdav_username: "bad name/../" });
    check("用户名含非法字符 400", badUser.status === 400, String(badUser.status));
    check("非法用户名不写库", !db.upserts.some((u) => u.key === "webdav_username"));

    const cleared = await call(db, "PUT", "/api/admin/settings", { webdav_password: "" });
    check("空串清除口令", cleared.status === 200 && db.settings.get("webdav_password_hash") === "", String(cleared.status));

    const keep = await call(db, "PUT", "/api/admin/settings", { webdav_enabled: false });
    const hashWrites = db.upserts.filter((u) => u.key === "webdav_password_hash").length;
    check("不传口令字段就不动口令（只写过清除那一次）", keep.status === 200 && hashWrites === 1, String(hashWrites));
    check("关开关生效", db.settings.get("webdav_enabled") === "0");
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
