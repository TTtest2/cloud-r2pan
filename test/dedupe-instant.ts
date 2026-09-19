/**
 * 内容去重与秒传测试
 *
 * 这里守的是三条会丢数据的红线：
 *   1. 指纹必须带方案前缀（sha256: / etag:），不同方案绝不能互相命中
 *   2. 去重后同一个 key 有多行引用 —— 只删一份引用时**不许**删对象
 *   3. 配额必须按 key 去重统计，否则同一份字节被数好几遍
 *
 * 运行：
 *   npx esbuild test/dedupe-instant.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/dedupe.mjs
 *   node .dev/dedupe.mjs
 */
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import { invalidateSettingsCache } from "../src/settings";
import { usedStorageBytes } from "../src/limits";
import { etagFp, normalizeSha, shaFp } from "../src/dedupe";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const MB = 1024 ** 2;
const ADMIN = "sekret";
const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const KNOWN_LENGTH_ERROR = "Provided readable stream must have a known length";

/** storage.ts 缓存 provider，绑第一次见到的 r2 → 记录必须放全局 */
const putLog: { key: string; etag: string }[] = [];
const deletedKeys: string[] = [];
/** 内容指纹 → etag：同一段字节第二次写入时给出同一个 etag，模拟真实 MD5 */
const etagByContent = new Map<string, string>();
let expectedBody: unknown = null;
let nextContent = "";

const r2: any = {
  async put(key: string, body: any) {
    if (body !== expectedBody && !(body instanceof Uint8Array)) throw new Error(KNOWN_LENGTH_ERROR);
    const etag = etagByContent.get(nextContent) ?? `md5-${etagByContent.size + 1}`;
    etagByContent.set(nextContent, etag);
    putLog.push({ key, etag });
    return { size: nextContent === "big" ? 600 * 1024 : 10, httpEtag: etag };
  },
  async get(key: string) {
    return { body: new Uint8Array(8), size: 8, httpEtag: "e", httpMetadata: { contentType: "text/plain" }, key };
  },
  async head(key: string) {
    return { size: 8, httpMetadata: { contentType: "text/plain" }, key };
  },
  async delete(key: string) {
    deletedKeys.push(key);
  },
};

interface Row {
  id: string; key: string; name: string; size: number; mime: string;
  folder_id: string | null; deleted_at: number | null; sha256: string | null; etag: string | null;
}

class Db {
  files: Row[] = [];
  constructor(public settingsRows: { key: string; value: string }[]) {}

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
        return self.dispatch(norm, binds, "first");
      },
      async all() {
        const r = self.dispatch(norm, binds, "all");
        return { results: Array.isArray(r) ? r : [], success: true, meta: {} };
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

  private dispatch(sql: string, binds: any[], mode: string): any {
    if (/sqlite_master/.test(sql)) return { name: "settings", sql: "x" };
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "9999" };
    if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^CREATE INDEX|^DROP TABLE/.test(sql)) throw new Error("冷启动不该跑 DDL: " + sql);
    if (/^SELECT key, value FROM settings/.test(sql)) return this.settingsRows;
    if (/^SELECT COALESCE\(SUM\(s\), 0\) AS bytes FROM \(SELECT MIN\(size\) AS s FROM files GROUP BY key\)/.test(sql)) {
      const seen = new Set<string>();
      return { bytes: this.files.filter((f) => !seen.has(f.key) && seen.add(f.key)).reduce((a, b) => a + b.size, 0) };
    }
    if (/^SELECT id FROM folders WHERE id = \?1/.test(sql)) return { id: String(binds[0]) };
    if (/^INSERT INTO files\(/.test(sql)) {
      const [id, key, name, size, mime, uploaded_at, folder_id, sha256, etag] = binds as any[];
      this.files.push({ id, key, name, size, mime, folder_id: folder_id ?? null, deleted_at: null, sha256: sha256 ?? null, etag: etag ?? null });
      return null;
    }
    /* 秒传查询：按 sha256（体积可选） */
    if (/^SELECT id, key, name, size, mime, sha256, etag FROM files WHERE sha256 = \?1 AND size = \?2/.test(sql)) {
      return this.files.find((f) => f.sha256 === String(binds[0]) && f.size === Number(binds[1]) && !f.deleted_at) ?? null;
    }
    if (/^SELECT id, key, name, size, mime, sha256, etag FROM files WHERE sha256 = \?1 AND deleted_at/.test(sql)) {
      return this.files.find((f) => f.sha256 === String(binds[0]) && !f.deleted_at) ?? null;
    }
    /* 写后去重查询：同 etag 同体积的别人那行 */
    if (/^SELECT id, key, name, size, mime, sha256, etag FROM files WHERE etag = \?1 AND size = \?2 AND id != \?3/.test(sql)) {
      return this.files.find((f) => f.etag === String(binds[0]) && f.size === Number(binds[1]) && f.id !== String(binds[2]) && !f.deleted_at) ?? null;
    }
    if (/^UPDATE files SET key = \?1 WHERE id = \?2/.test(sql)) {
      const row = this.files.find((f) => f.id === String(binds[1]));
      if (row) row.key = String(binds[0]);
      return null;
    }
    /* 引用计数 */
    if (/^SELECT key, COUNT\(\*\) AS c FROM files WHERE key IN/.test(sql)) {
      return binds.map(String)
        .map((k) => ({ key: k, c: this.files.filter((f) => f.key === k).length }))
        .filter((r) => r.c > 0);
    }
    if (/^SELECT id, key, folder_id FROM files WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      return this.files.filter((f) => ids.includes(f.id)).map((f) => ({ id: f.id, key: f.key, folder_id: f.folder_id }));
    }
    if (/^UPDATE files SET deleted_at = \?1 WHERE id IN/.test(sql)) {
      const ts = Number(binds[0]);
      for (const f of this.files) if (binds.slice(1).map(String).includes(f.id) && !f.deleted_at) f.deleted_at = ts;
      return null;
    }
    if (/^DELETE FROM (shares|direct_links|download_logs) WHERE file_id IN/.test(sql)) return null;
    if (/^DELETE FROM files WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      this.files = this.files.filter((f) => !ids.includes(f.id));
      return null;
    }
    if (/^SELECT COUNT\(\*\) AS c FROM files WHERE deleted_at/.test(sql)) {
      const wantTrash = /IS NOT NULL/.test(sql);
      return { c: this.files.filter((f) => (wantTrash ? !!f.deleted_at : !f.deleted_at)).length };
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }
}

function rows(maxMb = 100, quotaMb = 0) {
  return [
    { key: "admin_ips", value: "" },
    { key: "max_upload_mb", value: String(maxMb) },
    { key: "storage_quota_mb", value: String(quotaMb) },
  ];
}

async function call(db: Db, path: string, init: { method?: string; body?: BodyInit | null; headers?: Record<string, string> } = {}, maxMb = 100) {
  invalidateSettingsCache();
  db.settingsRows = rows(maxMb);
  const env: any = { db, admin: ADMIN, r2 };
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    method: init.method ?? "GET",
    headers: { cookie, "cf-connecting-ip": "203.0.113.1", ...init.headers },
    body: init.body,
    ...(init.body ? { duplex: "half" } : {}),
  } as any);
  const bg: Promise<void>[] = [];
  expectedBody = req.body; // 处理函数必须把 req.body 原样交给存储层
  const res = await handleAdminApi(req, env, { waitUntil: (p: Promise<any>) => void bg.push(p), props: {} } as any, new URL(req.url).pathname);
  await Promise.all(bg);
  return { status: res.status, body: await res.json().catch(() => null) };
}

/** 上传一段内容（content 只是用来让假 r2 产生可预测的 etag） */
async function upload(db: Db, name: string, content: string, sha?: string, maxMb = 100) {
  invalidateSettingsCache();
  nextContent = content;
  return call(db, "/api/admin/upload", {
    method: "POST",
    headers: {
      "x-file-name": encodeURIComponent(name),
      "content-type": "text/plain",
      ...(sha ? { "x-content-sha256": sha } : {}),
    },
    body: new Uint8Array(content === "big" ? 600 * 1024 : 10),
  }, maxMb);
}

function fresh(): Db {
  return new Db(rows());
}

async function main() {
  console.log("\n[1] 指纹格式与前缀隔离");
  {
    check("64 位十六进制才认", normalizeSha(SHA_A.toUpperCase()) === SHA_A);
    check("带空白的合法值可修剪", normalizeSha("  " + SHA_B + "  ") === SHA_B);
    check("短串/非十六进制一律拒绝", normalizeSha("abc") === null && normalizeSha("z".repeat(64)) === null && normalizeSha(null) === null);
    check("两种方案前缀不会互撞", shaFp(SHA_A) !== etagFp(SHA_A) && shaFp(SHA_A).startsWith("sha256:") && etagFp("x").startsWith("etag:"));
    check("etag 引号被清掉", etagFp('"abc-"').endsWith("abc-") && !etagFp('"abc-"').includes('"'));
  }

  console.log("\n[2] 写后去重（同内容第二次上传不占两份）");
  {
    const db = fresh();
    const first = await upload(db, "one.txt", "same", SHA_A);
    check("第一次正常入库", first.status === 201 && db.files.length === 1, JSON.stringify(first.body));
    check("行里带上 sha256 与 etag 指纹", db.files[0].sha256 === SHA_A && !!db.files[0].etag, JSON.stringify(db.files[0]));
    const second = await upload(db, "two.txt", "same", SHA_A);
    check("第二次回报已去重", second.status === 201 && second.body?.deduped === true, JSON.stringify(second.body));
    check("两行指向同一个 key", db.files.length === 2 && db.files[0].key === db.files[1].key, JSON.stringify(db.files.map((f) => [f.id, f.key])));
    check("多余的第二次写入被删掉", deletedKeys.includes(second.body?.id ? "files/" + db.files[1].id : ""), JSON.stringify({ deletedKeys, put: putLog.map((p) => p.key) }));
    const used = await usedStorageBytes({ db, admin: ADMIN } as any);
    check("配额只算一份字节", used === 10, String(used));
  }

  console.log("\n[3] 秒传：一个字节都不传");
  {
    const db = fresh();
    await upload(db, "one.txt", "same", SHA_A);
    const hit = await call(db, "/api/admin/upload/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sha256: SHA_A, size: 10 }),
    });
    check("check 命中已有内容", hit.status === 200 && hit.body?.exists === true && hit.body?.size === 10, JSON.stringify(hit.body));
    const miss = await call(db, "/api/admin/upload/check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sha256: SHA_B, size: 10 }) });
    check("另一种内容不命中", miss.body?.exists === false);
    const bad = await call(db, "/api/admin/upload/check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sha256: "../etc/passwd" }) });
    check("非法 sha256 直接 400", bad.status === 400, String(bad.status));
    const before = putLog.length;
    const claim = await call(db, "/api/admin/upload/claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sha256: SHA_A, name: "别名.txt", folder_id: null }),
    });
    check("claim 成功且没写任何字节", claim.status === 201 && putLog.length === before, JSON.stringify({ st: claim.status, puts: putLog.length - before }));
    check("新行复用已有 key 并继承指纹", db.files.length === 2 && db.files[1].key === db.files[0].key && db.files[1].sha256 === SHA_A, JSON.stringify(db.files[1]));
    check("claim 也算 deduped", claim.body?.deduped === true);
    const ghost = await call(db, "/api/admin/upload/claim", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sha256: SHA_B, name: "x.txt" }) });
    check("没见过的内容不能凭空 claim", ghost.status === 404, String(ghost.status));
    const tooBig = await call(db, "/api/admin/upload/claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sha256: "c".repeat(64), name: "x.txt" }),
    });
    check("未知指纹同样是 404", tooBig.status === 404, String(tooBig.status));
  }

  console.log("\n[4] 上限不能靠秒传绕过");
  {
    const db = fresh();
    // 模拟"以前上限还很大时存下的 5 MB 内容"
    db.files.push({ id: "old1", key: "files/old1", name: "old.bin", size: 5 * MB, mime: "application/octet-stream", folder_id: null, deleted_at: null, sha256: SHA_A, etag: etagFp("old-etag") });
    const r = await call(db, "/api/admin/upload/claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sha256: SHA_A, name: "again.bin" }),
    }, 1); // 现在单文件上限只有 1 MB
    check("复用的对象超过新上限 → 413", r.status === 413 && r.body?.error === "too_large", JSON.stringify(r.body));
    check("被拒时不多写一行", db.files.length === 1, JSON.stringify(db.files.map((f) => f.id)));
    const ok = await call(db, "/api/admin/upload/claim", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sha256: SHA_A, name: "again.bin" }),
    }, 10);
    check("上限放宽后同一份内容可以秒传", ok.status === 201 && db.files.length === 2, JSON.stringify(ok.body));
  }

  console.log("\n[5] 引用计数：删一份不许碰另一份的字节");
  {
    const db = fresh();
    await upload(db, "one.txt", "same", SHA_A);
    const two = await upload(db, "two.txt", "same", SHA_A);
    const [a, b] = db.files;
    check("前提：两行同 key", a.key === b.key, JSON.stringify([a.key, b.key]));
    deletedKeys.length = 0;
    const p1 = await call(db, "/api/admin/files/" + a.id + "?purge=1", { method: "DELETE" });
    check("彻底删除第一行", p1.status === 200 && db.files.length === 1, JSON.stringify(p1.body));
    check("对象仍在（还有人在用）", deletedKeys.length === 0, JSON.stringify(deletedKeys));
    const p2 = await call(db, "/api/admin/files/" + db.files[0].id + "?purge=1", { method: "DELETE" });
    check("最后一行删掉时才删对象", p2.status === 200 && deletedKeys.includes(a.key), JSON.stringify({ deletedKeys, n: db.files.length }));
    void two;
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
