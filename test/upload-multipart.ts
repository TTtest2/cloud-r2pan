/**
 * 分片上传测试 —— 重点是三件容易做错的事：
 *   1. 分片的流必须原样交给存储层（R2/S3 只收"长度已知"的流，包一层计数就全挂）
 *   2. 客户端报的体积一律不算数，合并完用 head() 的真实字节复核，超限要删对象
 *   3. 会话要么合并要么中止，超时未完成必须能被 cron 回收
 *
 * 运行：
 *   npx esbuild test/upload-multipart.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/upload-multipart.mjs
 *   node .dev/upload-multipart.mjs
 */
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import { invalidateSettingsCache } from "../src/settings";
import { CHUNK_SIZE, MAX_PARTS, UPLOAD_TTL_MS } from "../src/uploads";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const MB = 1024 ** 2;
const KNOWN_LENGTH_ERROR =
  "Provided readable stream must have a known length (request/response body or readable half of FixedLengthStream)";

/* ═══════════ 假存储：只认"长度已知"的载体 ═══════════ */

let expectedBody: unknown = null;

const bucket = {
  creates: [] as string[],
  parts: [] as { key: string; n: number; bytes: number }[],
  completes: [] as { key: string; parts: number }[],
  aborts: [] as string[],
  deleted: [] as string[],
  /** 合并后对象体积（可注入，用来模拟"真实体积比声明的大"） */
  sizeOf: new Map<string, number>(),
  reset() {
    this.creates = [];
    this.parts = [];
    this.completes = [];
    this.aborts = [];
    this.deleted = [];
    this.sizeOf = new Map();
  },
};

const r2Fake: any = {
  async createMultipartUpload(key: string) {
    bucket.creates.push(key);
    return { uploadId: "up-" + key, key };
  },
  resumeMultipartUpload(key: string, uploadId: string) {
    return {
      uploadId,
      async uploadPart(partNumber: number, body: any) {
        let bytes: Uint8Array;
        if (body instanceof Uint8Array) bytes = body;
        else if (body instanceof ArrayBuffer) bytes = new Uint8Array(body);
        else if (body === expectedBody) bytes = new Uint8Array(await new Response(body).arrayBuffer());
        else throw new Error(KNOWN_LENGTH_ERROR);
        bucket.parts.push({ key, n: partNumber, bytes: bytes.byteLength });
        return { partNumber, etag: `etag-${partNumber}` };
      },
      async complete(parts: { partNumber: number }[]) {
        const total = bucket.parts.filter((p) => p.key === key).reduce((a, b) => a + b.bytes, 0);
        bucket.completes.push({ key, parts: parts.length });
        if (!bucket.sizeOf.has(key)) bucket.sizeOf.set(key, total);
        return { size: bucket.sizeOf.get(key) };
      },
      async abort() {
        bucket.aborts.push(key);
      },
    };
  },
  async head(key: string) {
    const size = bucket.sizeOf.get(key);
    return size === undefined ? null : { size, httpMetadata: { contentType: "application/octet-stream" } };
  },
  async delete(key: string) {
    bucket.deleted.push(key);
  },
  async get() {
    return null;
  },
};

/* ═══════════ 假 D1：upload_sessions + files ═══════════ */

class Db {
  sessions: { id: string; key: string; upload_id: string; created_at: number }[] = [];
  insertedFiles: any[] = [];
  deletedSessions: string[] = [];
  constructor(private settingsRows: { key: string; value: string }[]) {}

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
        if (/sqlite_master/.test(norm)) return /name='settings'/.test(norm) ? { name: "settings" } : { sql: "x" };
        if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(norm)) return { value: "9999" };
        if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path/.test(norm)) return null;
        if (/^SELECT COALESCE\(SUM\(size\), 0\) AS bytes FROM files/.test(norm)) return { bytes: 0 };
        if (/^SELECT id, key, upload_id, name, mime, folder_id, size_declared, created_at FROM upload_sessions WHERE id = \?1/.test(norm)) {
          const s = self.sessions.find((x) => x.id === String(binds[0]));
          return s ? { ...s, name: "big.bin", mime: "application/octet-stream", folder_id: null, size_declared: null } : null;
        }
        if (/^SELECT id FROM folders WHERE id = \?1/.test(norm)) return binds[0] === "ghost" ? null : { id: String(binds[0]) };
        return null;
      },
      async all() {
        if (/^SELECT key, value FROM settings/.test(norm)) return { results: self.settingsRows };
        if (/^SELECT id, key, upload_id, name, mime, folder_id, size_declared, created_at FROM upload_sessions WHERE created_at < \?1/.test(norm)) {
          const cutoff = Number(binds[0]);
          return { results: self.sessions.filter((s) => s.created_at < cutoff).slice(0, Number(binds[1])) };
        }
        throw new Error("未覆盖的 SQL: " + norm);
      },
      async run() {
        if (/^INSERT INTO upload_sessions\(/.test(norm)) {
          self.sessions.push({
            id: String(binds[0]),
            key: String(binds[1]),
            upload_id: String(binds[2]),
            created_at: Number(binds[7]),
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (/^DELETE FROM upload_sessions WHERE id = \?1/.test(norm)) {
          const id = String(binds[0]);
          self.sessions = self.sessions.filter((s) => s.id !== id);
          self.deletedSessions.push(id);
          return { success: true, meta: { changes: 1 } };
        }
        if (/^DELETE FROM upload_sessions WHERE id IN/.test(norm)) {
          const ids = binds.map(String);
          self.sessions = self.sessions.filter((s) => !ids.includes(s.id));
          self.deletedSessions.push(...ids);
          return { success: true, meta: { changes: ids.length } };
        }
        if (/^INSERT INTO files\(/.test(norm)) {
          self.insertedFiles.push(binds);
          return { success: true, meta: { changes: 1 } };
        }
        throw new Error("未覆盖的 SQL: " + norm);
      },
    };
    return stmt;
  }
  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }
}

function mk(rows: { key: string; value: string }[]) {
  const db = new Db(rows);
  const env: any = { db, admin: "sekret", r2: r2Fake };
  return { db, env };
}

function defaultRows(maxMb = 100, quotaMb = 0) {
  return [
    { key: "admin_ips", value: "" },
    { key: "max_upload_mb", value: String(maxMb) },
    { key: "storage_quota_mb", value: String(quotaMb) },
  ];
}

async function call(env: any, path: string, init: { method?: string; body?: any; headers?: Record<string, string> } = {}) {
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    method: init.method ?? "GET",
    headers: { cookie, "cf-connecting-ip": "203.0.113.1", ...(init.headers ?? {}) },
    body: init.body,
  });
  // 每个请求都要重新绑定"本尊"：分片体必须原样进存储层
  expectedBody = req.body;
  const res = await handleAdminApi(req, env, { waitUntil() {}, props: {} } as any, new URL(req.url).pathname);
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function initUpload(env: any, name: string, size: number | null, extra: Record<string, unknown> = {}) {
  return call(env, "/api/admin/upload/init", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name, size, mime: "application/octet-stream", ...extra }),
  });
}

async function main() {
  console.log("\n[1] init：开会话并给出分片大小");
  {
    invalidateSettingsCache();
    bucket.reset();
    const { db, env } = mk(defaultRows());
    const r = await initUpload(env, "big.bin", 20 * MB);
    check("201", r.status === 201, JSON.stringify(r.body));
    check("回传会话 id 与 8 MiB 分片建议", !!r.body?.id && r.body?.chunk_size === CHUNK_SIZE, JSON.stringify(r.body));
    check("开了 R2 多段上传", bucket.creates.length === 1, JSON.stringify(bucket.creates));
    check("会话落库一行", db.sessions.length === 1 && db.sessions[0].id === r.body.id, JSON.stringify(db.sessions));
    const badName = await call(env, "/api/admin/upload/init", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ size: 1 }) });
    check("没名字 400", badName.status === 400, String(badName.status));
    const badFolder = await initUpload(env, "x.bin", 1024, { folder_id: "ghost" });
    check("未知目录 400", badFolder.status === 400, String(badFolder.status));
  }

  console.log("\n[2] init 阶段就能挡掉的体积");
  {
    invalidateSettingsCache();
    bucket.reset();
    const { env } = mk(defaultRows(50));
    const over = await initUpload(env, "big.bin", 60 * MB);
    check("声明体积超上限 → 413 + 上限回传", over.status === 413 && over.body?.error === "too_large" && over.body?.limit_mb === 50, JSON.stringify(over.body));
    const parts = await initUpload(env, "big.bin", (MAX_PARTS + 5) * CHUNK_SIZE, {});
    check("分片数超协议上限 → 413", parts.status === 413, JSON.stringify(parts.body));
  }

  console.log("\n[3] 逐片上传（流必须原样交给存储层）");
  {
    invalidateSettingsCache();
    bucket.reset();
    const { db, env } = mk(defaultRows());
    const r = await initUpload(env, "big.bin", 18 * MB);
    const id = r.body.id;
    const chunkA = new Uint8Array(8 * MB);
    const p1 = await call(env, `/api/admin/upload/part?id=${id}&part=1`, { method: "PUT", body: chunkA });
    check("第 1 片 200 + 回传 etag", p1.status === 200 && p1.body?.etag === "etag-1", JSON.stringify(p1.body));
    const ghost = await call(env, `/api/admin/upload/part?id=nope&part=1`, { method: "PUT", body: chunkA });
    check("未知会话 404", ghost.status === 404 && ghost.body?.error === "upload_not_found", JSON.stringify(ghost.body));
    const badNo = await call(env, `/api/admin/upload/part?id=${id}&part=0`, { method: "PUT", body: chunkA });
    check("片号越界 400", badNo.status === 400 && badNo.body?.error === "bad_part_number", JSON.stringify(badNo.body));
    const huge = await call(env, `/api/admin/upload/part?id=${id}&part=2`, {
      method: "PUT",
      body: chunkA,
      headers: { "content-length": String(200 * MB) },
    });
    check("单片谎报超限 → 413", huge.status === 413, String(huge.status));
    check("片号非法时不写存储", bucket.parts.filter((p) => p.n !== 1).length === 0, JSON.stringify(bucket.parts));
    const done = await call(env, "/api/admin/upload/complete", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, parts: [{ partNumber: 1, etag: "etag-1" }] }),
    });
    check("合并成功 → 201 并按真实字节落库", done.status === 201 && db.insertedFiles.length === 1, JSON.stringify(done.body));
    check("落库 size = 真实 8 MiB", db.insertedFiles[0]?.[3] === 8 * MB, JSON.stringify(db.insertedFiles[0]));
    check("会话行被清掉", db.sessions.length === 0, JSON.stringify(db.sessions));
  }

  console.log("\n[4] 真实体积才是判据（声明可以撒谎）");
  {
    invalidateSettingsCache();
    bucket.reset();
    const { db, env } = mk(defaultRows(10));
    const r = await initUpload(env, "big.bin", 2 * MB); // 谎报 2 MB
    const id = r.body.id;
    check("谎报体积能过 init（落盘前无从判断）", r.status === 201, JSON.stringify(r.body));
    await call(env, `/api/admin/upload/part?id=${id}&part=1`, { method: "PUT", body: new Uint8Array(4 * MB) });
    // 合并后对象实际 50 MB —— 直接改 head 会读到的体积
    const key = db.sessions[0].key;
    bucket.sizeOf.set(key, 50 * MB);
    const done = await call(env, "/api/admin/upload/complete", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, parts: [{ partNumber: 1, etag: "etag-1" }] }),
    });
    check("真实体积超上限 → 413", done.status === 413 && done.body?.error === "too_large", JSON.stringify(done.body));
    check("对象被删掉", bucket.deleted.includes(key), JSON.stringify(bucket.deleted));
    check("行没落库", db.insertedFiles.length === 0, JSON.stringify(db.insertedFiles));
    check("会话也清掉了", db.sessions.length === 0, JSON.stringify(db.sessions));
  }

  console.log("\n[5] complete 的入参校验");
  {
    invalidateSettingsCache();
    bucket.reset();
    const { db, env } = mk(defaultRows());
    const id = (await initUpload(env, "big.bin", 8 * MB)).body.id;
    const post = (parts: unknown, sessionId = id) =>
      call(env, "/api/admin/upload/complete", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: sessionId, parts }),
      });
    check("没有分片 → 400", (await post([])).status === 400);
    check("重复片号 → 400", (await post([{ partNumber: 1, etag: "a" }, { partNumber: 1, etag: "b" }])).body?.error === "duplicate_part");
    check("缺 etag → 400", (await post([{ partNumber: 1 }])).body?.error === "bad_etag");
    check("未知会话 → 404", (await post([{ partNumber: 1, etag: "a" }], "nope")).status === 404);
    check("校验不过不会误删会话", db.sessions.length === 1, JSON.stringify(db.sessions));
  }

  console.log("\n[6] 取消与超时回收");
  {
    invalidateSettingsCache();
    bucket.reset();
    const { db, env } = mk(defaultRows());
    const id = (await initUpload(env, "big.bin", 8 * MB)).body.id;
    const gone = await call(env, `/api/admin/upload?id=${id}`, { method: "DELETE" });
    check("取消 200", gone.status === 200, JSON.stringify(gone.body));
    check("中止了 R2 多段上传", bucket.aborts.length === 1, JSON.stringify(bucket.aborts));
    check("会话行已删", db.sessions.length === 0);
    check("再取消一次 404", (await call(env, `/api/admin/upload?id=${id}`, { method: "DELETE" })).status === 404);
  }
  {
    invalidateSettingsCache();
    bucket.reset();
    const { db, env } = mk(defaultRows());
    const id = (await initUpload(env, "big.bin", 8 * MB)).body.id;
    db.sessions[0].created_at = Date.now() - UPLOAD_TTL_MS - 1000; // 假装是昨天的
    const { staleUploadIds, abortStaleUploads } = await import("../src/uploads");
    const stale = await staleUploadIds(env as any, Date.now(), 100);
    check("超时会话被扫出来", stale.length === 1 && stale[0].id === id, JSON.stringify(stale));
    const n = await abortStaleUploads(env as any, stale);
    check("中止并清行", n === 1 && bucket.aborts.length === 1 && db.sessions.length === 0, JSON.stringify({ n, aborts: bucket.aborts }));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
