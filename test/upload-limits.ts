/**
 * 上传体积闸门测试 —— 前端那句"单文件最大 100 MB"以前只存在于文案里，
 * 服务端从来没校验过。这里验证真的拦得住，包括撒谎的 Content-Length。
 *
 * 运行：
 *   npx esbuild test/upload-limits.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/upload-limits.mjs
 *   node .dev/upload-limits.mjs
 */
import {
  cappedStream,
  declaredSize,
  formatMb,
  isOverLimitError,
  postUploadRejection,
  preUploadRejection,
} from "../src/limits";
import { getSettings, invalidateSettingsCache } from "../src/settings";
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import type { Settings } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const MB = 1024 ** 2;

function settingsWith(patch: Partial<Settings>): Settings {
  return { ...({} as Settings), maxUploadBytes: 100 * MB, storageQuotaBytes: 0, ...patch } as Settings;
}

function streamOf(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i < chunks.length) controller.enqueue(chunks[i++]);
      else controller.close();
    },
  });
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<number> {
  const reader = stream.getReader();
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
  }
  return total;
}

/* ═══════════ 走通管理端上传所需的最小环境 ═══════════ */

const NEW_TABLE_SQL =
  "CREATE TABLE \"folders\"(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)";

class UploadDb {
  inserted: any[] = [];
  constructor(public settingsRows: { key: string; value: string }[]) {}
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
        if (/sqlite_master/.test(norm)) {
          return /name='settings'/.test(norm) ? { name: "settings" } : { sql: NEW_TABLE_SQL };
        }
        if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(norm)) return { value: "999" };
        if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path/.test(norm)) return null;
        if (/^SELECT COALESCE\(SUM\(size\), 0\) AS bytes FROM files/.test(norm)) return { bytes: self.inserted.length * 10 };
        return null;
      },
      async all() {
        if (/^SELECT key, value FROM settings/.test(norm)) return { results: self.settingsRows };
        throw new Error("未覆盖的 SQL: " + norm);
      },
      async run() {
        if (/^INSERT INTO files\(/.test(norm)) {
          self.inserted.push(binds);
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

function makeR2(log: { put: string[]; deleted: string[] }, maxBytes: number) {
  return {
    async put(key: string, body: any) {
      const bytes = await new Response(body).arrayBuffer();
      if (bytes.byteLength > maxBytes) throw new Error("stream aborted");
      log.put.push(key);
      return { size: bytes.byteLength, httpEtag: "etag" };
    },
    async delete(key: string) {
      log.deleted.push(key);
    },
    async get() {
      return null;
    },
    async head() {
      return null;
    },
  };
}

async function upload(body: Uint8Array, opts: { contentLength?: string; maxMb: number; quotaMb?: number }) {
  invalidateSettingsCache();
  const rows = [
    { key: "admin_ips", value: "" },
    { key: "max_upload_mb", value: String(opts.maxMb) },
    { key: "storage_quota_mb", value: String(opts.quotaMb ?? 0) },
  ];
  const db = new UploadDb(rows);
  const log = { put: [] as string[], deleted: [] as string[] };
  const env: any = {
    db,
    admin: "sekret",
    r2: makeR2(log, opts.maxMb * MB),
  };
  const cookie = (await createSession(env)).split(";")[0];
  const headers: Record<string, string> = {
    cookie,
    "cf-connecting-ip": "203.0.113.1",
    "x-file-name": encodeURIComponent("big.bin"),
    "content-type": "application/octet-stream",
  };
  if (opts.contentLength !== undefined) headers["content-length"] = opts.contentLength;
  const req = new Request("https://pan.test/api/admin/upload", { method: "POST", headers, body: body as any });
  const res = await handleAdminApi(req, env, { waitUntil() {}, props: {} } as any, "/api/admin/upload");
  return { status: res.status, body: await res.json().catch(() => null), db, log };
}

async function main() {
  console.log("\n[1] 声明体积与配额判定");
  {
    const declared = new Request("https://x.test/", { method: "POST", headers: { "content-length": "123" }, body: "x" });
    check("Content-Length 读得出", declaredSize(declared) === 123, String(declaredSize(declared)));
    check("没有 Content-Length 时不猜", declaredSize(new Request("https://x.test/")) === null);

    const limits = settingsWith({ maxUploadBytes: 10 * MB, storageQuotaBytes: 100 * MB });
    check("超过单文件上限 → 413", preUploadRejection(limits, 0, 11 * MB)?.status === 413);
    check("刚好等于上限放行", preUploadRejection(limits, 0, 10 * MB) === null);
    check("未声明体积时先放行（由流计数兜）", preUploadRejection(limits, 0, null) === null);
    check("配额不够 → 507", preUploadRejection(limits, 95 * MB, 10 * MB)?.status === 507);
    check("配额判定只看声明", preUploadRejection(limits, 95 * MB, null) === null);
    check("上限 0 = 不限", preUploadRejection(settingsWith({ maxUploadBytes: 0, storageQuotaBytes: 0 }), 0, 999 * MB) === null);
    check("事后按真实体积判配额", postUploadRejection(limits, 95 * MB, 8 * MB)?.status === 507);
    check("事后未超放行", postUploadRejection(limits, 10 * MB, 8 * MB) === null);
    check("MB 取整显示", formatMb(1.5 * MB) === 1.5 && formatMb(100 * MB) === 100);
  }

  console.log("\n[2] 流式计数：撒谎的 Content-Length 挡不住它");
  {
    const chunks = [new Uint8Array(1000), new Uint8Array(1000), new Uint8Array(1000)];
    const capped = cappedStream(streamOf(chunks), 2500);
    let thrown = "";
    try {
      await drain(capped);
    } catch (e: any) {
      thrown = String(e?.message ?? e);
    }
    check("超限抛错", isOverLimitError(new Error(thrown)), thrown);
    check("没超限时原样通过", (await drain(cappedStream(streamOf([new Uint8Array(1000)]), 2500))) === 1000);
    check("普通错误不误判", isOverLimitError(new Error("network down")) === false);
  }

  console.log("\n[3] 设置解析：MB → 字节");
  {
    invalidateSettingsCache();
    const db = new UploadDb([
      { key: "admin_ips", value: "" },
      { key: "max_upload_mb", value: "20" },
      { key: "storage_quota_mb", value: "500" },
    ]);
    const s = await getSettings({ db } as any);
    check("单文件上限 20MB", s.maxUploadBytes === 20 * MB, String(s.maxUploadBytes));
    check("配额 500MB", s.storageQuotaBytes === 500 * MB, String(s.storageQuotaBytes));
    invalidateSettingsCache();
    const d = await getSettings({ db: new UploadDb([{ key: "admin_ips", value: "" }]) } as any);
    check("缺省回到 100MB / 不限", d.maxUploadBytes === 100 * MB && d.storageQuotaBytes === 0);
    invalidateSettingsCache();
    const bad = await getSettings({ db: new UploadDb([{ key: "admin_ips", value: "" }, { key: "max_upload_mb", value: "-5" }]) } as any);
    check("非法值回落默认", bad.maxUploadBytes === 100 * MB, String(bad.maxUploadBytes));
  }

  console.log("\n[4] 管理端上传真的被服务端拦下");
  {
    const big = new Uint8Array(2 * MB);
    const honest = await upload(big, { maxMb: 1, contentLength: String(2 * MB) });
    check("诚实声明超限 → 413", honest.status === 413, String(honest.status));
    check("错误码与上限回传", (honest.body as any)?.error === "too_large" && (honest.body as any).limit_mb === 1, JSON.stringify(honest.body));
    check("未落库", honest.db.inserted.length === 0);
    check("落盘前就挡下：没写对象也没得回滚", honest.log.put.length === 0 && honest.log.deleted.length === 0, JSON.stringify(honest.log));

    // 谎报 Content-Length：躲得过预检，躲不过流式计数
    const liar = await upload(big, { maxMb: 1, contentLength: "5" });
    check("谎报 Content-Length 仍被拦下", liar.status === 413, String(liar.status) + JSON.stringify(liar.body));
    check("谎报时也没落库", liar.db.inserted.length === 0, JSON.stringify(liar.db.inserted));
    // 所有调用共用同一个 storage provider（按设置指纹缓存），所以看第一个 log
    check("写到一半的对象被回滚删除", honest.log.deleted.length >= 1 && honest.log.put.length === 0, JSON.stringify(honest.log));

    const fits = await upload(new Uint8Array(600 * 1024), { maxMb: 1, contentLength: String(600 * 1024) });
    check("合法上传照常成功", fits.status === 201, String(fits.status) + JSON.stringify(fits.body));
    check("成功时写入一行", fits.db.inserted.length === 1);

    const quota = await upload(new Uint8Array(600 * 1024), { maxMb: 1, quotaMb: 0, contentLength: String(600 * 1024) });
    check("配额 0 表示不限", quota.status === 201, String(quota.status));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
