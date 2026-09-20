/**
 * 取件码投递测试 —— 码既是地址也是凭据，所以要点全在"猜不动 + 看不见 + 烧不掉"上：
 *   1. 归一化：大小写/空格/连字符等价；形状不对连库都不查
 *   2. 三层限流：按 IP 总量、按 IP 失败数、按码失败数（拿到码的人自己也会被冷却住）
 *   3. 配额：单件上限、单 IP 每日件数/字节、投递区总量；超配额必须回滚对象
 *   4. 投递出来的分享：origin='drop'、不进市场、不派生直链、按保留期到期
 *   5. 下载复用分享那条闸门流水线（票据缺失/被改 → 拒；一次一取 → 第二次取不到）
 *   6. 失败响应统一形状，不区分"码不存在 / 已过期 / 已取走"
 *
 * 运行：
 *   npx esbuild test/pickup-code.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/pickup-code.mjs
 *   node .dev/pickup-code.mjs
 */
import { handlePickupClaim, handlePickupDownload, handlePickupDrop, normalizePickupCode, normalizePickupCodeLoose, formatPickupCode, mintPickupCode, invalidateDropFolderCache } from "../src/pickup";
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

const ADMIN = "pickup-test-secret";
const MB = 1024 ** 2;

type Row = Record<string, any>;

const BASE_SETTINGS: Record<string, string> = {
  turnstile_mode: "off",
  traffic_limit_bytes: "0",
  max_downloads_per_ip: "0",
  count_window_hours: "24",
  oauth_enabled: "0",
  admin_ips: "",
  max_upload_mb: "100",
  storage_quota_mb: "0",
  auto_ban: "0",
  pickup_enabled: "1",
  pickup_max_upload_mb: "20",
  pickup_total_quota_mb: "30",
  pickup_per_ip_daily_count: "3",
  pickup_per_ip_daily_mb: "25",
  pickup_retention_days: "7",
};

/** 真 D1 会拒绝"占位符个数 ≠ 绑定个数"，假库必须一样严格 */
function assertBinds(sql: string, binds: any[]) {
  const numbered = new Set([...sql.matchAll(/\?(\d+)/g)].map((m) => Number(m[1])));
  if (numbered.size && numbered.size !== binds.length)
    throw new Error(`占位符与绑定不匹配（${numbered.size} vs ${binds.length}）: ${sql}`);
}

class FakeD1 {
  files: Row[] = [];
  shares: Row[] = [];
  folders: Row[] = [];
  traffic = 0;
  sqlLog: string[] = [];
  downloads = 0;
  constructor(public settings: Record<string, string> = {}) {}

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    const self = this;
    const stmt: any = {
      bind(...binds: any[]) {
        stmt._binds = binds;
        return stmt;
      },
      _binds: [] as any[],
      async first() { return self.exec(norm, stmt._binds, "first"); },
      async all() {
        const r = self.exec(norm, stmt._binds, "all");
        return Array.isArray(r) ? { results: r, success: true, meta: {} } : { results: [], success: true, meta: {} };
      },
      async run() {
        const out = self.exec(norm, stmt._binds, "run");
        return { success: true, meta: { changes: out?.changes ?? 1 }, results: [] };
      },
    };
    return stmt;
  }
  async batch(stmts: any[]) { for (const s of stmts) await s.run(); return []; }

  private exec(sql: string, binds: any[], mode: string): any {
    assertBinds(sql, binds);
    this.sqlLog.push(sql);

    /* ── ensureSchema 冷启动：这些查询要活着，DDL 不该在这里出现 ── */
    if (/sqlite_master/.test(sql)) return mode === "all" ? [] : { name: "settings", sql: "CREATE TABLE settings" };
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "9999" };
    if (/^SELECT 1 FROM directories|^SELECT 1 FROM files WHERE folder_id IS NULL AND path IS NOT NULL/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^CREATE INDEX|^DROP TABLE/.test(sql)) throw new Error("冷启动不该跑 DDL: " + sql);
    if (/^SELECT key, value FROM settings/.test(sql)) {
      return Object.entries({ ...BASE_SETTINGS, ...this.settings }).map(([key, value]) => ({ key, value }));
    }
    if (/^SELECT id, name, parent_id, created_at FROM folders/.test(sql)) return this.folders.map((f) => ({ ...f }));
    if (/^INSERT INTO folders/.test(sql)) {
      const [id, name, parent_id, created_at] = binds;
      if (this.folders.some((f) => f.name === name && (f.parent_id ?? null) === (parent_id ?? null))) return { changes: 0 };
      this.folders.push({ id, name, parent_id, created_at });
      return { changes: 1 };
    }
    if (/^SELECT reason, expires_at FROM banned_ips/.test(sql)) return null;

    /* ── 撞码探测 ── */
    if (/^SELECT id FROM shares WHERE pickup_hash = \?1/.test(sql)) {
      return this.shares.find((s) => s.pickup_hash === binds[0]) ? { id: s_id(this.shares, binds[0]) } : null;
    }
    /* ── 投递区占用（去重后的真实字节，按 drop 行） ── */
    if (/SELECT COALESCE\(SUM\(s\), 0\) AS bytes FROM/.test(sql)) {
      const live = this.shares.filter((s) => s.origin === "drop")
        .map((s) => this.files.find((f) => f.id === s.file_id && f.deleted_at == null))
        .filter(Boolean) as Row[];
      const byKey = new Map<string, number>();
      for (const f of live) byKey.set(f.key, Math.min(byKey.get(f.key) ?? f.size, f.size));
      let sum = 0;
      for (const v of byKey.values()) sum += v;
      return { bytes: sum };
    }
    /* ── 单 IP 当日投递量 ── */
    if (/^SELECT COUNT\(\*\) AS c, COALESCE\(SUM\(size\), 0\) AS bytes FROM/.test(sql)) {
      const [ip, since] = binds;
      const rows = this.shares.filter((s) => s.origin === "drop" && s.origin_ip === ip && s.created_at > since)
        .map((s) => this.files.find((f) => f.id === s.file_id))
        .filter(Boolean) as Row[];
      return { c: rows.length, bytes: rows.reduce((a, f) => a + f.size, 0) };
    }
    /* ── 投递写入 ── */
    if (/^INSERT INTO files/.test(sql)) {
      const [id, key, name, size, mime, uploaded_at, folder_id, etag] = binds;
      this.files.push({ id, key, name, size, mime, uploaded_at, folder_id, etag, deleted_at: null });
      return { changes: 1 };
    }
    if (/^INSERT INTO shares/.test(sql)) {
      const names = /INSERT INTO shares\(([^)]*)\)/.exec(sql)![1].split(",").map((c) => c.trim());
      const values = /VALUES\(([^)]*)\)/.exec(sql)![1].split(",").map((c) => c.trim());
      if (values.length !== names.length) throw new Error(`shares 插入列数与取值不符: ${sql}`);
      let slot = 0;
      const row: Row = { revoked: 0, download_count: 0, password_hash: null, is_market: 0, origin: "admin", pickup_claims: 0 };
      names.forEach((n, i) => {
        const v = values[i];
        if (/^\?\d+$/.test(v)) row[n] = binds[slot++] ?? null;
        else if (/^'.*'$/.test(v)) row[n] = v.slice(1, -1);
        else if (/^\d+$/.test(v)) row[n] = Number(v);
      });
      if (slot !== binds.length) throw new Error(`shares 插入有 ${binds.length} 个绑定却只用了 ${slot} 个: ${sql}`);
      row.download_count = Number(row.download_count) || 0;
      this.shares.push(row);
      return { changes: 1 };
    }
    /* ── 按码取行（JOIN files，回收站里的不算） ── */
    if (/FROM shares sh JOIN files f ON f\.id = sh\.file_id WHERE sh\.pickup_hash = \?1/.test(sql)) {
      const s = this.shares.find((x) => x.pickup_hash === binds[0] && x.origin === "drop");
      const f = s && this.files.find((x) => x.id === s.file_id && x.deleted_at == null);
      if (!s || !f) return null;
      return {
        share_id: s.id, file_id: s.file_id, created_at: s.created_at, expires_at: s.expires_at,
        max_downloads: s.max_downloads, download_count: s.download_count, revoked: s.revoked,
        password_hash: s.password_hash, key: f.key, name: f.name, size: f.size, mime: f.mime,
      };
    }
    if (/^UPDATE shares SET pickup_claims/.test(sql)) {
      const s = this.shares.find((x) => x.id === binds[0]);
      if (s) s.pickup_claims = (s.pickup_claims ?? 0) + 1;
      return { changes: 1 };
    }
    if (/^UPDATE shares SET download_count = download_count \+ 1/.test(sql)) {
      const [id, max] = binds;
      const s = this.shares.find((x) => x.id === id);
      if (!s) return { changes: 0 };
      if (max === undefined || s.download_count < Number(max)) { s.download_count++; this.downloads++; return { changes: 1 }; }
      return { changes: 0 };
    }
    if (/^SELECT COUNT\(\*\) AS c FROM download_logs/.test(sql)) return { c: 0 };
    if (/^INSERT INTO download_logs|^UPDATE settings SET|^INSERT INTO traffic_stats|^INSERT INTO settings/.test(sql)) return { changes: 1 };
    throw new Error("假库没覆盖的语句: " + sql.slice(0, 120));
  }
}

function s_id(shares: Row[], hash: string): string {
  return shares.find((s) => s.pickup_hash === hash)?.id ?? "";
}

/* ═══════════ 假存储：整个文件必须原样落进来，删除动作要看得见 ═══════════ */

const r2 = {
  puts: [] as { key: string; size: number }[],
  deletes: [] as string[],
  nextSize: 4096,
  async put(key: string, body: any, opts: any = {}) {
    const size = body?.byteLength ?? body?.size ?? this.nextSize;
    this.puts.push({ key, size });
    return { size, httpEtag: "etag-" + key.slice(-4), httpMetadata: { contentType: opts?.contentType ?? "application/octet-stream" } };
  },
  async get(key: string) {
    const size = this.puts.find((p) => p.key === key)?.size ?? 4096;
    return { body: new Response("x".repeat(size)).body, size, httpEtag: "etag", httpMetadata: { contentType: "application/octet-stream" } };
  },
  async delete(key: string) { this.deletes.push(key); },
  async head(key: string) { return { size: this.puts.find((p) => p.key === key)?.size ?? 0, contentType: "application/octet-stream" }; },
};

function makeCtx() {
  const waited: Promise<any>[] = [];
  return { ctx: { waitUntil: (p: Promise<any>) => void waited.push(Promise.resolve(p)), passThroughOnException: () => {}, props: {} } as any, waited };
}

function env(db: FakeD1): Env {
  return { db, r2: r2 as any, admin: ADMIN } as any;
}

let ipSeq = 0;
function freshIp(): string {
  ipSeq++;
  return `203.0.113.${(ipSeq % 200) + 1}`;
}

/** 一次投件。body 用真流，体积由假 R2 回报（默认 24 字节） */
async function drop(db: FakeD1, opts: { ip?: string; size?: number; name?: string; query?: string; body?: any } = {}) {
  invalidateSettingsCache();
  invalidateDropFolderCache();
  r2.nextSize = opts.size ?? 24;
  const req = new Request("https://pan.test/api/pickup" + (opts.query ?? ""), {
    method: "POST",
    duplex: "half" as any,
    headers: {
      "cf-connecting-ip": opts.ip ?? freshIp(),
      "content-type": "application/octet-stream",
      "x-file-name": encodeURIComponent(opts.name ?? "report.bin"),
    },
    body: opts.body ?? new Response("x".repeat(opts.size ?? 24)).body,
  });
  const { ctx, waited } = makeCtx();
  const res = await handlePickupDrop(req, env(db), ctx);
  await Promise.all(waited);
  return { res, json: await res.json().catch(() => null) as any };
}

async function claim(db: FakeD1, code: unknown, ip = freshIp()) {
  invalidateSettingsCache();
  const req = new Request("https://pan.test/api/pickup/claim", {
    method: "POST",
    headers: { "cf-connecting-ip": ip, "content-type": "application/json" },
    body: JSON.stringify({ code }),
  });
  const res = await handlePickupClaim(req, env(db));
  const text = await res.text();
  let json: any = null;
  try { json = JSON.parse(text); } catch { /* 错误页是 HTML */ }
  return { res, json, text };
}

async function take(db: FakeD1, code: string, t: string | null, ip = freshIp()) {
  invalidateSettingsCache();
  const req = new Request(`https://pan.test/api/pickup/download?c=${code}&t=${encodeURIComponent(t ?? "")}`, {
    headers: { "cf-connecting-ip": ip },
  });
  const { ctx, waited } = makeCtx();
  const res = await handlePickupDownload(req, env(db), ctx);
  await Promise.all(waited);
  return res;
}

function bareCode(r: any): string {
  return String(r?.json?.code ?? "").replace("-", "").toLowerCase();
}

/* ═══════════ [1] 码的形状 ═══════════ */

function codeShapeTests() {
  console.log("\n[1] 码的归一化与展示（默认 6 位纯数字）");
  check("空格与连字符被吃掉", normalizePickupCode("123 456") === "123456" && normalizePickupCode("123-456") === "123456");
  check("数字模式下字母不接受", normalizePickupCode("12a456") === null && normalizePickupCode("ab3dk9fq") === null);
  check("长度不符不接受", normalizePickupCode("12345") === null && normalizePickupCode("1234567") === null);
  check("非字符串不炸", normalizePickupCode(null) === null && normalizePickupCode(123456 as any) === null);
  check("alnum8 模式仍可用（严格）", normalizePickupCode("AB3D-K9 FQ", "alnum8") === "ab3dk9fq", String(normalizePickupCode("AB3D-K9 FQ", "alnum8")));
  check("宽松模式两种形状都收", normalizePickupCodeLoose("123456") === "123456" && normalizePickupCodeLoose("ab3d-k9fq") === "ab3dk9fq" && normalizePickupCodeLoose("12345") === null);
  check("前导零是码的一部分", normalizePickupCode("007456") === "007456");
  check("展示分组按长度：123-456 / ab3d-k9fq", formatPickupCode("123456") === "123-456" && formatPickupCode("ab3dk9fq") === "ab3d-k9fq", formatPickupCode("123456"));
}

async function mintTests() {
  console.log("\n[2] 生成码");
  const db = new FakeD1();
  const a = await mintPickupCode(env(db));
  check("默认形状是 6 位数字", /^\d{6}$/.test(a.code), a.code);
  check("存 keyed hash（64 hex）与密文", a.hash.length === 64 && !!a.cipher && !a.cipher.includes(a.code), a.hash.slice(0, 12));
  invalidateSettingsCache();
  const strong = new FakeD1({ pickup_code_style: "alnum8" });
  const b = await mintPickupCode(env(strong));
  check("切到 alnum8 后是 8 位且不含易混字符", /^[a-z0-9]{8}$/.test(b.code) && !/[ilo0]/.test(b.code), b.code);
  invalidateSettingsCache();
  const taken = await mintPickupCode(env(db));
  db.shares.push({ id: "SH_TAKEN", pickup_hash: taken.hash, origin: "drop", download_count: 0, revoked: 0 });
  const again = await mintPickupCode(env(db));
  check("撞上已占用的 hash 会换一枚", again.hash !== taken.hash && /^\d{6}$/.test(again.code), `${again.code} vs ${taken.code}`);
}

async function dropTests() {
  console.log("\n[3] 投件：行落在哪、长成什么样");
  const db = new FakeD1();
  r2.puts.length = 0;
  const r = await drop(db, { name: "合同 (终版).zip" });
  check("投件成功回 201", r.res.status === 201, String(r.res.status));
  check("给出 6 位数字取件码", /^\d{3}-\d{3}$/.test(r.json?.code ?? ""), r.json?.code);
  check("对象键在 drops/ 前缀下", r2.puts.length === 1 && r2.puts[0].key.startsWith("drops/"), JSON.stringify(r2.puts));
  const f = db.files[0];
  const s = db.shares[0];
  const dropDir = db.folders.find((x) => x.name === "投递箱");
  check("自动建出顶层投递箱目录", !!dropDir && dropDir.parent_id === null, JSON.stringify(db.folders));
  check("文件挂进投递箱", !!f && f.folder_id === dropDir?.id, JSON.stringify(f));
  check("文件名按 basename 清洗后保留", f?.name === "合同 (终版).zip", f?.name);
  check("分享行 origin=drop 且带来源 IP", s?.origin === "drop" && !!s?.origin_ip, JSON.stringify(s));
  check("投递行不进市场、不设访问口令", !s?.is_market && !s?.password_hash);
  check("按保留期到期（7 天）", !!s && s.expires_at - s.created_at === 7 * 86_400_000, String((s?.expires_at ?? 0) - (s?.created_at ?? 0)));
  check("响应带有效期与真实体积", r.json?.expires_at === s?.expires_at && r.json?.size === f?.size, JSON.stringify(r.json));
  check("库里只有 hash/cipher，没有明文码", !JSON.stringify(s).includes(bareCode(r)), JSON.stringify(s).slice(0, 90));

  console.log("\n[4] 总开关关掉 = 这功能不存在");
  const off = new FakeD1({ pickup_enabled: "0" });
  const rOff = await drop(off);
  check("投递入口 404", rOff.res.status === 404, String(rOff.res.status));
  check("什么都没写进库", off.files.length === 0 && off.shares.length === 0);
  const ok = new FakeD1();
  const code = bareCode(await drop(ok));
  const cOff = await claim(new FakeD1({ pickup_enabled: "0" }), code);
  check("关掉后已发出的码一律取不到", cOff.res.status === 404, String(cOff.res.status));
  const page = cOff.text;
  // 三种失败（功能关闭 / 形状不对 / 码不存在）必须回同一张页面 —— 不给试探者任何信息
  const junk = await claim(new FakeD1(), "!!!");
  const miss = await claim(new FakeD1(), "000000");
  check("失败响应同形（不泄露原因）",
    cOff.res.status === 404 && junk.res.status === 404 && miss.res.status === 404 &&
      page.length === junk.text.length && junk.text.length === miss.text.length,
    `${cOff.res.status}/${junk.res.status}/${miss.res.status} 长度 ${page.length}/${junk.text.length}/${miss.text.length}`);
}

async function quotaTests() {
  console.log("\n[5] 配额：超了必须把对象退回去");
  const sizeCap = new FakeD1();
  r2.deletes.length = 0;
  const big = await drop(sizeCap, { size: 25 * MB });
  check("单件超过 pickup_max_upload_mb 被拒", big.res.status === 413, String(big.res.status));
  check("被拒的投件不留对象", r2.deletes.length === 1 && sizeCap.files.length === 0, JSON.stringify(r2.deletes));
  check("回话带限额（MB）", big.json?.limit_mb === 20, JSON.stringify(big.json));

  const countOnly = new FakeD1({ pickup_per_ip_daily_count: "2", pickup_per_ip_daily_mb: "0", pickup_total_quota_mb: "0" });
  const ip = freshIp();
  const a = await drop(countOnly, { ip, size: 1 * MB });
  const b = await drop(countOnly, { ip, size: 1 * MB });
  const c = await drop(countOnly, { ip, size: 1 * MB });
  check("同一 IP 两件放行、第三件被拒", a.res.status === 201 && b.res.status === 201 && c.res.status === 429, `${a.res.status}/${b.res.status}/${c.res.status}`);
  check("拒因写的是件数上限", c.json?.error === "ip_daily_count" && c.json?.limit === 2, JSON.stringify(c.json));
  const other = await drop(countOnly, { size: 1 * MB });
  check("换一枚 IP 就照常放行（额度按来源算）", other.res.status === 201, String(other.res.status));

  const bytesOnly = new FakeD1({ pickup_per_ip_daily_count: "0", pickup_per_ip_daily_mb: "15", pickup_total_quota_mb: "0" });
  const ip2 = freshIp();
  const q1 = await drop(bytesOnly, { ip: ip2, size: 10 * MB });
  const q2 = await drop(bytesOnly, { ip: ip2, size: 10 * MB });
  const q3 = await drop(bytesOnly, { ip: ip2, size: 10 * MB });
  check("单 IP 字节额度到顶后 429", q1.res.status === 201 && q2.res.status === 201 && q3.res.status === 429, `${q1.res.status}/${q2.res.status}/${q3.res.status}`);
  check("拒因写的是字节额度", q3.json?.error === "ip_daily_bytes", JSON.stringify(q3.json));

  const total = new FakeD1({ pickup_per_ip_daily_count: "0", pickup_per_ip_daily_mb: "0", pickup_total_quota_mb: "30" });
  r2.deletes.length = 0;
  const t1 = await drop(total, { size: 20 * MB });
  const t2 = await drop(total, { size: 12 * MB });
  const t3 = await drop(total, { size: 5 * MB });
  check("不同 IP 共享投递区总配额", t1.res.status === 201 && t2.res.status === 507, `${t1.res.status}/${t2.res.status}`);
  check("被拒的那件不占额度（回滚后小件仍能投）", t3.res.status === 201 && total.files.length === 2, JSON.stringify({ rows: total.files.length, del: r2.deletes.length }));
  check("超配额写下的对象被删掉（不留孤儿）",
    r2.deletes.length === 1 && !total.files.some((f) => f.key === r2.deletes[0]),
    JSON.stringify({ del: r2.deletes, keys: total.files.map((f) => f.key) }));
}

async function roundTripTests() {
  console.log("\n[6] 取件回合：票据与下载");
  const db = new FakeD1();
  const code = bareCode(await drop(db, { name: "机密.pdf" }));
  const cl = await claim(db, ` ${code.slice(0, 3)}-${code.slice(3)} `);
  check("带空格与连字符的码照样能取", cl.res.status === 200, String(cl.res.status));
  check("回文件信息与票据", cl.json?.name === "机密.pdf" && !!cl.json?.t, JSON.stringify(cl.json).slice(0, 90));
  check("已取次数被记下来", db.shares[0].pickup_claims === 1, String(db.shares[0].pickup_claims));

  const noTicket = await take(db, code, null);
  check("没有票据不给下载", noTicket.status === 403, String(noTicket.status));
  const tampered = await take(db, code, "9999999999.deadbeef");
  check("伪造票据不给下载", tampered.status === 403, String(tampered.status));
  const ok = await take(db, code, cl.json.t);
  check("票据有效 → 200 推流", ok.status === 200, String(ok.status));
  check("按文件自己的名字下载", /attachment/.test(ok.headers.get("content-disposition") ?? ""), ok.headers.get("content-disposition") ?? "");
  check("走的是分享那条闸门：计数已 +1", db.shares[0].download_count === 1, String(db.shares[0].download_count));

  console.log("\n[7] 一次一取");
  const db2 = new FakeD1();
  const onceCode = bareCode(await drop(db2, { query: "?once=1", size: 32 }));
  check("once=1 → max_downloads 1", db2.shares[0].max_downloads === 1, String(db2.shares[0].max_downloads));
  const c1 = await claim(db2, onceCode);
  check("首次输码可取", c1.res.status === 200 && c1.json.one_shot === true, JSON.stringify(c1.json).slice(0, 60));
  const d1 = await take(db2, onceCode, c1.json.t);
  const c2 = await claim(db2, onceCode);
  check("名额用掉后连码都取不到（统一 404）", d1.status === 200 && c2.res.status === 404, `${d1.status}/${c2.res.status}`);
}

async function throttleTests() {
  console.log("\n[8] 三层限流");
  const db = new FakeD1();
  const code = bareCode(await drop(db));
  /** 只数"真的查了库"的语句（getSettings 每次都读，与爆破成本无关） */
  const reads = () => db.sqlLog.filter((s) => !/FROM settings/.test(s)).length;

  const before = reads();
  const junk = await claim(db, "!!!", freshIp());
  check("形状不对直接拒", junk.res.status === 404, String(junk.res.status));
  check("形状不对一次库都不查", reads() === before, `多出 ${reads() - before} 条`);

  const guessed = "999999";
  for (let i = 0; i < 5; i++) await claim(new FakeD1(), guessed, freshIp());
  const throttled = new FakeD1({});
  const mark = throttled.sqlLog.length;
  const sixth = await claim(throttled, guessed, freshIp());
  check("同一枚码被反复试 → 不再查库", sixth.res.status === 404 && !throttled.sqlLog.slice(mark).some((s) => /pickup_hash = \?1/.test(s)),
    throttled.sqlLog.slice(mark).filter((s) => !/FROM settings/.test(s)).join(" | ").slice(0, 80));

  const flood = freshIp();
  let last = 0;
  for (let i = 0; i < 11; i++) last = (await claim(db, code, flood)).res.status;
  check("同一 IP 猜 11 次触发频率限流", last === 429, String(last));
  const otherIp = await claim(db, code, freshIp());
  check("限流按 IP 计，殃及不到别人", otherIp.res.status === 200, String(otherIp.res.status));

  // 6 位数字只有 100 万种组合，靠的是"每天也不让你试几次"
  const daily = new FakeD1({ pickup_per_ip_daily_claims: "1" });
  const dailyCode = bareCode(await drop(daily));
  const slow = freshIp();
  const first = await claim(daily, dailyCode, slow);
  const second = await claim(daily, dailyCode, slow);
  check("每分钟还没超，但每日尝试预算超了就拒", first.res.status === 200 && second.res.status === 429, `${first.res.status}/${second.res.status}`);

  console.log("\n[9] 投件侧频率");
  const db3 = new FakeD1({ pickup_per_ip_daily_count: "0", pickup_per_ip_daily_mb: "0", pickup_total_quota_mb: "0" });
  const spam = freshIp();
  let dropLast = 0;
  for (let i = 0; i < 8; i++) dropLast = (await drop(db3, { ip: spam, size: 8 })).res.status;
  check("同 IP 连投 8 次触发频率限流", dropLast === 429, String(dropLast));
}

async function main() {
  codeShapeTests();
  await mintTests();
  await dropTests();
  await quotaTests();
  await roundTripTests();
  await throttleTests();
  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
