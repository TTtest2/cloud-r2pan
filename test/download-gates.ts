/**
 * 下载闸门测试 —— 校验"占用下载名额"一定发生在所有鉴权/限流闸门之后：
 * 被密码、验证码、流量限额、重复下载拦掉的请求，都不能白烧 max_downloads。
 * 顺带覆盖 OAuth 回跳白名单（开放重定向）。
 *
 * 运行：
 *   npx esbuild test/download-gates.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/download-gates.mjs
 *   node .dev/download-gates.mjs
 */
import { handleDownload, handleDirectDownload } from "../src/public";
import { localRedirect } from "../src/oauth_handlers";
import { hmacHex } from "../src/crypto";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const INC = /download_count = download_count \+ 1/;
const ADMIN_SECRET = "test-admin-secret";
const FILE_ROW = { id: "F1", key: "files/F1", name: "report.pdf", size: 64, mime: "application/pdf" };

/* ═══════════ 路由式假 D1 ═══════════ */

interface Route {
  re: RegExp;
  first?: () => any;
  all?: () => any;
  run?: () => { changes: number };
}

class FakeD1 {
  readonly sqlLog: string[] = [];
  increments = 0;

  constructor(private routes: Route[]) {}

  private resolve(sql: string): Route {
    const r = this.routes.find((x) => x.re.test(sql));
    if (!r) throw new Error("未覆盖的 SQL: " + sql);
    return r;
  }

  indexOf(re: RegExp): number {
    return this.sqlLog.findIndex((s) => re.test(s));
  }

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
        self.sqlLog.push(norm);
        const r = self.resolve(norm);
        return r.first ? r.first() : null;
      },
      async all() {
        self.sqlLog.push(norm);
        const r = self.resolve(norm);
        return { results: r.all ? r.all() : [], success: true, meta: {} };
      },
      async run() {
        self.sqlLog.push(norm);
        const r = self.resolve(norm);
        const changes = r.run ? r.run().changes : 1;
        if (INC.test(norm)) self.increments++;
        return { success: true, meta: { changes } };
      },
    };
    return stmt;
  }

  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }
}

interface Scenario {
  settings?: Record<string, string>;
  share?: Record<string, unknown> | null;
  direct?: Record<string, unknown> | null;
  dupCount?: number;
  slotAvailable?: boolean;
}

function harness(sc: Scenario) {
  invalidateSettingsCache();
  const settings: Record<string, string> = {
    turnstile_mode: "off",
    traffic_limit_bytes: "0",
    max_downloads_per_ip: "0",
    oauth_enabled: "0",
    admin_ips: "",
    ...sc.settings,
  };
  const db = new FakeD1([
    {
      re: /SELECT key, value FROM settings/,
      all: () => Object.entries(settings).map(([key, value]) => ({ key, value })),
    },
    { re: /FROM banned_ips WHERE ip/, first: () => null },
    { re: /FROM shares s JOIN files f/, first: () => ({ ...FILE_ROW, ...(sc.share ?? {}) }) },
    { re: /FROM direct_links dl JOIN files f/, first: () => ({ ...FILE_ROW, ...(sc.direct ?? {}) }) },
    {
      re: /UPDATE (shares|direct_links) SET download_count/,
      run: () => ({ changes: sc.slotAvailable === false ? 0 : 1 }),
    },
    { re: /SELECT COUNT\(\*\) AS c FROM download_logs/, first: () => ({ c: sc.dupCount ?? 0 }) },
    {
      re: /INSERT INTO settings|UPDATE settings|INSERT INTO traffic_stats|INSERT INTO download_logs|INSERT INTO banned_ips/,
      run: () => ({ changes: 1 }),
    },
  ]);
  const r2 = {
    async get() {
      return {
        body: new Uint8Array(64),
        size: 64,
        httpEtag: "etag1",
        httpMetadata: { contentType: "application/pdf" },
      };
    },
    async head() {
      return { size: 64, httpMetadata: { contentType: "application/pdf" } };
    },
  };
  const waited: Promise<any>[] = [];
  const ctx = {
    waitUntil: (p: Promise<any>) => void waited.push(Promise.resolve(p)),
    passThroughErrorOnCatch: () => {},
    props: {},
  };
  const env: any = { db, r2, admin: ADMIN_SECRET };
  return { db, env, ctx: ctx as any, waited };
}

async function signToken(token: string): Promise<string> {
  const exp = Date.now() + 60_000;
  return `${exp}.${await hmacHex(ADMIN_SECRET, `${token}:${exp}`)}`;
}

function shareReq(token: string, t?: string): Request {
  return new Request(`https://pan.test/s/${token}/download${t ? `?t=${t}` : ""}`, {
    headers: { "cf-connecting-ip": "203.0.113.7", "user-agent": "pytest" },
  });
}

function directReq(): Request {
  return new Request("https://pan.test/d/DL1", { headers: { "cf-connecting-ip": "203.0.113.9" } });
}

/** 走完所有分支后收集后台任务，并断言名额只被 UPDATE 过一次 */
async function finish(h: ReturnType<typeof harness>) {
  await Promise.all(h.waited);
  return h.db;
}

/* ═══════════ 用例 ═══════════ */

async function main() {
  console.log("\n[1] 分享下载：闸门未过时不得占用名额");
  {
    const h = harness({ share: { max_downloads: 5, download_count: 0, password_hash: "h" } });
    const res = await handleDownload(shareReq("S1"), h.env, h.ctx, "S1");
    check("缺密码令牌 → 403", res.status === 403, String(res.status));
    check("未扣减 max_downloads", h.db.increments === 0, String(h.db.increments));
    await finish(h);
  }
  {
    const h = harness({ share: { max_downloads: 3, download_count: 3 } });
    const res = await handleDownload(shareReq("S1"), h.env, h.ctx, "S1");
    check("名额已满 → 410", res.status === 410, String(res.status));
    check("名额已满时不再 UPDATE", h.db.increments === 0);
    await finish(h);
  }
  {
    const h = harness({
      settings: { turnstile_mode: "on_download" },
      share: { max_downloads: 5, download_count: 0 },
    });
    h.env.turnstile_secret = "sk-test";
    const res = await handleDownload(shareReq("S1"), h.env, h.ctx, "S1");
    check("缺人机验证码 → 403", res.status === 403, String(res.status));
    check("验证码未过时不扣名额", h.db.increments === 0);
    await finish(h);
  }
  {
    const h = harness({
      settings: { traffic_limit_bytes: "1", traffic_used_bytes: "999" },
      share: { max_downloads: 5, download_count: 0 },
    });
    const res = await handleDownload(shareReq("S1"), h.env, h.ctx, "S1");
    check("本月流量超限 → 503", res.status === 503, String(res.status));
    check("流量超限时不扣名额", h.db.increments === 0);
    await finish(h);
  }
  {
    const h = harness({
      settings: { max_downloads_per_ip: "2", count_window_hours: "24" },
      dupCount: 2,
      share: { max_downloads: 5, download_count: 0 },
    });
    const res = await handleDownload(shareReq("S1"), h.env, h.ctx, "S1");
    check("同 IP 重复下载 → 403", res.status === 403, String(res.status));
    check("重复下载被拦截时不扣名额", h.db.increments === 0);
    await finish(h);
  }

  console.log("\n[2] 全部闸门通过后才扣一次名额");
  {
    const h = harness({
      settings: { max_downloads_per_ip: "5", count_window_hours: "24" },
      share: { max_downloads: 5, download_count: 0, password_hash: "h" },
    });
    const res = await handleDownload(shareReq("S1", await signToken("S1")), h.env, h.ctx, "S1");
    check("带合法令牌 → 200 并推流", res.status === 200, String(res.status));
    check("恰好扣一次", h.db.increments === 1, String(h.db.increments));
    const incIdx = h.db.indexOf(INC);
    const dupIdx = h.db.indexOf(/SELECT COUNT\(\*\) AS c FROM download_logs/);
    check("扣次排在重复下载检查之后", dupIdx >= 0 && incIdx > dupIdx, `inc=${incIdx} dup=${dupIdx}`);
    await finish(h);
  }
  {
    const h = harness({ share: { max_downloads: 1, download_count: 0 }, slotAvailable: false });
    const res = await handleDownload(shareReq("S1"), h.env, h.ctx, "S1");
    check("并发抢不到最后一个名额 → 410 且不推流", res.status === 410, String(res.status));
    await finish(h);
  }

  console.log("\n[3] 直链下载：同样只在闸门之后扣次");
  {
    const h = harness({
      settings: { max_downloads_per_ip: "1", count_window_hours: "0" },
      dupCount: 1,
      direct: { max_downloads: 9, download_count: 0 },
    });
    const res = await handleDirectDownload(directReq(), h.env, h.ctx, "DL1");
    check("直链重复下载 → 403", res.status === 403, String(res.status));
    check("直链被拦截时不扣名额", h.db.increments === 0);
    await finish(h);
  }
  {
    const h = harness({
      settings: { max_downloads_per_ip: "3", count_window_hours: "24" },
      direct: { max_downloads: 9, download_count: 0 },
    });
    const res = await handleDirectDownload(directReq(), h.env, h.ctx, "DL1");
    check("直链正常下载 → 200", res.status === 200, String(res.status));
    check("直链恰好扣一次", h.db.increments === 1, String(h.db.increments));
    const incIdx = h.db.indexOf(INC);
    const dupIdx = h.db.indexOf(/SELECT COUNT\(\*\) AS c FROM download_logs/);
    check("直链扣次排在限流之后", dupIdx >= 0 && incIdx > dupIdx, `inc=${incIdx} dup=${dupIdx}`);
    await finish(h);
  }

  console.log("\n[4] OAuth 回跳白名单（防开放重定向）");
  {
    check("站内路径保留 query", localRedirect("/s/abc?x=1") === "/s/abc?x=1", localRedirect("/s/abc?x=1"));
    check("外部绝对 URL → /", localRedirect("https://evil.example/phish") === "/");
    check("协议相对 //host → /", localRedirect("//evil.example") === "/");
    check("反斜杠变体 → /", localRedirect("/\\evil.example") === "/", localRedirect("/\\evil.example"));
    check("javascript: → /", localRedirect("javascript:alert(1)") === "/");
    check("空值 → /", localRedirect("") === "/");
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
