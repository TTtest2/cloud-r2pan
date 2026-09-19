/**
 * 内联预览测试 —— ?inline=1 只在 MIME 白名单内生效，且必须：
 *   - 非白名单（尤其是 text/html、image/svg+xml、octet-stream）永远退回 attachment
 *   - inline 响应换掉默认那条 default-src 'none' 的下载 CSP，否则媒体分片会被自己挡死
 *   - 不携带 inline 参数时行为与改动前完全一致（attachment）
 *
 * 运行：
 *   npx esbuild test/preview-inline.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/preview-inline.mjs
 *   node .dev/preview-inline.mjs
 */
import { applyDisposition, canInline, inlineCsp, wantsInline } from "../src/preview";
import { handleDownload } from "../src/public";
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

const ADMIN_SECRET = "test-admin-secret";

/* ═══════════ [1] 白名单本身 ═══════════ */

function unitTests() {
  console.log("\n[1] MIME 白名单");
  check("pdf 可内联", canInline("application/pdf"));
  check("png 可内联", canInline("image/png"));
  check("mp4 可内联", canInline("video/mp4"));
  check("mp3 可内联", canInline("audio/mpeg"));
  check("纯文本可内联", canInline("text/plain;charset=utf-8"), "带 charset 参数也要认");
  check("html 不可内联", !canInline("text/html"));
  check("xhtml 不可内联", !canInline("application/xhtml+xml"));
  check("svg 不可内联（能嵌脚本）", !canInline("image/svg+xml"));
  check("js 不可内联", !canInline("text/javascript"));
  check("octet-stream 不可内联", !canInline("application/octet-stream"));
  check("空 MIME 不可内联", !canInline(null) && !canInline(undefined) && !canInline(""));

  console.log("\n[2] disposition 与请求参数");
  check("?inline=1 认", wantsInline(new Request("https://pan.test/s/S1/download?inline=1")));
  check("?disposition=inline 认", wantsInline(new Request("https://pan.test/d/DL1?disposition=inline")));
  check("无参数不认", !wantsInline(new Request("https://pan.test/s/S1/download")));
  check("inline=0 不认", !wantsInline(new Request("https://pan.test/s/S1/download?inline=0")));

  const h1 = new Headers();
  const r1 = applyDisposition(h1, { mime: "image/png", name: "a.png", inline: true });
  check("白名单 + 要求内联 → inline", r1.inline && /^inline; /.test(h1.get("content-disposition") ?? ""), h1.get("content-disposition") ?? "");
  const h2 = new Headers();
  const r2 = applyDisposition(h2, { mime: "text/html", name: "x.html", inline: true });
  check("黑名单强行要求 → 退回 attachment", !r2.inline && /^attachment; /.test(h2.get("content-disposition") ?? ""), h2.get("content-disposition") ?? "");
  const h3 = new Headers();
  applyDisposition(h3, { mime: "image/png", name: "图片 报告.png", inline: true });
  const cd = h3.get("content-disposition") ?? "";
  check("文件名走 RFC 5987 编码", cd.includes("filename*=UTF-8''") && !cd.includes("图片"), cd);
  check("inline CSP 不放脚本", !/script-src/.test(inlineCsp()) && inlineCsp().includes("default-src 'none'"), inlineCsp());
}

/* ═══════════ [3] 端到端：真过一遍 handleDownload ═══════════ */

const FILE_ROW = { id: "F1", key: "files/F1", name: "report.pdf", size: 64, mime: "application/pdf" };

class FakeD1 {
  increments = 0;
  constructor(private routes: { re: RegExp; first?: () => any; all?: () => any; run?: () => { changes: number } }[]) {}
  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    const self = this;
    const stmt: any = {
      bind() { return stmt; },
      async first() {
        const r = self.routes.find((x) => x.re.test(norm));
        return r?.first ? r.first() : null;
      },
      async all() {
        const r = self.routes.find((x) => x.re.test(norm));
        return { results: r?.all ? r.all() : [], success: true, meta: {} };
      },
      async run() {
        if (/download_count = download_count \+ 1/.test(norm)) self.increments++;
        const r = self.routes.find((x) => x.re.test(norm));
        const changes = r?.run ? 1 : 0;
        return { changes, meta: { changes }, success: true };
      },
    };
    return stmt;
  }
  async batch(stmts: any[]) { for (const s of stmts) await s.run(); return []; }
}

function harness() {
  invalidateSettingsCache();
  const settings: Record<string, string> = {
    turnstile_mode: "off",
    traffic_limit_bytes: "0",
    max_downloads_per_ip: "0",
    oauth_enabled: "0",
    admin_ips: "",
  };
  const db = new FakeD1([
    { re: /SELECT key, value FROM settings/, all: () => Object.entries(settings).map(([key, value]) => ({ key, value })) },
    { re: /FROM banned_ips WHERE ip/, first: () => null },
    { re: /FROM shares s JOIN files f/, first: () => ({ ...FILE_ROW, max_downloads: 5, download_count: 0 }) },
    { re: /UPDATE shares SET download_count/, run: () => ({ changes: 1 }) },
    { re: /SELECT COUNT\(\*\) AS c FROM download_logs/, first: () => ({ c: 0 }) },
    { re: /INSERT INTO|UPDATE settings/, run: () => ({ changes: 1 }) },
  ]);
  const r2 = {
    async get() {
      return { body: new Uint8Array(64), size: 64, httpEtag: "etag1", httpMetadata: { contentType: "application/pdf" } };
    },
    async head() { return { size: 64, httpMetadata: { contentType: "application/pdf" } }; },
  };
  const waited: Promise<any>[] = [];
  const ctx = { waitUntil: (p: Promise<any>) => void waited.push(Promise.resolve(p)), passThroughOnException: () => {}, props: {} };
  return { db, env: { db, r2, admin: ADMIN_SECRET } as any, ctx: ctx as any, waited };
}

async function integrationTests() {
  console.log("\n[3] 分享下载端到端");
  const t = `${Date.now() + 60_000}.${await hmacHex(ADMIN_SECRET, `S1:${Date.now() + 60_000}`)}`;
  const mk = (query: string) =>
    new Request(`https://pan.test/s/S1/download${query}`, { headers: { "cf-connecting-ip": "203.0.113.7" } });

  const plain = harness();
  const r0 = await handleDownload(mk(`?t=${t}`), plain.env, plain.ctx, "S1");
  check("默认仍是 attachment", r0.status === 200 && /^attachment; /.test(r0.headers.get("content-disposition") ?? ""), r0.headers.get("content-disposition") ?? "");
  check("下载 CSP 禁脚本", (r0.headers.get("content-security-policy") ?? "").includes("script-src 'none'"), r0.headers.get("content-security-policy") ?? "");
  await Promise.all(plain.waited);

  const inlineH = harness();
  const r1 = await handleDownload(mk(`?t=${t}&inline=1`), inlineH.env, inlineH.ctx, "S1");
  const cd = r1.headers.get("content-disposition") ?? "";
  check("inline=1 且 PDF → inline", r1.status === 200 && /^inline; /.test(cd), cd);
  check("inline 换掉了 default-src 'none' 下载 CSP", !(r1.headers.get("content-security-policy") ?? "").includes("script-src 'none'"), r1.headers.get("content-security-policy") ?? "");
  check("inline 响应仍带 nosniff", (r1.headers.get("x-content-type-options") ?? "").toLowerCase() === "nosniff");
  check("inline 预览照样占用下载名额", inlineH.db.increments === 1, String(inlineH.db.increments));
  await Promise.all(inlineH.waited);

  console.log("\n[4] Range 与 inline 共存");
  const rangeH = harness();
  const r3 = await handleDownload(
    new Request(`https://pan.test/s/S1/download?t=${t}&inline=1`, {
      headers: { "cf-connecting-ip": "203.0.113.7", range: "bytes=0-15" },
    }),
    rangeH.env,
    rangeH.ctx,
    "S1"
  );
  check("内联预览支持 206 分段", r3.status === 206, String(r3.status));
  check("206 上仍是 inline", /^inline; /.test(r3.headers.get("content-disposition") ?? ""), r3.headers.get("content-disposition") ?? "");
  check("206 带 content-range", r3.headers.get("content-range") === "bytes 0-15/64", r3.headers.get("content-range") ?? "");
  await Promise.all(rangeH.waited);
}

async function main() {
  unitTests();
  await integrationTests();
  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
