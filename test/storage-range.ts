/**
 * 分段读取（Range）适配测试 —— 线上真实事故回归：
 *   分享下载返回 206 + 正确的 Content-Range，但 body 是**整个对象**。
 * 根因在 provider 适配层：R2 的分片选项必须嵌在 `options.range` 里，
 * 顶层 `{offset,length}` 是老写法，运行时不认识就直接忽略（既不报错也不分片）。
 * Miniflare 与手写假桶都会照单全收，所以只有断言"传出去的选项形状 + 回来的字节"才拦得住。
 *
 * 运行：
 *   npx esbuild test/storage-range.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/storage-range.mjs
 *   node .dev/storage-range.mjs
 */
import { createR2Provider, createS3Provider, type S3Config } from "../src/storage";

let failures = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

/** 37 字节可预测内容：A..Z 循环 */
const DATA = new Uint8Array(37).map((_, i) => 65 + (i % 26));
const TEXT = new TextDecoder();
const slice = (from: number, to: number) => TEXT.decode(DATA.slice(from, to));

function streamOf(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new Response(bytes).body!;
}

/* ═══════════ [1] R2：模拟真实运行时的 options.range 契约 ═══════════ */

type Call = { key: string; options: any };

function fakeR2Bucket(calls: Call[]) {
  return {
    async get(key: string, options?: any) {
      calls.push({ key, options });
      // 只认 options.range —— 其他顶层键（如老的 offset/length 写法）一律忽略，
      // 与 Cloudflare 运行时一致：未知选项静默不生效，而不是抛错。
      const r = options && options.range;
      let start = 0;
      let end = DATA.length;
      if (r) {
        start = r.offset ?? 0;
        if (r.length !== undefined) end = Math.min(DATA.length, start + r.length);
      }
      return {
        body: streamOf(DATA.slice(start, end)),
        size: DATA.length,
        httpEtag: "etag-r2",
        httpMetadata: { contentType: "text/plain" },
      };
    },
  };
}

async function readBody(provider: { get(k: string, r?: any): Promise<any> }, key: string, range?: any) {
  const obj = await provider.get(key, range);
  const bytes = new Uint8Array(await new Response(obj.body as ReadableStream).arrayBuffer());
  return { text: TEXT.decode(bytes), size: obj.size, etag: obj.etag, contentType: obj.contentType };
}

async function r2Tests() {
  console.log("\n[1] R2 provider 的分段读取");
  const calls: Call[] = [];
  const prov = createR2Provider(fakeR2Bucket(calls) as any);

  const full = await readBody(prov, "files/F1");
  check("无 range 时取整对象", full.text === slice(0, 37) && calls[0].options === undefined, JSON.stringify(calls[0].options));

  const mid = await readBody(prov, "files/F1", { offset: 10, length: 10 });
  const o1 = calls[1].options;
  check("offset+length 走 options.range", !!o1 && !!o1.range && o1.range.offset === 10 && o1.range.length === 10, JSON.stringify(o1));
  check(
    "不把 offset/length 摊平在顶层（线上被静默忽略）",
    o1 && Object.keys(o1).join() === "range",
    Object.keys(o1 || {}).join()
  );
  check("body 只有被请求的那 10 字节", mid.text === slice(10, 20) && mid.text.length === 10, mid.text);

  const tail = await readBody(prov, "files/F1", { offset: 20 });
  const o2 = calls[2].options;
  check("只给 offset → range.offset（读到尾）", !!o2 && !!o2.range && o2.range.offset === 20 && o2.range.length === undefined, JSON.stringify(o2));
  check("后缀分片内容正确", tail.text === slice(20, 37), tail.text);

  check("contentType/etag 仍从 httpMetadata 来", mid.contentType === "text/plain" && mid.etag === "etag-r2", mid.contentType + "/" + mid.etag);
}

/* ═══════════ [2] S3：必须真的发出 Range 头 ═══════════ */

const CFG: S3Config = {
  endpoint: "https://s3.example.com",
  region: "auto",
  bucket: "my-bucket",
  accessKeyId: "AKID",
  secretAccessKey: "SECRET",
  addressingStyle: "path",
};

async function s3Tests() {
  console.log("\n[2] S3 provider 的分段读取");
  const seen: { url: string; headers: Record<string, string> }[] = [];
  globalThis.fetch = (async (url: any, init: any) => {
    const headers = Object.fromEntries(
      Object.entries(init.headers as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])
    );
    seen.push({ url: String(url), headers });
    const raw = headers["range"] || "";
    const m = /^bytes=(\d+)-(\d*)$/.exec(raw);
    let bytes = DATA;
    if (raw && m) {
      const from = Number(m[1]);
      const to = m[2] === "" ? DATA.length : Number(m[2]) + 1;
      bytes = DATA.slice(from, to);
    }
    return new Response(streamOf(bytes), {
      status: raw ? 206 : 200,
      headers: { "content-type": "text/plain", "content-length": String(bytes.length), etag: '"etag-s3"' },
    });
  }) as any;

  const prov = createS3Provider(CFG);
  const a = await readBody(prov, "files/F1", { offset: 10, length: 10 });
  check("闭区间 Range 头正确", seen[0].headers["range"] === "bytes=10-19", seen[0].headers["range"]);
  check("S3 分段只回那 10 字节", a.text === slice(10, 20), a.text);

  const b = await readBody(prov, "files/F1", { offset: 20 });
  check("开区间 Range 头正确", seen[1].headers["range"] === "bytes=20-", seen[1].headers["range"]);
  check("S3 后缀分片内容正确", b.text === slice(20, 37), b.text);

  await readBody(prov, "files/F1");
  check("无 range 时不发 Range 头", seen[2].headers["range"] === undefined, JSON.stringify(seen[2].headers["range"]));
}

async function main() {
  await r2Tests();
  await s3Tests();
  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
