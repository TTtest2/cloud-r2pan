/**
 * S3 签名对照测试 —— 用 node:crypto 按 AWS SigV4 规范独立复算一遍签名，
 * 与 createS3Provider 产出的 Authorization 比对，确保两者一致。
 *
 * 运行：
 *   npx esbuild test/s3-signer.ts --bundle --platform=node --format=esm --outfile=.dev/s3-signer.mjs
 *   node .dev/s3-signer.mjs
 */
import { createHmac, createHash } from "node:crypto";
import { createS3Provider, type S3Config } from "../src/storage";

const CFG: S3Config = {
  endpoint: "https://s3.us-west-002.backblazeb2.com",
  region: "us-west-002",
  bucket: "my-bucket",
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  addressingStyle: "path",
};

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
}

const captured: Captured[] = [];

function fakeFetch(handler: (req: Captured) => Response) {
  return (input: any, init: any = {}) => {
    const headers: Record<string, string> = {};
    for (const [k, v] of new Headers(init.headers ?? {})) headers[k] = v;
    const rec = { url: String(input), method: init.method ?? "GET", headers };
    captured.push(rec);
    return Promise.resolve(handler(rec));
  };
}

const EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/** 独立实现（直接照 AWS 文档的 canonical request 结构），不复用被测代码 */
function referenceSignature(
  cfg: S3Config,
  method: string,
  urlStr: string,
  headers: Record<string, string>,
  payloadHash: string,
  amzDate: string
): { signature: string; signedHeaders: string; canonical: string } {
  const url = new URL(urlStr);
  const enc = (s: string) =>
    encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
  const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  // pathname 已是百分号编码，先解码到原始字符再重新编码，避免二次编码
  const canonicalUri = url.pathname
    .split("/")
    .map((seg) => enc(decodeURIComponent(seg)))
    .join("/");
  const sorted = [...url.searchParams.entries()]
    .map(([k, v]) => [enc(k), enc(v)] as [string, string])
    .sort((a, b) => (a[0] === b[0] ? cmp(a[1], b[1]) : cmp(a[0], b[0])))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v.trim();
  const names = Object.keys(lower).sort();
  const canonicalHeaders = names.map((n) => `${n}:${lower[n]}\n`).join("");
  const signedHeaders = names.join(";");
  const canonical = [method, canonicalUri, sorted, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    createHash("sha256").update(canonical).digest("hex"),
  ].join("\n");
  const h = (key: Buffer | string, data: string) =>
    createHmac("sha256", key).update(data, "utf8").digest();
  let signing = h(Buffer.from("AWS4" + cfg.secretAccessKey, "utf8"), dateStamp);
  signing = createHmac("sha256", signing).update(cfg.region).digest();
  signing = createHmac("sha256", signing).update("s3").digest();
  signing = createHmac("sha256", signing).update("aws4_request").digest();
  const signature = createHmac("sha256", signing).update(stringToSign).digest("hex");
  return { signature, signedHeaders, canonical };
}

function authHeaderParts(authorization: string) {
  const credential = /Credential=([^,]+),/.exec(authorization)?.[1] ?? "";
  const signedHeaders = /SignedHeaders=([^,]+),/.exec(authorization)?.[1] ?? "";
  const signature = /Signature=([0-9a-f]+)$/.exec(authorization)?.[1] ?? "";
  return { credential, signedHeaders, signature };
}

let failures = 0;
function check(name: string, cond: boolean, detail = "") {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

/** 断言：被签名并发送的 Host 必须就是实际请求的 host */
function assertHostMatchesUrl(name: string, rec: Captured) {
  const host = new URL(rec.url).host;
  check(`${name}: Host 头与请求 URL 一致`, rec.headers["host"] === host, `Host=${rec.headers["host"]} URL=${host}`);
}

/** 断言：Authorization 里的 Signature 与独立实现一致 */
function assertSignatureMatches(name: string, rec: Captured, cfg: S3Config) {
  const auth = rec.headers["authorization"] ?? "";
  const { credential, signedHeaders, signature } = authHeaderParts(auth);
  check(`${name}: 带 Authorization 头`, !!auth && !!signature, auth.slice(0, 60));
  const amzDate = rec.headers["x-amz-date"];
  check(`${name}: 有 x-amz-date`, !!amzDate, String(amzDate));
  const payloadHash = rec.headers["x-amz-content-sha256"] ?? EMPTY_SHA;
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec.headers)) {
    if (k === "authorization") continue;
    if (signedHeaders.split(";").includes(k.toLowerCase())) headers[k] = v;
  }
  const ref = referenceSignature(cfg, rec.method, rec.url, headers, payloadHash, amzDate);
  check(`${name}: 签名与独立实现一致`, ref.signature === signature, `ref=${ref.signature} got=${signature}`);
  check(`${name}: SignedHeaders 一致`, ref.signedHeaders === signedHeaders, `ref=${ref.signedHeaders} got=${signedHeaders}`);
  const expectedScope = `${amzDate.slice(0, 8)}/${cfg.region}/s3/aws4_request`;
  check(`${name}: Credential 前缀正确`, credential === `${cfg.accessKeyId}/${expectedScope}`, credential);
}

async function main() {
  const ok = () => new Response("", { status: 200, headers: { etag: '"abc"' } });

  console.log("\n[1] path-style：PUT 文本 / Range GET / HEAD / DELETE");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok) as any;
  const pathProv = createS3Provider(CFG);
  const textBody = new TextEncoder().encode("hello s3");
  const putRes = await pathProv.put("files/文档 1.txt", textBody, {
    contentType: "text/plain",
    contentDisposition: "attachment",
  });
  await pathProv.get("files/文档 1.txt", { offset: 100, length: 50 });
  await pathProv.head("files/文档 1.txt");
  await pathProv.delete("files/文档 1.txt");
  for (const rec of captured) {
    assertHostMatchesUrl(rec.method, rec);
    assertSignatureMatches(rec.method, rec, CFG);
  }
  check("PUT 回填真实字节数", putRes.size === textBody.byteLength, String(putRes.size));
  check(
    "请求 URL 为 path-style（bucket 在路径里）",
    captured[0].url.includes("/my-bucket/files/"),
    captured[0].url
  );
  check(
    "二进制体按字节做 payload hash（非 UTF-8 往返）",
    captured[0].headers["x-amz-content-sha256"] ===
      createHash("sha256").update(textBody).digest("hex"),
    captured[0].headers["x-amz-content-sha256"]
  );

  console.log("\n[2] virtual-host-style：bucket 必须在 Host 里");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok) as any;
  const vhostProv = createS3Provider({ ...CFG, addressingStyle: "virtual" });
  await vhostProv.put("a/b.bin", new Uint8Array([0, 255, 137, 80, 4, 16, 255, 254]), {
    contentType: "application/octet-stream",
  });
  const vrec = captured[0];
  assertHostMatchesUrl("virtual PUT", vrec);
  assertSignatureMatches("virtual PUT", vrec, { ...CFG, addressingStyle: "virtual" });
  check(
    "virtual Host 含 bucket 前缀",
    vrec.headers["host"] === `my-bucket.s3.us-west-002.backblazeb2.com`,
    vrec.headers["host"]
  );
  check("virtual 路径不含 bucket", !vrec.url.includes("/my-bucket/"), vrec.url);
  check(
    "二进制字节不被 TextDecoder 破坏",
    vrec.headers["x-amz-content-sha256"] ===
      createHash("sha256").update(Buffer.from([0, 255, 137, 80, 4, 16, 255, 254])).digest("hex"),
    vrec.headers["x-amz-content-sha256"]
  );

  console.log("\n[3] 流式上传：必须带 Content-Length 且用 UNSIGNED-PAYLOAD");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok) as any;
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(new Uint8Array([1, 2, 3]));
      c.close();
    },
  });
  const streamRes = await pathProv.put("stream.bin", stream, { contentLength: 3 });
  check("流式 PUT 使用 UNSIGNED-PAYLOAD", captured[0].headers["x-amz-content-sha256"] === "UNSIGNED-PAYLOAD");
  check("流式 PUT 显式 Content-Length", captured[0].headers["content-length"] === "3", String(captured[0].headers["content-length"]));
  check("流式 PUT 采用 hint 作为 size", streamRes.size === 3, String(streamRes.size));
  assertSignatureMatches("stream PUT", captured[0], CFG);

  console.log("\n[4] 流式上传无 hint：回读 HEAD 补真实 size");
  captured.length = 0;
  globalThis.fetch = fakeFetch(() => new Response("", { status: 200, headers: { etag: '"x"', "content-length": "4096" } })) as any;
  const noHint = await pathProv.put(
    "stream2.bin",
    new ReadableStream({ start(c) { c.enqueue(new Uint8Array([1])); c.close(); } }),
    { contentType: "application/octet-stream" }
  );
  check("无 hint 时通过 HEAD 得到 size", noHint.size === 4096, String(noHint.size));

  console.log("\n[5] endpoint 带子路径 / http 协议");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok) as any;
  const subProv = createS3Provider({ ...CFG, endpoint: "http://minio.local:9000/gw", pathPrefix: "p1" });
  await subProv.get("k.txt");
  assertHostMatchesUrl("subpath GET", captured[0]);
  assertSignatureMatches("subpath GET", captured[0], { ...CFG, endpoint: "http://minio.local:9000/gw", pathPrefix: "p1" });
  check("URL 保留 endpoint 子路径与前缀", captured[0].url === "http://minio.local:9000/gw/p1/my-bucket/k.txt", captured[0].url);
  check("http endpoint 的 Host 带端口", captured[0].headers["host"] === "minio.local:9000", captured[0].headers["host"]);

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
