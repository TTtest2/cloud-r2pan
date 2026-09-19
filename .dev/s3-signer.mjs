// test/s3-signer.ts
import { createHmac, createHash } from "node:crypto";

// src/settings.ts
var DEFAULT_SETTINGS = {
  siteTitle: "cloud-r2pan",
  trafficLimitBytes: 10 * 1024 ** 3,
  // 10 GB
  trafficUsedBytes: 0,
  trafficMonth: "",
  maxDownloadsPerIp: 2,
  countWindowHours: 24,
  autoBan: true,
  banHours: 24,
  totpEnabled: false,
  totpSecretCipher: null,
  totpRecoveryHash: null,
  turnstileMode: "off",
  turnstileThreshold: 5,
  turnstileSitekeyOverride: null,
  turnstileSecretCipher: null,
  // OAuth2
  oauthEnabled: false,
  oauthProvider: "github",
  oauthClientId: "",
  oauthClientSecretCipher: null,
  oauthScope: "user:email",
  oauthCustomAuthorizeUrl: "",
  oauthCustomTokenUrl: "",
  oauthCustomUserinfoUrl: "",
  oauthCustomTokenField: "access_token",
  adminIps: "",
  // 下载市场
  homeRedirectMarket: false,
  // 激活码浮动按钮
  codesFloatingButtonEnabled: true,
  codesFloatingButtonPosition: "top-right",
  // 存储后端 —— 默认 R2（向后兼容）
  storageProvider: "r2",
  s3Endpoint: null,
  s3Region: null,
  s3Bucket: null,
  s3AccessKeyId: null,
  s3SecretKeyCipher: null,
  s3AddressingStyle: "path",
  // WebDAV —— 默认关闭，启用后通过 Basic Auth 保护
  webdavEnabled: false,
  webdavUsername: "webdav",
  webdavPasswordHash: null,
  webdavRootPath: "/"
};

// src/storage.ts
function encodeURIComponentStrict(s) {
  return encodeURIComponent(s).replace(/'/g, "%27").replace(/\(/g, "%28").replace(/\)/g, "%29").replace(/\*/g, "%2A");
}
function buildCanonicalRequest(method, path, query, headers, bodyHash) {
  const sortedHeaderNames = Object.keys(headers).map((k) => k.toLowerCase()).sort();
  const signedHeaders = sortedHeaderNames.join(";");
  const lowercased = {};
  for (const [k, v] of Object.entries(headers)) lowercased[k.toLowerCase()] = v.trim();
  const headerLines = sortedHeaderNames.map((name) => `${name}:${lowercased[name]}
`).join("");
  let canonicalQuery = "";
  if (query) {
    const pairs = [];
    query.forEach((v, k) => pairs.push([k, v]));
    const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
    pairs.sort(
      (a, b) => a[0] === b[0] ? cmp(encodeURIComponentStrict(a[1]), encodeURIComponentStrict(b[1])) : cmp(encodeURIComponentStrict(a[0]), encodeURIComponentStrict(b[0]))
    );
    canonicalQuery = pairs.map(([k, v]) => `${encodeURIComponentStrict(k)}=${encodeURIComponentStrict(v)}`).join("&");
  }
  const canonical = [
    method,
    path,
    canonicalQuery,
    headerLines,
    signedHeaders,
    bodyHash
  ].join("\n");
  return { canonical, signedHeaders };
}
function toArrayBuffer(data) {
  if (data instanceof Uint8Array) return data.slice().buffer;
  return data;
}
async function hmacSha256(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}
async function sha256Hex(data) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sha256HexBytes(data) {
  return bufToHex(await crypto.subtle.digest("SHA-256", toArrayBuffer(data)));
}
function bufToHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function deriveSigningKey(secret, date, region) {
  const kDate = await hmacSha256(new TextEncoder().encode("AWS4" + secret), date);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, "s3");
  return await hmacSha256(kService, "aws4_request");
}
async function signS3Request(cfg, method, s3Key, query, headers, bodyHash, now) {
  const amzDate = now.toISOString().replace(/[-:]/g, "").slice(0, 19) + "Z";
  const dateStamp = amzDate.slice(0, 8);
  const baseUrl = cfg.endpoint.replace(/\/+$/, "");
  const schemeSep = baseUrl.indexOf("://");
  const scheme = schemeSep >= 0 ? baseUrl.slice(0, schemeSep + 3) : "https://";
  const endpointHost = (schemeSep >= 0 ? baseUrl.slice(schemeSep + 3) : baseUrl).split("/")[0];
  const endpointPath = "/" + (schemeSep >= 0 ? baseUrl.slice(schemeSep + 3) : baseUrl).split("/").slice(1).join("/");
  const prefix = cfg.pathPrefix ? "/" + cfg.pathPrefix.replace(/^\/+|\/+$/g, "").split("/").map(encodeURIComponentStrict).join("/") : "";
  const encodedKey = s3Key.split("/").map(encodeURIComponentStrict).join("/");
  let host;
  let url;
  if (cfg.addressingStyle === "virtual") {
    host = `${cfg.bucket}.${endpointHost}`;
    url = `${scheme}${host}${endpointPath}${prefix}/${encodedKey}`;
  } else {
    host = endpointHost;
    url = `${baseUrl}${prefix}/${encodeURIComponentStrict(cfg.bucket)}/${encodedKey}`;
  }
  const path = new URL(url).pathname;
  headers["Host"] = host;
  headers["x-amz-date"] = amzDate;
  headers["x-amz-content-sha256"] = bodyHash;
  const { canonical, signedHeaders } = buildCanonicalRequest(method, path, query, headers, bodyHash);
  const canonicalHash = await sha256Hex(canonical);
  const credentialScope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256
${amzDate}
${credentialScope}
${canonicalHash}`;
  const signingKey = await deriveSigningKey(cfg.secretAccessKey, dateStamp, cfg.region);
  const signature = bufToHex(await hmacSha256(signingKey, stringToSign));
  headers["Authorization"] = `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  if (query) url += `?${query.toString()}`;
  return { url, headers };
}
function createS3Provider(cfg) {
  const endpoint = cfg.endpoint.replace(/\/+$/, "");
  const region = cfg.region || "us-east-1";
  const addressing = cfg.addressingStyle || "path";
  async function doFetch(method, key, opts) {
    const amzHeaders = opts.headers ? { ...opts.headers } : {};
    const now = /* @__PURE__ */ new Date();
    let bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let fetchBody = void 0;
    if (opts.body !== void 0) {
      if (typeof opts.body === "string") {
        bodyHash = await sha256Hex(opts.body);
        fetchBody = opts.body;
      } else if (opts.body instanceof ReadableStream) {
        bodyHash = "UNSIGNED-PAYLOAD";
        fetchBody = opts.body;
      } else if (opts.body instanceof Uint8Array || opts.body instanceof ArrayBuffer) {
        const buf = toArrayBuffer(opts.body);
        bodyHash = await sha256HexBytes(buf);
        fetchBody = buf;
      }
    }
    const { url, headers } = await signS3Request(
      { ...cfg, endpoint, region, addressingStyle: addressing },
      method,
      key,
      opts.query,
      amzHeaders,
      bodyHash,
      now
    );
    const resp = await fetch(url, {
      method,
      headers,
      body: fetchBody
    });
    return resp;
  }
  async function headSize(key) {
    const resp = await doFetch("HEAD", key, {});
    if (!resp.ok) return 0;
    return parseInt(resp.headers.get("Content-Length") || "0", 10) || 0;
  }
  return {
    kind: "s3",
    async put(key, body, opts) {
      const headers = {};
      if (opts.contentType) headers["Content-Type"] = opts.contentType;
      if (opts.contentDisposition) headers["Content-Disposition"] = opts.contentDisposition;
      if (typeof opts.contentLength === "number") headers["Content-Length"] = String(opts.contentLength);
      const resp = await doFetch("PUT", key, { body, headers });
      if (!resp.ok) {
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 PUT failed: ${resp.status} ${text}`);
      }
      let size = body instanceof ReadableStream ? 0 : body.byteLength;
      if (!size) size = opts.contentLength ?? 0;
      if (!size) size = await headSize(key);
      return { size, etag: resp.headers.get("etag")?.replace(/"/g, "") || void 0 };
    },
    async get(key, range) {
      const headers = {};
      if (range) {
        let rangeHeader;
        if (range.length !== void 0) {
          rangeHeader = `bytes=${range.offset}-${range.offset + range.length - 1}`;
        } else {
          rangeHeader = `bytes=${range.offset}-`;
        }
        headers["Range"] = rangeHeader;
      }
      const resp = await doFetch("GET", key, { headers });
      if (resp.status === 404 || resp.status === 403) return null;
      if (!resp.ok) {
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 GET failed: ${resp.status} ${text}`);
      }
      const sizeStr = resp.headers.get("Content-Length") || resp.headers.get("x-amz-meta-size") || "0";
      const size = parseInt(sizeStr, 10) || 0;
      return {
        body: resp.body,
        size,
        contentType: resp.headers.get("Content-Type") || "application/octet-stream",
        etag: resp.headers.get("ETag") || ""
      };
    },
    async delete(key) {
      const resp = await doFetch("DELETE", key, { expectNoBody: true });
      if (!resp.ok && resp.status !== 404) {
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 DELETE failed: ${resp.status} ${text}`);
      }
    },
    async head(key) {
      const resp = await doFetch("HEAD", key, {});
      if (resp.status === 404 || resp.status === 403) return null;
      if (!resp.ok) return null;
      const size = parseInt(resp.headers.get("Content-Length") || "0", 10) || 0;
      return {
        size,
        contentType: resp.headers.get("Content-Type") || "application/octet-stream"
      };
    }
  };
}

// test/s3-signer.ts
var CFG = {
  endpoint: "https://s3.us-west-002.backblazeb2.com",
  region: "us-west-002",
  bucket: "my-bucket",
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
  addressingStyle: "path"
};
var captured = [];
function fakeFetch(handler) {
  return (input, init = {}) => {
    const headers = {};
    for (const [k, v] of new Headers(init.headers ?? {})) headers[k] = v;
    const rec = { url: String(input), method: init.method ?? "GET", headers };
    captured.push(rec);
    return Promise.resolve(handler(rec));
  };
}
var EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
function referenceSignature(cfg, method, urlStr, headers, payloadHash, amzDate) {
  const url = new URL(urlStr);
  const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
  const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const canonicalUri = url.pathname.split("/").map((seg) => enc(decodeURIComponent(seg))).join("/");
  const sorted = [...url.searchParams.entries()].map(([k, v]) => [enc(k), enc(v)]).sort((a, b) => a[0] === b[0] ? cmp(a[1], b[1]) : cmp(a[0], b[0])).map(([k, v]) => `${k}=${v}`).join("&");
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v.trim();
  const names = Object.keys(lower).sort();
  const canonicalHeaders = names.map((n) => `${n}:${lower[n]}
`).join("");
  const signedHeaders = names.join(";");
  const canonical = [method, canonicalUri, sorted, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    createHash("sha256").update(canonical).digest("hex")
  ].join("\n");
  const h = (key, data) => createHmac("sha256", key).update(data, "utf8").digest();
  let signing = h(Buffer.from("AWS4" + cfg.secretAccessKey, "utf8"), dateStamp);
  signing = createHmac("sha256", signing).update(cfg.region).digest();
  signing = createHmac("sha256", signing).update("s3").digest();
  signing = createHmac("sha256", signing).update("aws4_request").digest();
  const signature = createHmac("sha256", signing).update(stringToSign).digest("hex");
  return { signature, signedHeaders, canonical };
}
function authHeaderParts(authorization) {
  const credential = /Credential=([^,]+),/.exec(authorization)?.[1] ?? "";
  const signedHeaders = /SignedHeaders=([^,]+),/.exec(authorization)?.[1] ?? "";
  const signature = /Signature=([0-9a-f]+)$/.exec(authorization)?.[1] ?? "";
  return { credential, signedHeaders, signature };
}
var failures = 0;
function check(name, cond, detail = "") {
  if (cond) console.log(`  \x1B[32m\u2713\x1B[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1B[31m\u2717\x1B[0m ${name}${detail ? " \u2014 " + detail : ""}`);
  }
}
function assertHostMatchesUrl(name, rec) {
  const host = new URL(rec.url).host;
  check(`${name}: Host \u5934\u4E0E\u8BF7\u6C42 URL \u4E00\u81F4`, rec.headers["host"] === host, `Host=${rec.headers["host"]} URL=${host}`);
}
function assertSignatureMatches(name, rec, cfg) {
  const auth = rec.headers["authorization"] ?? "";
  const { credential, signedHeaders, signature } = authHeaderParts(auth);
  check(`${name}: \u5E26 Authorization \u5934`, !!auth && !!signature, auth.slice(0, 60));
  const amzDate = rec.headers["x-amz-date"];
  check(`${name}: \u6709 x-amz-date`, !!amzDate, String(amzDate));
  const payloadHash = rec.headers["x-amz-content-sha256"] ?? EMPTY_SHA;
  const headers = {};
  for (const [k, v] of Object.entries(rec.headers)) {
    if (k === "authorization") continue;
    if (signedHeaders.split(";").includes(k.toLowerCase())) headers[k] = v;
  }
  const ref = referenceSignature(cfg, rec.method, rec.url, headers, payloadHash, amzDate);
  check(`${name}: \u7B7E\u540D\u4E0E\u72EC\u7ACB\u5B9E\u73B0\u4E00\u81F4`, ref.signature === signature, `ref=${ref.signature} got=${signature}`);
  check(`${name}: SignedHeaders \u4E00\u81F4`, ref.signedHeaders === signedHeaders, `ref=${ref.signedHeaders} got=${signedHeaders}`);
  const expectedScope = `${amzDate.slice(0, 8)}/${cfg.region}/s3/aws4_request`;
  check(`${name}: Credential \u524D\u7F00\u6B63\u786E`, credential === `${cfg.accessKeyId}/${expectedScope}`, credential);
}
async function main() {
  const ok = () => new Response("", { status: 200, headers: { etag: '"abc"' } });
  console.log("\n[1] path-style\uFF1APUT \u6587\u672C / Range GET / HEAD / DELETE");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok);
  const pathProv = createS3Provider(CFG);
  const textBody = new TextEncoder().encode("hello s3");
  const putRes = await pathProv.put("files/\u6587\u6863 1.txt", textBody, {
    contentType: "text/plain",
    contentDisposition: "attachment"
  });
  await pathProv.get("files/\u6587\u6863 1.txt", { offset: 100, length: 50 });
  await pathProv.head("files/\u6587\u6863 1.txt");
  await pathProv.delete("files/\u6587\u6863 1.txt");
  for (const rec of captured) {
    assertHostMatchesUrl(rec.method, rec);
    assertSignatureMatches(rec.method, rec, CFG);
  }
  check("PUT \u56DE\u586B\u771F\u5B9E\u5B57\u8282\u6570", putRes.size === textBody.byteLength, String(putRes.size));
  check(
    "\u8BF7\u6C42 URL \u4E3A path-style\uFF08bucket \u5728\u8DEF\u5F84\u91CC\uFF09",
    captured[0].url.includes("/my-bucket/files/"),
    captured[0].url
  );
  check(
    "\u4E8C\u8FDB\u5236\u4F53\u6309\u5B57\u8282\u505A payload hash\uFF08\u975E UTF-8 \u5F80\u8FD4\uFF09",
    captured[0].headers["x-amz-content-sha256"] === createHash("sha256").update(textBody).digest("hex"),
    captured[0].headers["x-amz-content-sha256"]
  );
  console.log("\n[2] virtual-host-style\uFF1Abucket \u5FC5\u987B\u5728 Host \u91CC");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok);
  const vhostProv = createS3Provider({ ...CFG, addressingStyle: "virtual" });
  await vhostProv.put("a/b.bin", new Uint8Array([0, 255, 137, 80, 4, 16, 255, 254]), {
    contentType: "application/octet-stream"
  });
  const vrec = captured[0];
  assertHostMatchesUrl("virtual PUT", vrec);
  assertSignatureMatches("virtual PUT", vrec, { ...CFG, addressingStyle: "virtual" });
  check(
    "virtual Host \u542B bucket \u524D\u7F00",
    vrec.headers["host"] === `my-bucket.s3.us-west-002.backblazeb2.com`,
    vrec.headers["host"]
  );
  check("virtual \u8DEF\u5F84\u4E0D\u542B bucket", !vrec.url.includes("/my-bucket/"), vrec.url);
  check(
    "\u4E8C\u8FDB\u5236\u5B57\u8282\u4E0D\u88AB TextDecoder \u7834\u574F",
    vrec.headers["x-amz-content-sha256"] === createHash("sha256").update(Buffer.from([0, 255, 137, 80, 4, 16, 255, 254])).digest("hex"),
    vrec.headers["x-amz-content-sha256"]
  );
  console.log("\n[3] \u6D41\u5F0F\u4E0A\u4F20\uFF1A\u5FC5\u987B\u5E26 Content-Length \u4E14\u7528 UNSIGNED-PAYLOAD");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok);
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(new Uint8Array([1, 2, 3]));
      c.close();
    }
  });
  const streamRes = await pathProv.put("stream.bin", stream, { contentLength: 3 });
  check("\u6D41\u5F0F PUT \u4F7F\u7528 UNSIGNED-PAYLOAD", captured[0].headers["x-amz-content-sha256"] === "UNSIGNED-PAYLOAD");
  check("\u6D41\u5F0F PUT \u663E\u5F0F Content-Length", captured[0].headers["content-length"] === "3", String(captured[0].headers["content-length"]));
  check("\u6D41\u5F0F PUT \u91C7\u7528 hint \u4F5C\u4E3A size", streamRes.size === 3, String(streamRes.size));
  assertSignatureMatches("stream PUT", captured[0], CFG);
  console.log("\n[4] \u6D41\u5F0F\u4E0A\u4F20\u65E0 hint\uFF1A\u56DE\u8BFB HEAD \u8865\u771F\u5B9E size");
  captured.length = 0;
  globalThis.fetch = fakeFetch(() => new Response("", { status: 200, headers: { etag: '"x"', "content-length": "4096" } }));
  const noHint = await pathProv.put(
    "stream2.bin",
    new ReadableStream({ start(c) {
      c.enqueue(new Uint8Array([1]));
      c.close();
    } }),
    { contentType: "application/octet-stream" }
  );
  check("\u65E0 hint \u65F6\u901A\u8FC7 HEAD \u5F97\u5230 size", noHint.size === 4096, String(noHint.size));
  console.log("\n[5] endpoint \u5E26\u5B50\u8DEF\u5F84 / http \u534F\u8BAE");
  captured.length = 0;
  globalThis.fetch = fakeFetch(ok);
  const subProv = createS3Provider({ ...CFG, endpoint: "http://minio.local:9000/gw", pathPrefix: "p1" });
  await subProv.get("k.txt");
  assertHostMatchesUrl("subpath GET", captured[0]);
  assertSignatureMatches("subpath GET", captured[0], { ...CFG, endpoint: "http://minio.local:9000/gw", pathPrefix: "p1" });
  check("URL \u4FDD\u7559 endpoint \u5B50\u8DEF\u5F84\u4E0E\u524D\u7F00", captured[0].url === "http://minio.local:9000/gw/p1/my-bucket/k.txt", captured[0].url);
  check("http endpoint \u7684 Host \u5E26\u7AEF\u53E3", captured[0].headers["host"] === "minio.local:9000", captured[0].headers["host"]);
  console.log(`
${failures === 0 ? "\x1B[32m\u5168\u90E8\u901A\u8FC7\x1B[0m" : `\x1B[31m${failures} \u9879\u5931\u8D25\x1B[0m`}
`);
  process.exit(failures === 0 ? 0 : 1);
}
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
