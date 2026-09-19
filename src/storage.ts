/**
 * Storage 抽象层 —— 零依赖对象存储访问
 *
 * 支持两种后端：
 *   1. R2StorageProvider  —— 直接用 Cloudflare Workers 的 R2Bucket binding（原有方式）
 *   2. S3StorageProvider  —— 通用 S3 兼容存储（AWS S3 / Backblaze B2 / MinIO / 阿里云 OSS / 腾讯云 COS 等）
 *
 * S3 客户端用纯 fetch + crypto.subtle 手写 AWS Signature V4，
 * 零 npm 依赖，完全符合本项目"零运行时依赖"原则。
 */

import type { Env } from "./types";
import { decryptSecret } from "./crypto";
import { getSettings } from "./settings";

/* ═══════════════════════════════════════════════════════
 * 存储提供者接口 —— 替换原有 env.r2 的硬编码
 * ═══════════════════════════════════════════════════════ */

export interface StorageObject {
  body: ReadableStream<Uint8Array>;
  size: number;
  contentType: string;
  etag: string;
}

export interface StoragePutResult {
  size: number;
  etag?: string;
}

export interface StorageProvider {
  kind: "r2" | "s3";
  /** 上传对象（body 可以是 ReadableStream 或 ArrayBuffer） */
  put(
    key: string,
    body: ReadableStream<Uint8Array> | ArrayBuffer | Uint8Array,
    opts: { contentType?: string; contentDisposition?: string; contentLength?: number }
  ): Promise<StoragePutResult>;
  /** 读取对象（支持 Range） */
  get(key: string, range?: { offset: number; length?: number }): Promise<StorageObject | null>;
  /** 删除对象 */
  delete(key: string): Promise<void>;
  /** 获取对象元数据（不含 body） */
  head(key: string): Promise<{ size: number; contentType: string } | null>;
}

/* ═══════════════════════════════════════════════════════
 * Provider 1: Cloudflare R2 —— 原有 binding 直接包装
 * ═══════════════════════════════════════════════════════ */

export function createR2Provider(r2: R2Bucket): StorageProvider {
  return {
    kind: "r2",
    async put(key, body, opts) {
      const r2Body = body instanceof Uint8Array ? body.buffer : body;
      const httpMetadata: Record<string, string> = {};
      if (opts.contentType) httpMetadata.contentType = opts.contentType;
      if (opts.contentDisposition) httpMetadata.contentDisposition = opts.contentDisposition;
      const obj = await r2.put(key, r2Body as any, { httpMetadata });
      return { size: obj.size, etag: obj.httpEtag };
    },
    async get(key, range) {
      const r2Range = range
        ? range.length !== undefined
          ? { offset: range.offset, length: range.length }
          : { offset: range.offset }
        : undefined;
      const obj = (await r2.get(key, r2Range as any)) as any;
      if (!obj) return null;
      return {
        body: obj.body as ReadableStream<Uint8Array>,
        size: obj.size,
        contentType: obj.httpMetadata?.contentType ?? "application/octet-stream",
        etag: obj.httpEtag,
      };
    },
    async delete(key) {
      await r2.delete(key);
    },
    async head(key) {
      const obj = await r2.head(key);
      if (!obj) return null;
      return { size: obj.size, contentType: obj.httpMetadata?.contentType ?? "application/octet-stream" };
    },
  };
}

/* ═══════════════════════════════════════════════════════
 * Provider 2: S3 兼容存储 —— 纯 fetch + AWS Signature V4
 * ═══════════════════════════════════════════════════════ */

export interface S3Config {
  endpoint: string; // 如 https://s3.amazonaws.com 或 https://s3.us-west-002.backblazeb2.com
  region: string; // 如 us-east-1、ap-southeast-1、auto（R2 用 auto）
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** "path" = bucket 在 URL path 中；"virtual" = bucket 作为 hostname 前缀 */
  addressingStyle?: "path" | "virtual";
  /** 可选的自定义路径前缀（如 MinIO 的子路径） */
  pathPrefix?: string;
}

/** URL 编码（RFC 3986），AWS S3 签名要求严格的百分号编码 */
function encodeURIComponentStrict(s: string): string {
  return encodeURIComponent(s)
    .replace(/'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A");
}

/** 生成规范化请求（Canonical Request）—— AWS Signature V4 的核心 */
function buildCanonicalRequest(
  method: string,
  path: string,
  query: URLSearchParams | undefined,
  headers: Record<string, string>,
  bodyHash: string
): { canonical: string; signedHeaders: string } {
  const sortedHeaderNames = Object.keys(headers)
    .map((k) => k.toLowerCase())
    .sort();
  const signedHeaders = sortedHeaderNames.join(";");

  const lowercased: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lowercased[k.toLowerCase()] = v.trim();
  const headerLines = sortedHeaderNames.map((name) => `${name}:${lowercased[name]}\n`).join("");

  // 规范化 query string
  let canonicalQuery = "";
  if (query) {
    const pairs: [string, string][] = [];
    query.forEach((v, k) => pairs.push([k, v]));
    // SigV4 要求按字节序排序，localeCompare 会按语言环境把 "a" 排在 "B" 前面
    const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
    pairs.sort((a, b) =>
      a[0] === b[0] ? cmp(encodeURIComponentStrict(a[1]), encodeURIComponentStrict(b[1]))
        : cmp(encodeURIComponentStrict(a[0]), encodeURIComponentStrict(b[0]))
    );
    canonicalQuery = pairs.map(([k, v]) => `${encodeURIComponentStrict(k)}=${encodeURIComponentStrict(v)}`).join("&");
  }

  const canonical = [
    method,
    path,
    canonicalQuery,
    headerLines,
    signedHeaders,
    bodyHash,
  ].join("\n");

  return { canonical, signedHeaders };
}

/** Normalize to a standalone ArrayBuffer (copies the view, so byteOffset/length are honoured) */
function toArrayBuffer(data: ArrayBuffer | Uint8Array): ArrayBuffer {
  if (data instanceof Uint8Array) return data.slice().buffer as ArrayBuffer;
  return data;
}

/** HMAC-SHA256 */
async function hmacSha256(key: ArrayBuffer | Uint8Array, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

async function sha256Hex(data: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Binary payloads must be hashed byte-for-byte — a TextDecoder round-trip mangles non-UTF8 bodies */
async function sha256HexBytes(data: ArrayBuffer | Uint8Array): Promise<string> {
  return bufToHex(await crypto.subtle.digest("SHA-256", toArrayBuffer(data)));
}

function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** AWS Signature V4 签名派生 */
async function deriveSigningKey(secret: string, date: string, region: string): Promise<ArrayBuffer> {
  const kDate = await hmacSha256(new TextEncoder().encode("AWS4" + secret), date);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, "s3");
  return await hmacSha256(kService, "aws4_request");
}

/** 构造完整 S3 URL + 签名 */
async function signS3Request(
  cfg: S3Config,
  method: string,
  s3Key: string,
  query: URLSearchParams | undefined,
  headers: Record<string, string>,
  bodyHash: string,
  now: Date
): Promise<{ url: string; headers: Record<string, string> }> {
  const amzDate = now.toISOString().replace(/[-:]/g, "").slice(0, 19) + "Z"; // 20260914T120000Z
  const dateStamp = amzDate.slice(0, 8); // SigV4 scope 必须是紧凑的 YYYYMMDD

  const baseUrl = cfg.endpoint.replace(/\/+$/, "");
  const schemeSep = baseUrl.indexOf("://");
  const scheme = schemeSep >= 0 ? baseUrl.slice(0, schemeSep + 3) : "https://";
  const endpointHost = (schemeSep >= 0 ? baseUrl.slice(schemeSep + 3) : baseUrl).split("/")[0];
  const endpointPath = "/" + (schemeSep >= 0 ? baseUrl.slice(schemeSep + 3) : baseUrl).split("/").slice(1).join("/");
  const prefix = cfg.pathPrefix
    ? "/" + cfg.pathPrefix.replace(/^\/+|\/+$/g, "").split("/").map(encodeURIComponentStrict).join("/")
    : "";
  const encodedKey = s3Key.split("/").map(encodeURIComponentStrict).join("/");

  let host: string;
  let url: string;
  if (cfg.addressingStyle === "virtual") {
    host = `${cfg.bucket}.${endpointHost}`;
    url = `${scheme}${host}${endpointPath}${prefix}/${encodedKey}`;
  } else {
    host = endpointHost;
    url = `${baseUrl}${prefix}/${encodeURIComponentStrict(cfg.bucket)}/${encodedKey}`;
  }

  // Sign the path actually being sent (endpoint subpath included), not a re-derivation of it
  const path = new URL(url).pathname;

  // 添加签名头
  headers["Host"] = host;
  headers["x-amz-date"] = amzDate;
  headers["x-amz-content-sha256"] = bodyHash;

  const { canonical, signedHeaders } = buildCanonicalRequest(method, path, query, headers, bodyHash);
  const canonicalHash = await sha256Hex(canonical);
  const credentialScope = `${dateStamp}/${cfg.region}/s3/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${canonicalHash}`;
  const signingKey = await deriveSigningKey(cfg.secretAccessKey, dateStamp, cfg.region);
  const signature = bufToHex(await hmacSha256(signingKey, stringToSign));

  headers["Authorization"] =
    `AWS4-HMAC-SHA256 Credential=${cfg.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  // 把 query 也拼进 url
  if (query) url += `?${query.toString()}`;

  return { url, headers };
}

/** 构造 S3 Provider —— 通用 S3 兼容存储 */
export function createS3Provider(cfg: S3Config): StorageProvider {
  const endpoint = cfg.endpoint.replace(/\/+$/, "");
  const region = cfg.region || "us-east-1";
  const addressing = cfg.addressingStyle || "path";

  async function doFetch(
    method: string,
    key: string,
    opts: {
      query?: URLSearchParams;
      headers?: Record<string, string>;
      body?: ReadableStream<Uint8Array> | ArrayBuffer | Uint8Array | string;
      expectNoBody?: boolean;
    }
  ): Promise<Response> {
    const amzHeaders: Record<string, string> = opts.headers ? { ...opts.headers } : {};
    const now = new Date();

    // 计算 body SHA256（S3 签名需要）
    let bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // 空字符串 hash
    let fetchBody: any = undefined;
    if (opts.body !== undefined) {
      if (typeof opts.body === "string") {
        bodyHash = await sha256Hex(opts.body);
        fetchBody = opts.body;
      } else if (opts.body instanceof ReadableStream) {
        // ReadableStream 不适合 hash（消费后不能重放），使用 UNSIGNED-PAYLOAD
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
      body: fetchBody,
    });
    return resp;
  }

  /** Content-Length of an object via HEAD — used to recover the size of streamed uploads */
  async function headSize(key: string): Promise<number> {
    const resp = await doFetch("HEAD", key, {});
    if (!resp.ok) return 0;
    return parseInt(resp.headers.get("Content-Length") || "0", 10) || 0;
  }

  return {
    kind: "s3",

    async put(key, body, opts) {
      const headers: Record<string, string> = {};
      if (opts.contentType) headers["Content-Type"] = opts.contentType;
      if (opts.contentDisposition) headers["Content-Disposition"] = opts.contentDisposition;
      if (typeof opts.contentLength === "number") headers["Content-Length"] = String(opts.contentLength);

      const resp = await doFetch("PUT", key, { body, headers });
      if (!resp.ok) {
        const text = await resp.text().catch(() => resp.statusText);
        throw new Error(`S3 PUT failed: ${resp.status} ${text}`);
      }
      let size = body instanceof ReadableStream ? 0 : (body as ArrayBuffer | Uint8Array).byteLength;
      if (!size) size = opts.contentLength ?? 0;
      if (!size) size = await headSize(key);
      return { size, etag: resp.headers.get("etag")?.replace(/"/g, "") || undefined };
    },

    async get(key, range) {
      const headers: Record<string, string> = {};
      if (range) {
        let rangeHeader: string;
        if (range.length !== undefined) {
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
        body: resp.body!,
        size,
        contentType: resp.headers.get("Content-Type") || "application/octet-stream",
        etag: resp.headers.get("ETag") || "",
      };
    },

    async delete(key) {
      const resp = await doFetch("DELETE", key, { expectNoBody: true });
      if (!resp.ok && resp.status !== 404) {
        // S3 的 404 不算错误
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
        contentType: resp.headers.get("Content-Type") || "application/octet-stream",
      };
    },
  };
}

/* ═══════════════════════════════════════════════════════
 * Storage Provider 工厂 —— 根据 settings 自动选择后端
 *
 * 优先级：
 *   1. settings.storage_provider === 's3' 且配置了 S3 → 用 S3
 *   2. 否则默认用 env.r2（需要 env.r2 binding 存在）
 * ═══════════════════════════════════════════════════════ */

export async function createStorageProvider(
  env: Env,
  settings: { storageProvider: string | null; s3Endpoint: string | null; s3Region: string | null; s3Bucket: string | null; s3AccessKeyId: string | null; s3SecretKeyCipher: string | null; s3AddressingStyle: string | null }
): Promise<StorageProvider> {
  const useS3 = settings.storageProvider === "s3" && settings.s3Endpoint && settings.s3Bucket;
  if (useS3) {
    const secretAccessKey = settings.s3SecretKeyCipher
      ? await decryptSecret(settings.s3SecretKeyCipher, env.admin)
      : null;
    if (!secretAccessKey || !settings.s3AccessKeyId) {
      // S3 配置不完整，回退到 R2
      if (!env.r2) throw new Error("Storage: S3 config incomplete and no R2 binding available");
      return createR2Provider(env.r2);
    }
    return createS3Provider({
      endpoint: settings.s3Endpoint!,
      region: settings.s3Region || "us-east-1",
      bucket: settings.s3Bucket!,
      accessKeyId: settings.s3AccessKeyId,
      secretAccessKey,
      addressingStyle: (settings.s3AddressingStyle as "path" | "virtual") || "path",
    });
  }
  if (!env.r2) throw new Error("Storage: no R2 binding and S3 not configured");
  return createR2Provider(env.r2);
}

/* ═══════════════════════════════════════════════════════
 * 全 Worker 共享的 Provider 缓存（admin / public / webdav 同一个实例）
 * 以存储相关配置做指纹：getSettings 本身有 5 秒 TTL，
 * 所以管理员改后端最多 5 秒后所有模块一起切过去，无需手动失效钩子。
 * ═══════════════════════════════════════════════════════ */
let _cachedProvider: StorageProvider | null = null;
let _cachedProviderKey = "";

export async function getStorageProvider(env: Env): Promise<StorageProvider> {
  const s = await getSettings(env);
  const key = [
    s.storageProvider,
    s.s3Endpoint,
    s.s3Region,
    s.s3Bucket,
    s.s3AccessKeyId,
    s.s3AddressingStyle,
    s.s3SecretKeyCipher ? s.s3SecretKeyCipher.slice(-12) : "",
  ].join("|");
  if (_cachedProvider && _cachedProviderKey === key) return _cachedProvider;
  _cachedProvider = await createStorageProvider(env, s);
  _cachedProviderKey = key;
  return _cachedProvider;
}
