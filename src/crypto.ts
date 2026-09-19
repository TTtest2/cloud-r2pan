/**
 * 共享加密原语 —— 收敛 auth.ts 和 public.ts 中重复实现的工具函数。
 *
 * ── Bug #6 修复 ───────────────────────────────────────────────
 * 原来 safeEqual / hmac 等在 auth.ts 和 public.ts 各有一份，
 * 且两个 hmac 返回不同编码（base64url vs hex），命名相同但行为不同，
 * 极易在维护时漏改或误用。此处统一实现，按用途命名。
 */

/** 恒定时间字符串比较，防时序攻击 */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** HMAC-SHA256，hex 编码 —— 公开分享令牌签名用（public.ts） */
export async function hmacHex(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** HMAC-SHA256，base64url 编码 —— 管理后台会话签名用（auth.ts） */
export async function hmacB64url(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  let bin = "";
  for (const b of new Uint8Array(sig)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** SHA-256，hex 编码 —— 分享密码哈希用 */
export async function sha256Hex(data: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 生成指定长度的随机十六进制串 —— 密码盐值生成用 */
export function randomHex(n = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(n));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ═══════════ WebDAV 口令拉伸 ═══════════ */

/**
 * workerd 在生产环境对 PBKDF2 的迭代数设了 100_000 的硬上限
 * （CPU 计时无法打断 BoringSSL 的运算，只能事前限制迭代数），
 * 所以这里取 50_000：远低于上限，单次派生约几十毫秒，够劝退在线爆破。
 */
const WEBDAV_ITERATIONS = 50_000;
const MAX_ITERATIONS = 100_000;
const HEX_RE = /^[0-9a-f]+$/i;

/** PBKDF2-SHA256，hex 编码 */
export async function pbkdf2Hex(password: string, saltHex: string, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const salt = Uint8Array.from(saltHex.match(/.{2}/g) ?? [], (h) => parseInt(h, 16));
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 新格式：pbkdf2$<迭代数>$<盐>$<哈希> */
export async function hashWebDAVPassword(password: string): Promise<string> {
  const salt = randomHex(16);
  const hash = await pbkdf2Hex(password, salt, WEBDAV_ITERATIONS);
  return `pbkdf2$${WEBDAV_ITERATIONS}$${salt}$${hash}`;
}

/** 校验口令；needUpgrade 表示存储格式该换（老格式，或迭代数低于当前标准） */
export async function verifyWebDAVPassword(
  stored: string,
  password: string
): Promise<{ ok: boolean; needUpgrade: boolean }> {
  if (!stored) return { ok: false, needUpgrade: false };

  if (stored.startsWith("pbkdf2$")) {
    const [, iters, salt, hash] = stored.split("$");
    const n = Number(iters);
    if (!n || n < 1 || n > MAX_ITERATIONS || !HEX_RE.test(salt ?? "") || !HEX_RE.test(hash ?? "")) {
      return { ok: false, needUpgrade: true }; // 存的东西坏了，让管理员重设一次
    }
    const got = await pbkdf2Hex(password, salt, n);
    return { ok: safeEqual(got, hash), needUpgrade: n < WEBDAV_ITERATIONS };
  }

  // 老格式 salt:sha256(salt:password) —— 单轮散列可被离线爆破，验对后立刻升级
  const i = stored.indexOf(":");
  if (i < 0) return { ok: false, needUpgrade: false };
  const salt = stored.slice(0, i);
  const want = stored.slice(i + 1);
  const got = await sha256Hex(salt + ":" + password);
  return { ok: safeEqual(want, got), needUpgrade: true };
}

/**
 * 用 admin key 派生出 AES-GCM 密钥 —— 加密分享密码明文用。
 * 密钥派生: HKDF-SHA256(info = "share-password-v1")
 */
let cachedAesKeyPromise: Promise<CryptoKey> | null = null;
let cachedAesKeySecret = "";

async function getAesKey(secret: string): Promise<CryptoKey> {
  // 命中缓存：同一个 secret 的 in-flight Promise 或已完成的都直接复用
  if (cachedAesKeyPromise && cachedAesKeySecret === secret) return cachedAesKeyPromise;
  // 换了 secret 也要重新派生，覆盖旧缓存
  cachedAesKeySecret = secret;
  cachedAesKeyPromise = (async () => {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HKDF" },
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(16), info: new TextEncoder().encode("share-password-v1") },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  })();
  return cachedAesKeyPromise;
}

/**
 * AES-GCM 加密。返回格式: "base64(nonce).base64(ciphertext+tag)"
 * 失败时（如 key 未就绪）返回空字符串。
 */
export async function encryptSecret(plain: string, secret: string): Promise<string> {
  if (!plain) return "";
  const key = await getAesKey(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, new TextEncoder().encode(plain));
  const toB64 = (u8: Uint8Array) => btoa(String.fromCharCode(...u8)).replace(/=+$/, "");
  return toB64(nonce) + "." + toB64(new Uint8Array(ct));
}

/** AES-GCM 解密。格式不匹配或密钥错误时返回 null。 */
export async function decryptSecret(payload: string, secret: string): Promise<string | null> {
  if (!payload) return null;
  const parts = payload.split(".");
  if (parts.length !== 2) return null;
  try {
    const key = await getAesKey(secret);
    const fromB64 = (s: string) => {
      const pad = "=".repeat((4 - (s.length % 4)) % 4);
      const bin = atob(s + pad);
      return new Uint8Array(bin.length).map((_, i) => bin.charCodeAt(i));
    };
    const nonce = fromB64(parts[0]);
    const ct = fromB64(parts[1]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

/* ═══════════════════════════════════════════════
 * TOTP (RFC 6238) — Google Authenticator 标准
 * 依赖: crypto.subtle (HMAC-SHA1)
 * ═══════════════════════════════════════════════ */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** 随机生成 TOTP secret（20 字节 → 32 字符 Base32） */
export function totpGenerateSecret(len = 20): string {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  let out = "";
  // 每 5 bit 取一个 alphabet 字符
  let buf = 0;
  let bits = 0;
  for (const b of bytes) {
    buf = (buf << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buf >> bits) & 0x1f];
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(buf << (5 - bits)) & 0x1f];
  return out;
}

/** Base32 解码 → Uint8Array */
function base32Decode(s: string): Uint8Array {
  s = s.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let buf = 0;
  let bits = 0;
  const out: number[] = [];
  for (const ch of s) {
    const v = BASE32_ALPHABET.indexOf(ch);
    if (v < 0) throw new Error("invalid base32");
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/** HMAC-SHA1 (不是 SHA256) — TOTP 标准要求 */
async function hmacSha1(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, msg);
  return new Uint8Array(sig);
}

/** 生成指定时间步的 6 位 TOTP */
async function totpAt(secretB32: string, counter: number, digits = 6): Promise<string> {
  const key = base32Decode(secretB32);
  // counter 大端序 8 字节
  const c = new Uint8Array(8);
  let v = counter;
  for (let i = 7; i >= 0; i--) {
    c[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  const sig = await hmacSha1(key, c);
  const offset = sig[sig.length - 1] & 0x0f;
  const code =
    ((sig[offset] & 0x7f) << 24 |
      (sig[offset + 1] & 0xff) << 16 |
      (sig[offset + 2] & 0xff) << 8 |
      (sig[offset + 3] & 0xff)) %
    10 ** digits;
  return String(code).padStart(digits, "0");
}

/** 验证 TOTP 码（容忍 ±1 个时间步，共 90 秒窗口） */
export async function totpVerify(secretB32: string, code: string, step = 30): Promise<boolean> {
  if (!/^\d{6}$/.test(code)) return false;
  const counter = Math.floor(Date.now() / 1000 / step);
  for (const offset of [-1, 0, 1]) {
    try {
      const expected = await totpAt(secretB32, counter + offset);
      if (safeEqual(code, expected)) return true;
    } catch {
      /* base32 非法 */
    }
  }
  return false;
}

/** 生成 TOTP URI（用于前端扫码） */
export function totpUri(secretB32: string, issuer: string, account: string): string {
  const params = new URLSearchParams({
    secret: secretB32,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  // URL 编码 account（@ 等特殊字符）
  return `otpauth://totp/${encodeURIComponent(issuer + ": " + account)}?${params.toString()}`;
}

/** 生成一组随机恢复码（8 位数字字符，用空格分组显示） */
export function totpGenerateRecoveryCodes(n = 8): string[] {
  const codes: string[] = [];
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  for (let i = 0; i < n; i++) {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    let c = "";
    for (let j = 0; j < 16; j++) c += alphabet[bytes[j] % alphabet.length];
    // 8 字符一组 2 段
    codes.push(c.slice(0, 8) + " " + c.slice(8, 16));
  }
  return codes;
}
