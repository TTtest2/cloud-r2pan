import type { Env } from "./types";
import { hmacB64url, safeEqual } from "./crypto";

const COOKIE_NAME = "cd_admin";
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000; // 7 天

function getCookie(req: Request, name: string): string | null {
  const cookies = req.headers.get("cookie") ?? "";
  for (const part of cookies.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

/** 登录成功后签发会话 Cookie */
export async function createSession(env: Env, secure = false): Promise<string> {
  const exp = Date.now() + SESSION_TTL_MS;
  const sig = await hmacB64url(env.admin, String(exp));
  const token = `${exp}.${sig}`;
  // Secure 标志仅在 HTTPS 下追加，兼容本地 http 调试
  const secureFlag = secure ? "; Secure" : "";
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_MS / 1000}${secureFlag}`;
}

/** 校验会话 Cookie，返回是否有效 */
export async function verifySession(req: Request, env: Env): Promise<boolean> {
  const token = getCookie(req, COOKIE_NAME);
  if (!token) return false;
  const dot = token.indexOf(".");
  if (dot < 0) return false;
  const exp = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  const expect = await hmacB64url(env.admin, exp);
  return safeEqual(sig, expect);
}

/** 校验登录密钥（恒定时间比较，直接比字符串即可，无需 HMAC 包装） */
export function checkAdminKey(env: Env, input: string): boolean {
  if (!env.admin) return false;
  return safeEqual(input, env.admin);
}

/**
 * 简易限流（每 isolate 内存计数，防暴力破解）。
 *
 * ── Bug #3 修复：Map 永不清理的内存泄漏 ──
 * 原实现每次过期 entry 都 set 新值而非 delete，且永不清理已过期的其他 IP 记录。
 * 恶意扫描 10 万个不同 IP 会吃光 isolate 内存。
 *
 * 修复：
 *   1. 命中过期 entry → 先 delete 再 set（覆盖也 OK 但 delete 更明确）
 *   2. 每 100 次调用触发一次全量 sweep，清理所有过期 entry
 *
 * scope 让互不相干的端点各数各的：管理员登录和"猜某个分享链接的密码"共用计数
 * 时，NAT 后面正常浏览分享页的人会把管理员挡在登录页外。
 */
const attempts = new Map<string, { count: number; resetAt: number }>();
let rateLimitCallCount = 0;

export function rateLimit(ip: string, scope: string, limit = 8, windowMs = 60_000): boolean {
  const key = `${scope}|${ip}`;
  const now = Date.now();
  const rec = attempts.get(key);
  if (!rec || rec.resetAt < now) {
    // 过期或首次：先清掉旧 entry（如果有），再创建新的
    if (rec) attempts.delete(key);
    attempts.set(key, { count: 1, resetAt: now + windowMs });
  } else {
    rec.count++;
  }

  // 每 100 次调用触发一次全量 sweep，防止长期积累的过期 entry 占内存
  if (++rateLimitCallCount % 100 === 0) {
    for (const [k, val] of attempts) {
      if (val.resetAt < now) attempts.delete(k);
    }
  }

  const current = attempts.get(key)!;
  return current.count <= limit;
}

/** 距当前限流窗口重置还有多少秒（用于 Retry-After） */
export function rateLimitRetryAfter(ip: string, scope: string): number {
  const rec = attempts.get(`${scope}|${ip}`);
  return rec && rec.resetAt > Date.now() ? Math.ceil((rec.resetAt - Date.now()) / 1000) : 60;
}

/** 获取客户端真实 IP（Cloudflare 环境下 CF-Connecting-IP 不可伪造） */
export function clientIp(req: Request): string {
  return (
    req.headers.get("cf-connecting-ip") ??
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "127.0.0.1"
  );
}

/** IPv4 字符串 → 32 位无符号整数 */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/** 判断一个 IP 是否匹配白名单中的某一项（支持精确 IP、CIDR、通配符 *） */
export function ipMatchesList(ip: string, listStr: string): boolean {
  if (!listStr) return false;
  const entries = listStr
    .split(/[,，\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (entries.length === 0) return false;

  for (const entry of entries) {
    // 精确匹配
    if (entry === ip) return true;

    // CIDR 匹配（仅 IPv4）
    const cidr = entry.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (cidr) {
      const network = ipv4ToInt(cidr[1]);
      const bits = parseInt(cidr[2], 10);
      const target = ipv4ToInt(ip);
      if (network !== null && target !== null && bits >= 0 && bits <= 32) {
        const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
        if ((network & mask) === (target & mask)) return true;
      }
    }
  }
  return false;
}

/** 白名单启用判定：adminIps 为空 → 不限制；非空 → 仅匹配的 IP 算白名单内 */
export function isAdminWhitelisted(ip: string, adminIps: string): boolean {
  if (!adminIps) return false; // 未配置就不标记为白名单内，保持原有限额
  return ipMatchesList(ip, adminIps);
}

/**
 * 管理员入口 IP 门禁：
 *   - adminIps 为空 → 所有人可以访问（保持向后兼容）
 *   - adminIps 非空 → 仅匹配白名单的 IP 可以访问，其他返回 403
 */
export function requireAdminIp(ip: string, adminIps: string): Response | null {
  if (!adminIps) return null;
  if (ipMatchesList(ip, adminIps)) return null;
  const body = JSON.stringify({ error: "ip_forbidden", message: "This IP is not allowed to access the admin panel." });
  return new Response(body, { status: 403, headers: { "content-type": "application/json" } });
}
