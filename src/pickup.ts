/**
 * 取件码投递 —— 奶牛快传式"输码取件"，但语义更硬一点：**码既是地址也是凭据**。
 *
 * 为什么不做成"短链接"：短链接泄露了才算泄露，码一旦泄露就是文件本身被取走。
 * 既然按码寻址，码就必须当口令对待：
 *   - 库里只存 keyed hash（HMAC(admin, 码)）与一份给后台回看的密文，明文不落库；
 *   - 在线猜码有三层限流（按 IP、按码、超阈值后连查库都不做）；
 *   - 所有失败路径回同一个响应，不区分"码不存在 / 已过期 / 已取走"。
 *
 * 存储模型让步：一条投递 = 一行 files + 一行 shares(origin='drop')。
 * 于是去重、引用计数、回收站、cron、闸门流水线全都白拿，只在 shares 上多挂了
 * pickup_* 列；投递的文件固定落在系统目录"投递箱"里，后台一眼能扫到、也不会
 * 混进正常的文件夹视图。码对应的分享天生不进市场、不派生直链。
 */
import type { Env } from "./types";
import { randomId } from "./db";
import { getSettings, type Settings } from "./settings";
import { hmacHex, encryptSecret, decryptSecret, safeEqual } from "./crypto";
import { authThrottled, noteAuthFailure, clearAuthFailures, clientIp, rateLimit } from "./auth";
import { createFolder, getFolderTree, invalidateFolderTree } from "./folders";
import { getStorageProvider as storage } from "./storage";
import { declaredSize, formatMb, postUploadRejection, preUploadRejection } from "./limits";
import { errorPage, json } from "./pages";
import { isTurnstileEnabled, serveShareDownload, verifyTurnstileToken } from "./public";

/** 去掉 0/o/1/i/l 的人工可抄字符集 */
const CODE_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789";
const CODE_LEN = 8;
/** 一次投件的取件码最多重试几次避撞（29^8 空间里撞码极罕见） */
const CODE_RETRY = 5;

/** 投递文件统一落这个系统目录；后台据此过滤，改名不影响逻辑（按 id 找） */
export const DROP_FOLDER_NAME = "投递箱";

export type PickupCode = { code: string; hash: string; cipher: string };

/**
 * 归一化用户输入的码：忽略大小写、空格与连字符（"AB3D-K9FQ" 与 "ab3dk9fq" 等价）。
 * 返回 null 表示这根本不是个合法形状的码 —— 此时连查库都不要发生。
 */
export function normalizePickupCode(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const compact = raw.toLowerCase().replace(/[\s\-_]/g, "");
  if (compact.length !== CODE_LEN) return null;
  for (const ch of compact) if (!CODE_ALPHABET.includes(ch)) return null;
  return compact;
}

/** 码 → 可寻址的 keyed hash。用 admin 密钥做 HMAC：拿到数据库也反推不出码 */
export function pickupCodeHash(env: Env, code: string): Promise<string> {
  return hmacHex(env.admin, `pickup:${code}`);
}

/** 生成一枚尚未占用的码（撞了 unique 索引就换一枚） */
export async function mintPickupCode(env: Env): Promise<PickupCode> {
  let last: PickupCode | null = null;
  for (let i = 0; i < CODE_RETRY; i++) {
    const bytes = crypto.getRandomValues(new Uint8Array(CODE_LEN));
    const code = Array.from(bytes, (b) => CODE_ALPHABET[b % CODE_ALPHABET.length]).join("");
    const hash = await pickupCodeHash(env, code);
    const taken = await env.db.prepare("SELECT id FROM shares WHERE pickup_hash = ?1").bind(hash).first();
    const cipher = await encryptSecret(code, env.admin);
    last = { code, hash, cipher };
    if (!taken) return last;
  }
  throw new Error("取件码空间撞满（不可能到这里，除非 admin 密钥被换过又反复撞）");
}

/** 后台回看码：解密失败（换过密钥）就回 null，而不是 500 */
export async function revealPickupCode(env: Env, cipher: string | null): Promise<string | null> {
  if (!cipher) return null;
  try {
    return await decryptSecret(cipher, env.admin);
  } catch {
    return null;
  }
}
/** 展示用分组：ab3d-k9fq */
export function formatPickupCode(code: string): string {
  return `${code.slice(0, 4)}-${code.slice(4)}`;
}

/** 投递区当前占用（只算还活着的 drop 行，去重后的真实字节） */
export async function dropAreaBytes(env: Env): Promise<number> {
  const row = await env.db.prepare(
    `SELECT COALESCE(SUM(s), 0) AS bytes FROM (
       SELECT MIN(f.size) AS s
       FROM files f JOIN shares sh ON sh.file_id = f.id
       WHERE sh.origin = 'drop' AND f.deleted_at IS NULL
       GROUP BY f.key
     )`
  ).first<{ bytes: number }>();
  return row?.bytes ?? 0;
}

/** 某个 IP 今天（自然日，UTC 起点简单按 24h 窗口）投了几件、多少字节 */
export async function dropUsageByIp(env: Env, ip: string, since: number) {
  const row = await env.db.prepare(
    `SELECT COUNT(*) AS c, COALESCE(SUM(size), 0) AS bytes FROM (
       SELECT f.size
       FROM shares sh JOIN files f ON f.id = sh.file_id
       WHERE sh.origin = 'drop' AND sh.origin_ip = ?1 AND sh.created_at > ?2
     )`
  ).bind(ip, since).first<{ c: number; bytes: number }>();
  return { count: row?.c ?? 0, bytes: row?.bytes ?? 0 };
}

/** 投递箱目录 id（没有就建；建到一半别人抢先了也不报错） */
let _dropFolderId: string | null = null;
export async function dropFolderId(env: Env): Promise<string> {
  if (_dropFolderId) return _dropFolderId;
  const find = async (fresh = false) => (await getFolderTree(env, { fresh })).child(null, DROP_FOLDER_NAME)?.id ?? null;
  let id = await find();
  if (!id) {
    const created = await createFolder(env, null, DROP_FOLDER_NAME);
    invalidateFolderTree();
    id = created?.id ?? (await find(true));
  }
  if (!id) throw new Error("投递箱目录创建失败");
  _dropFolderId = id;
  return id;
}

export function invalidateDropFolderCache(): void {
  _dropFolderId = null;
}

const DAY_MS = 86_400_000;
/** 输码换到的下载票据有效期：够拉完一个大文件，又不必把码本身放进每条 Range 请求 */
const CLAIM_TTL_MS = 15 * 60_000;

/** 所有"码不对"的分支回同一个页面：不区分不存在 / 已过期 / 已取走 */
function unknownCode(req: Request): Response {
  return errorPage(req, 404, { zh: "取件码无效", en: "Invalid Pickup Code" },
    { zh: "码不存在、已过期或已被取走，请向投递人重新索取。", en: "The code is unknown, expired, or already consumed." });
}

/** 匿名投递的文件名：解码 → 取 basename → 去控制字符 → 限长，绝不信任来路 */
export function sanitizeDropName(raw: string | null): string {
  let n = (raw ?? "").trim();
  try {
    n = decodeURIComponent(n);
  } catch {
    /* 不是百分号编码就用原值 */
  }
  n = (n.replace(/\\/g, "/").split("/").pop() ?? "").replace(/[\u0000-\u001f\u007f]/g, "");
  n = n.replace(/[<>:"|?*]/g, "_").trim();
  if (n.length > 120) n = n.slice(-120);
  return n || "投件.bin";
}

/** 票据 = 过期时间.HMAC(admin, "claim:分享id:过期时间")，与下载令牌同一套路 */
async function issueClaimTicket(env: Env, shareId: string): Promise<string> {
  const exp = Date.now() + CLAIM_TTL_MS;
  return `${exp}.${await hmacHex(env.admin, `claim:${shareId}:${exp}`)}`;
}

async function verifyClaimTicket(env: Env, shareId: string, t: string | null): Promise<boolean> {
  if (!t || !env.admin) return false;
  const dot = t.indexOf(".");
  if (dot < 0) return false;
  const exp = t.slice(0, dot);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return safeEqual(t.slice(dot + 1), await hmacHex(env.admin, `claim:${shareId}:${exp}`));
}

/* ═══════════ 投递：POST /api/pickup（文件名在 X-File-Name 头，body 就是文件流） ═══════════ */

/**
 * 闸门顺序：总开关 → 封禁 IP → 请求频率 → 人机验证（若配了）→ 声明体积 → 单 IP
 * 每日件数/字节 → 落盘 → 真实体积复核 → 投递区总配额（超了删对象、行不落库）。
 *
 * 投递**故意不做去重/秒传**：陌生人的文件与机主文件共用一个对象，会把两者的
 * 删除生命周期绑在一起，而且"这个 sha256 你已经有了"本身是个存在性oracle。
 * 投件区要的恰恰是"互相看不见"。
 */
export async function handlePickupDrop(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const settings = await getSettings(env);
  // 总开关关掉 = 这个功能不存在，已发出去的码也一并取不到（码就是凭据）
  if (!settings.pickupEnabled) return json({ error: "not_available" }, { status: 404 });

  const ip = clientIp(req);
  if (!rateLimit(ip, "pickup-drop", 6)) return json({ error: "too_many" }, { status: 429 });

  const ban = await env.db.prepare("SELECT reason, expires_at FROM banned_ips WHERE ip = ?1")
    .bind(ip).first<{ reason: string | null; expires_at: number | null }>();
  if (ban && (!ban.expires_at || ban.expires_at > Date.now())) return json({ error: "banned" }, { status: 403 });

  if (await isTurnstileEnabled(env, settings)) {
    const token = new URL(req.url).searchParams.get("cf");
    if (!token || !(await verifyTurnstileToken(env, settings, token, ip)))
      return json({ error: "turnstile_required" }, { status: 403 });
  }

  if (!req.body) return json({ error: "empty_body" }, { status: 400 });
  const name = sanitizeDropName(req.headers.get("x-file-name"));
  const mime = req.headers.get("content-type") || "application/octet-stream";

  // 限额复用 limits.ts 那一套（声明先挡、落盘后按真实 size 再判），只是把上限
  // 换成"投递区自己的预算"，不另写一份会走样的实现
  const limits: Settings = {
    ...settings,
    maxUploadBytes: settings.pickupMaxUploadBytes > 0
      ? Math.min(settings.maxUploadBytes || settings.pickupMaxUploadBytes, settings.pickupMaxUploadBytes)
      : settings.maxUploadBytes,
    storageQuotaBytes: settings.pickupTotalQuotaBytes,
  };
  const used = await dropAreaBytes(env);
  const declared = declaredSize(req);
  const rejected = preUploadRejection(limits, used, declared);
  if (rejected) return uploadReject(req, rejected);

  // 单 IP 滚动 24 小时内：件数与字节两条都要看
  const usage = await dropUsageByIp(env, ip, Date.now() - DAY_MS);
  if (settings.pickupPerIpDailyCount > 0 && usage.count >= settings.pickupPerIpDailyCount)
    return json({ error: "ip_daily_count", limit: settings.pickupPerIpDailyCount }, { status: 429 });
  // 声明了体积就连这件一起算；没声明时无从预判，只能"已经超了才拦"（落盘后的
  // 真实体积仍会被投递区总配额那道 post 检查管住）
  const ipBytesOver = settings.pickupPerIpDailyBytes > 0 &&
    (declared !== null ? usage.bytes + declared > settings.pickupPerIpDailyBytes : usage.bytes >= settings.pickupPerIpDailyBytes);
  if (ipBytesOver)
    return json({ error: "ip_daily_bytes", limit_mb: formatMb(settings.pickupPerIpDailyBytes) }, { status: 429 });

  const id = randomId(14);
  const key = `drops/${id}`;
  const st = await storage(env);
  // req.body 必须原样交给存储层：R2 只接受长度已知的流，套一层计数管道会被拒
  let size = 0;
  let etag: string | null = null;
  try {
    const put = await st.put(key, req.body, { contentType: mime, contentLength: declaredSize(req) ?? undefined });
    size = put.size;
    etag = put.etag ?? null;
  } catch (err: any) {
    await st.delete(key).catch(() => {});
    return json({ error: "storage_failed", detail: String(err?.message || err) }, { status: 502 });
  }
  const late = postUploadRejection(limits, used, size);
  if (late) {
    await st.delete(key).catch(() => {});
    return uploadReject(req, late);
  }

  const folderId = await dropFolderId(env);
  const now = Date.now();
  const expiresAt = now + Math.max(1, settings.pickupRetentionDays) * DAY_MS;
  const once = new URL(req.url).searchParams.get("once") === "1";
  const shareId = randomId(10);
  const { code, hash, cipher } = await mintPickupCode(env);

  try {
    await env.db.batch([
      env.db.prepare(
        "INSERT INTO files(id, key, name, size, mime, uploaded_at, folder_id, etag) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
      ).bind(id, key, name, size, mime, now, folderId, etag),
      // 一次一取 = max_downloads 1：现成的名额语义，不再另造标志
      env.db.prepare(
        `INSERT INTO shares(id, file_id, created_at, expires_at, max_downloads, download_count, revoked,
                            pickup_hash, pickup_cipher, origin, origin_ip)
         VALUES(?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?7, 'drop', ?8)`
      ).bind(shareId, id, now, expiresAt, once ? 1 : null, hash, cipher, ip),
    ]);
  } catch (dbErr) {
    // 行没落成 = 这次投递不存在，对象不能留下白占配额
    ctx.waitUntil(st.delete(key).catch(() => {}));
    console.error("pickup: insert failed", dbErr);
    return json({ error: "db_failed" }, { status: 500 });
  }

  return json({
    ok: true,
    code: formatPickupCode(code),
    name,
    size,
    expires_at: expiresAt,
    one_shot: once,
    pickup_url: "/pickup",
  }, { status: 201 });
}

/* ═══════════ 按码寻址的三处共用查询 ═══════════ */

/** 码 → 投递行（含文件本体）。找不到就 null，调用方一律回同一个"码无效"页面 */
async function findByCode(env: Env, code: string) {
  const hash = await pickupCodeHash(env, code);
  return await env.db.prepare(
    `SELECT sh.id AS share_id, sh.file_id, sh.created_at, sh.expires_at, sh.max_downloads, sh.download_count,
            sh.revoked, sh.password_hash, f.key, f.name, f.size, f.mime
     FROM shares sh JOIN files f ON f.id = sh.file_id
     WHERE sh.pickup_hash = ?1 AND sh.origin = 'drop' AND f.deleted_at IS NULL`
  ).bind(hash).first<DropRow>();
}

export interface DropRow {
  share_id: string;
  file_id: string;
  created_at: number;
  expires_at: number | null;
  max_downloads: number | null;
  download_count: number;
  revoked: number;
  password_hash: string | null;
  key: string;
  name: string;
  size: number;
  mime: string;
}

/* ═══════════ 取件：POST /api/pickup/claim {code} ═══════════ */

/**
 * 输码 → 换一张短时效票据。凭据就是码本身，所以这一层是唯一的对外认证口，
 * 三道省钱的闸：
 *   ① 形状不对（长度/字符集）连哈希与查库都不做；
 *   ② rateLimit 按 IP 数总请求，暴力猜的频次被压到每分钟十几次；
 *   ③ 按"被提交的那枚码"数失败：同一枚码被反复试就不再查库（顺带保住 D1 读次数）。
 *
 * ③ 只在对方已经知道这枚码时才可能触发（比如试一个刚过期的码），所以它不构成
 * "拿别人的码把真主人锁在门外"的把柄 —— 锁不住自己没见过的码。
 * 所有失败回同一张 404，不区分码不存在 / 已过期 / 已取走。
 */
export async function handlePickupClaim(req: Request, env: Env): Promise<Response> {
  const settings = await getSettings(env);
  if (!settings.pickupEnabled) return unknownCode(req);

  const ip = clientIp(req);
  if (!rateLimit(ip, "pickup-claim", 10)) return json({ error: "too_many" }, { status: 429 });

  const body = (await req.json().catch(() => null)) as { code?: unknown } | null;
  const code = normalizePickupCode(body?.code);
  if (!code) return unknownCode(req);
  if (authThrottled(code, "pickup-code", 5)) return unknownCode(req);

  const row = await findByCode(env, code);
  if (!row || row.revoked || (row.expires_at && row.expires_at < Date.now()) ||
      (row.max_downloads && row.download_count >= row.max_downloads)) {
    noteAuthFailure(code, "pickup-code");
    return unknownCode(req);
  }
  clearAuthFailures(code, "pickup-code");

  await env.db.prepare("UPDATE shares SET pickup_claims = pickup_claims + 1 WHERE id = ?1")
    .bind(row.share_id).run();

  return json({
    ok: true,
    name: row.name,
    size: row.size,
    mime: row.mime,
    expires_at: row.expires_at,
    one_shot: !!row.max_downloads,
    t: await issueClaimTicket(env, row.share_id),
    download_url: `/api/pickup/download?c=${code}&t=`,
  });
}

/* ═══════════ 下载：GET /api/pickup/download?c=&t= ═══════════ */

/**
 * 票据有效才把行交给**与分享链接同一条**闸门流水线（过期/次数/流量/单 IP 重复
 * 与自动封禁全都照旧）—— 取件码只是多给了一种进入方式，不是第二套宽松规则。
 */
export async function handlePickupDownload(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const settings = await getSettings(env);
  if (!settings.pickupEnabled) return unknownCode(req);

  const sp = new URL(req.url).searchParams;
  const ip = clientIp(req);
  if (!rateLimit(ip, "pickup-download", 30)) return json({ error: "too_many" }, { status: 429 });
  const code = normalizePickupCode(sp.get("c"));
  if (!code) return unknownCode(req);

  const row = await findByCode(env, code);
  if (!row) return unknownCode(req);
  if (!(await verifyClaimTicket(env, row.share_id, sp.get("t")))) {
    return errorPage(req, 403, { zh: "取件凭据已过期", en: "Claim Expired" },
      { zh: "请回到取件页重新输入取件码。", en: "Re-enter the pickup code on the pickup page." });
  }

  return serveShareDownload(req, env, ctx, row.share_id, {
    row: {
      id: row.share_id,
      file_id: row.file_id,
      created_at: row.created_at,
      expires_at: row.expires_at,
      max_downloads: row.max_downloads,
      download_count: row.download_count,
      revoked: row.revoked,
      password_hash: row.password_hash,
      key: row.key,
      name: row.name,
      size: row.size,
      mime: row.mime,
    },
  });
}

function fmtBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

/** 体积/配额被挡时的统一回法（状态码沿用 limits.ts 的 413/507） */
function uploadReject(req: Request, r: { status: number; code: string; limitBytes: number }): Response {
  return json({ error: r.code, limit_mb: formatMb(r.limitBytes), message: fmtBytes(r.limitBytes) }, { status: r.status });
}
