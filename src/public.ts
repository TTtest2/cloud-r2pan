import type { Env, ShareWithFile, DirectLinkWithFile } from "./types";
import { getSettings, addTraffic } from "./settings";
import { parseUA } from "./ua";
import { clientIp, isAdminWhitelisted } from "./auth";
import { findCodeByString, checkCodeUsable, activateCodeIfNeeded, deductQuota, formatCodeStatus } from "./codes";
import { errorPage, json } from "./pages";
import { hmacHex, sha256Hex, randomHex, safeEqual, decryptSecret } from "./crypto";
import { verifyOAuthSession } from "./oauth";
import { getStorageProvider as storage } from "./storage";
import { applyDisposition, inlineCsp, wantsInline } from "./preview";

const TOKEN_TTL_MS = 24 * 3600_000; // 授权令牌有效期 24h

/* ═══════════ Turnstile 辅助函数 ═══════════ */

/**
 * 计算一个 IP 今天已访问过多少次分享页 → 判断是否需要弹 Turnstile。
 * 同时把计数 +1 写回（用 UPSERT 单次 SQL 原子完成）。
 */
async function trackAndGetVisits(env: Env, ip: string): Promise<number> {
  const day = new Date().toISOString().slice(0, 10);
  // 先查 +1
  const upsert = env.db.prepare(
    `INSERT INTO turnstile_visits(ip, day, count) VALUES(?1, ?2, 1)
     ON CONFLICT(ip, day) DO UPDATE SET count = count + 1`
  );
  await upsert.bind(ip, day).run();
  const row = await env.db
    .prepare("SELECT count FROM turnstile_visits WHERE ip = ?1 AND day = ?2")
    .bind(ip, day)
    .first<{ count: number }>();
  return row?.count ?? 1;
}

/** 从 env 或 settings.cipher 拿到最终的 Turnstile Secret（优先 env） */
async function getTurnstileSecret(env: Env, settings: { turnstileSecretCipher: string | null }): Promise<string | null> {
  if (env.turnstile_secret) return env.turnstile_secret;
  if (settings.turnstileSecretCipher) return await decryptSecret(settings.turnstileSecretCipher, env.admin);
  return null;
}

/** 判断当前 Turnstile 是否可用（secret 必须在 env 或 settings 里配） */
export async function isTurnstileEnabled(
  env: Env,
  settings: { turnstileMode: string; turnstileThreshold: number; turnstileSecretCipher: string | null }
): Promise<boolean> {
  const secret = await getTurnstileSecret(env, settings);
  if (!secret) return false;
  if (settings.turnstileMode === "off") return false;
  return true;
}

/**
 * 返回 Turnstile 状态 + sitekey（前端渲染 widget 用）。
 * 如果 sitekey 没配 → 前端根本不会调 Turnstile 脚本。
 */
export function getTurnstileInfo(
  env: Env,
  settings: { turnstileMode: string; turnstileSitekeyOverride: string | null }
): { sitekey: string | null; mode: string } {
  const sitekey = env.turnstile_sitekey || settings.turnstileSitekeyOverride || null;
  return { sitekey, mode: settings.turnstileMode };
}

/**
 * 验证 Turnstile token —— 向 Cloudflare siteverify 发 POST。
 * 官方要求 POST application/x-www-form-urlencoded: secret + token
 */
export async function verifyTurnstileToken(
  env: Env,
  settings: { turnstileSecretCipher: string | null },
  token: string,
  remoteip: string
): Promise<boolean> {
  const secret = await getTurnstileSecret(env, settings);
  if (!secret || !token) return false;
  try {
    const form = new URLSearchParams({
      secret,
      response: token,
      remoteip,
    });
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    if (!r.ok) return false;
    const j = (await r.json()) as { success?: boolean; errorcodes?: string[] };
    return !!j.success;
  } catch {
    return false;
  }
}

/** 解析 Range 头 → {offset, length}，无效返回 null */
function parseRange(header: string | null, size: number): { offset: number; length: number } | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) return null;
  let offset: number, length: number;
  if (m[1] === "") {
    // 后缀范围: bytes=-N
    const n = Math.min(Number(m[2]), size);
    offset = size - n;
    length = n;
  } else {
    offset = Number(m[1]);
    const end = m[2] === "" ? size - 1 : Math.min(Number(m[2]), size - 1);
    length = end - offset + 1;
  }
  if (offset >= size || length <= 0) return null;
  return { offset, length };
}

/* ═══════════ 分享密码 & 下载授权令牌 ═══════════
 * 密码存储为加盐 SHA-256（salt:sha256(salt:password)）；下载授权用 HMAC 签名携带过期时间，
 * 避免把明文密码拼进下载 URL。HMAC 密钥复用 admin，无需新增 Secret，密钥轮换时短时令牌即失效。
 */
/** 加盐与密码哈希串（salt:hashhex） */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomHex();
  return salt + ":" + await sha256Hex(salt + ":" + password);
}
/** 常数时间校验密码 */
async function verifyPassword(stored: string, password: string): Promise<boolean> {
  const i = stored.indexOf(":");
  if (i < 0) return false;
  const salt = stored.slice(0, i);
  const want = stored.slice(i + 1);
  const got = await sha256Hex(salt + ":" + password);
  return safeEqual(want, got);
}
/** 颁发短时下载授权令牌：格式 `${到期时间戳}.${HMAC}` */
async function issueToken(env: Env, token: string): Promise<string> {
  const exp = Date.now() + TOKEN_TTL_MS;
  const sig = await hmacHex(env.admin, `${token}:${exp}`);
  return `${exp}.${sig}`;
}
/** 校验下载授权令牌（存在于 URL query string 中） */
async function verifyShareToken(env: Env, token: string, query: string): Promise<boolean> {
  const t = new URLSearchParams(query).get("t");
  if (!t) return false;
  const i = t.indexOf(".");
  if (i < 0) return false;
  const exp = Number(t.slice(0, i));
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const want = await hmacHex(env.admin, `${token}:${exp}`);
  return safeEqual(t.slice(i + 1), want);
}

/** GET /s/:token —— 分享页元信息（供前端渲染） */
export async function handleShareInfo(req: Request, env: Env, token: string): Promise<Response> {
  const row = await getShare(env, token);
  if (!row) return json({ error: "not_found" }, { status: 404 });
  const settings = await getSettings(env);
  const ip = clientIp(req);
  const isWhitelisted = isAdminWhitelisted(ip, settings.adminIps);
  const quotaExceeded =
    !isWhitelisted && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes;
  let status: "ok" | "gone" | "expired" | "maxed" = "ok";
  if (row.revoked) status = "gone";
  else if (row.expires_at && row.expires_at < Date.now()) status = "expired";
  else if (row.max_downloads && row.download_count >= row.max_downloads) status = "maxed";

  // Turnstile：在 share 页面加载时统计一次访问，判断是否需要弹
  const enabled = await isTurnstileEnabled(env, settings);
  let needsTurnstile = false;
  let visitCount = 0;
  let sitekey: string | null = null;
  if (enabled) {
    const { sitekey: sk, mode } = getTurnstileInfo(env, settings);
    sitekey = sk;
    // on_share / both 模式都在此时判断
    if (mode === "on_share" || mode === "both") {
      visitCount = await trackAndGetVisits(env, ip);
      needsTurnstile = visitCount > settings.turnstileThreshold;
    }
  }

  // OAuth2：检查是否已登录
  let oauthAuthed = false;
  let oauthProvider = settings.oauthEnabled ? settings.oauthProvider : "";
  if (settings.oauthEnabled) {
    const oauthCheck = await verifyOAuthSession(env, req.headers.get("cookie"));
    oauthAuthed = oauthCheck.ok;
  }

  // 市场浏览量累加（仅对 is_market=1 的分享 + 有至少 500ms 间隔的轻量节流）
  if (!row.revoked && row.is_market) {
    env.db.prepare("UPDATE shares SET market_views = market_views + 1 WHERE id = ?1 AND is_market = 1")
      .bind(token).run().catch(() => {}); // 不 await，不阻塞响应
  }

  return json({
    status,
    name: row.name,
    size: row.size,
    mime: row.mime,
    downloads: row.download_count,
    created_at: row.created_at,
    expires_at: row.expires_at,
    max_downloads: row.max_downloads,
    needs_password: !!row.password_hash,
    quota_exceeded: quotaExceeded,
    site_title: settings.siteTitle,
    turnstile: {
      enabled,
      sitekey,
      mode: settings.turnstileMode,
      threshold: settings.turnstileThreshold,
      needs_now: needsTurnstile,
      visit_count: visitCount,
    },
    oauth: {
      enabled: settings.oauthEnabled,
      provider: oauthProvider,
      client_id: settings.oauthClientId,
      authed: oauthAuthed,
    },
    codes_floating_button: {
      enabled: settings.codesFloatingButtonEnabled,
      position: settings.codesFloatingButtonPosition,
    },
  });
}

async function getShare(env: Env, token: string): Promise<ShareWithFile | null> {
  return await env.db.prepare(
    `SELECT s.id, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_count, s.revoked, s.password_hash,
            s.download_name, f.key, f.name, f.size, f.mime
     FROM shares s JOIN files f ON f.id = s.file_id
     WHERE s.id = ?1 AND f.deleted_at IS NULL`
  )
    .bind(token)
    .first<ShareWithFile>();
}

/** 从 direct_links 表查直链记录（独立表、独立 token） */
async function getDirectLink(env: Env, token: string): Promise<DirectLinkWithFile | null> {
  return await env.db.prepare(
    `SELECT dl.id, dl.file_id, dl.created_at, dl.expires_at, dl.max_downloads, dl.download_count, dl.revoked,
            dl.download_name, f.key, f.name, f.size, f.mime
     FROM direct_links dl JOIN files f ON f.id = dl.file_id
     WHERE dl.id = ?1 AND f.deleted_at IS NULL`
  )
    .bind(token)
    .first<DirectLinkWithFile>();
}

/** POST /s/:token/verify —— 校验分享密码 + 可选 Turnstile，成功后颁发下载令牌 */
export async function handleVerify(req: Request, env: Env, token: string): Promise<Response> {
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, { status: 405 });
  const row = await getShare(env, token);
  if (!row) return json({ error: "not_found" }, { status: 404 });
  let body: { password?: string; turnstile?: string } = {};
  try {
    body = await req.json();
  } catch {}

  const settings = await getSettings(env);
  const ip = clientIp(req);
  const turnstileOn = await isTurnstileEnabled(env, settings) && (settings.turnstileMode === "both");

  // Turnstile 校验（both 模式下必须有有效 token）
  if (turnstileOn) {
    const pass = await verifyTurnstileToken(env, settings, String(body.turnstile ?? ""), ip);
    if (!pass) {
      return json({ error: "turnstile_failed" }, { status: 403 });
    }
  }

  // 密码校验
  if (!row.password_hash) {
    // 无密码分享 → 如果 Turnstile 通过 + 没密码，直接给下载地址
    return json({ ok: true, url: `/s/${token}/download` });
  }
  if (!(await verifyPassword(row.password_hash, String(body.password ?? ""))))
    return json({ error: "bad_password" }, { status: 401 });
  const ticket = await issueToken(env, token);
  return json({ ok: true, url: `/s/${token}/download?t=${ticket}` });
}

/**
 * GET /s/:token/download —— 分享链接下载主流程
 * 走 shares 表，带完整鉴权链（密码/过期/次数/流量/Turnstile/OAuth/重复下载）
 */
export async function handleDownload(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  token: string
): Promise<Response> {
  const ip = clientIp(req);
  const ua = req.headers.get("user-agent") ?? "";
  const country = req.headers.get("cf-ipcountry") ?? "";
  const settings = await getSettings(env);

  const urlCode = new URL(req.url).searchParams.get("code");
  const headerCode = req.headers.get("x-activation-code");
  const activationCode = (urlCode || headerCode || "").trim().toUpperCase() || null;

  const [codeRow, ban, row] = await Promise.all([
    activationCode ? findCodeByString(env, activationCode) : Promise.resolve(null),
    env.db.prepare("SELECT reason, expires_at FROM banned_ips WHERE ip = ?1")
      .bind(ip).first<{ reason: string | null; expires_at: number | null }>(),
    getShare(env, token),
  ]);

  if (activationCode && codeRow) {
    const check = checkCodeUsable(codeRow as any);
    if (!check.ok) {
      const reason = check.reason;
      let title = "激活码不可用";
      if (reason === "exhausted") title = "激活码流量已耗尽";
      if (reason === "expired") title = "激活码已过期";
      if (reason === "revoked") title = "激活码已作废";
      return errorPage(req, 403,
        { zh: title, en: "Activation Code Unavailable" },
        { zh: check.message || reason || "该激活码不可用", en: check.message || "This activation code is not available" },
        { siteTitle: settings.siteTitle });
    }
    activateCodeIfNeeded(env, codeRow!).catch(() => {});
  }

  if (ban) {
    if (ban.expires_at && ban.expires_at < Date.now()) {
      env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(ip).run().catch(() => {});
    } else {
      return errorPage(req, 403, { zh: "访问已被封禁", en: "Access Banned" },
        { zh: ban.reason || "由于重复下载行为，该 IP 已被暂时封禁。", en: ban.reason || "This IP has been temporarily banned." });
    }
  }

  if (!row) return errorPage(req, 404, { zh: "链接不存在", en: "Link Not Found" },
    { zh: "该分享链接无效，或已被管理员删除。", en: "This share link is invalid or has been removed." });
  if (row.revoked) return errorPage(req, 410, { zh: "链接已失效", en: "Link Revoked" },
    { zh: "该分享已被管理员撤销。", en: "This share has been revoked." });
  if (row.expires_at && row.expires_at < Date.now()) return errorPage(req, 410, { zh: "链接已过期", en: "Link Expired" },
    { zh: "该分享已超过有效期。", en: "This share has expired." });
  if (row.max_downloads && row.download_count >= row.max_downloads) return errorPage(req, 410, { zh: "下载次数已达上限", en: "Download Limit Reached" },
    { zh: `该资源允许下载 ${row.max_downloads} 次，名额已用完。`, en: `Download limit (${row.max_downloads}) reached.` });

  if (row.password_hash && !(await verifyShareToken(env, token, new URL(req.url).search))) {
    return errorPage(req, 403, { zh: "需要访问密码", en: "Password Required" },
      { zh: "该分享受密码保护。", en: "This share is password-protected." });
  }

  if (settings.oauthEnabled) {
    const oauthResult = await verifyOAuthSession(env, req.headers.get("cookie"));
    if (!oauthResult.ok) {
      const providerName = settings.oauthProvider === "custom" ? "OAuth" : settings.oauthProvider;
      const startUrl = `/oauth/start?provider=${encodeURIComponent(settings.oauthProvider)}&redirect=${encodeURIComponent("/s/" + token)}`;
      return errorPage(req, 401, { zh: "需要登录", en: "OAuth Login Required" },
        { zh: `该资源需要通过 ${providerName} 账号登录后才能下载。`, en: `This resource requires ${providerName} login.` },
        { siteTitle: settings.siteTitle, oauth_login_url: startUrl });
    }
  }

  if (await isTurnstileEnabled(env, settings)) {
    const url = new URL(req.url);
    const mode = settings.turnstileMode;
    const downloadGate = mode === "on_download" || mode === "both";
    if (downloadGate) {
      const turnstileToken = url.searchParams.get("cf");
      if (!turnstileToken) {
        return errorPage(req, 403, { zh: "需要验证码", en: "Turnstile Required" },
          { zh: "请先通过人机验证。", en: "Please complete human verification." },
          { siteTitle: settings.siteTitle });
      }
      const pass = await verifyTurnstileToken(env, settings, turnstileToken, ip);
      if (!pass) {
        return errorPage(req, 403, { zh: "验证码校验失败", en: "Turnstile Failed" },
          { zh: "人机验证未通过。", en: "Human verification failed." },
          { siteTitle: settings.siteTitle });
      }
    }
  }

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (!whitelisted && !usingCode && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
      return errorPage(req, 503, { zh: "下载已暂停", en: "Downloads Paused" },
        { zh: "本月流量已达预设限额。", en: "Monthly traffic quota reached." },
        { siteTitle: settings.siteTitle });
    }
  }

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (!whitelisted && !usingCode && settings.maxDownloadsPerIp > 0) {
      const since = settings.countWindowHours > 0 ? Date.now() - settings.countWindowHours * 3600_000 : 0;
      const { c } = (await env.db.prepare(
        "SELECT COUNT(*) AS c FROM download_logs WHERE share_id = ?1 AND ip = ?2 AND created_at > ?3"
      ).bind(token, ip, since).first<{ c: number }>()) ?? { c: 0 };
      if (c >= settings.maxDownloadsPerIp) {
        if (settings.autoBan) {
          const expiresAt = settings.banHours > 0 ? Date.now() + settings.banHours * 3600_000 : null;
          await env.db.prepare(
            `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
          ).bind(ip, `重复下载「${row.name}」超过 ${settings.maxDownloadsPerIp} 次`, Date.now(), expiresAt).run();
        }
        return errorPage(req, 403, { zh: "重复下载被拦截", en: "Duplicate Download Blocked" },
          { zh: `同一 IP 在统计窗口内下载此资源的次数已达上限（${settings.maxDownloadsPerIp} 次）。`,
            en: `This IP has reached the download limit (${settings.maxDownloadsPerIp}).` },
          { siteTitle: settings.siteTitle });
      }
    }
  }

  // 名额必须在所有闸门之后占用：被密码/验证码/限流挡掉的请求不该烧掉 max_downloads
  if (row.max_downloads) {
    const r = await env.db.prepare(
      `UPDATE shares SET download_count = download_count + 1 WHERE id = ?1 AND download_count < ?2`
    ).bind(token, row.max_downloads).run();
    if ((r.meta.changes ?? 0) === 0)
      return errorPage(req, 410, { zh: "下载次数已达上限", en: "Download Limit Reached" },
        { zh: `名额已用完。`, en: `Quota used up.` });
  }

  return streamFile(req, env, ctx, row, token, "share");
}

/**
 * GET /d/:id —— 直链下载（独立入口，走 direct_links 表）
 * 轻量鉴权：封禁 → 过期/撤销/次数 → 流量限额 → 重复下载 → 原子扣次 → 推流
 * 不走密码/Turnstile/OAuth（直链设计就是"拿了就能下"）
 */
export async function handleDirectDownload(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  token: string
): Promise<Response> {
  const ip = clientIp(req);
  const ua = req.headers.get("user-agent") ?? "";
  const country = req.headers.get("cf-ipcountry") ?? "";
  const settings = await getSettings(env);

  const urlCode = new URL(req.url).searchParams.get("code");
  const headerCode = req.headers.get("x-activation-code");
  const activationCode = (urlCode || headerCode || "").trim().toUpperCase() || null;

  const [codeRow, ban, row] = await Promise.all([
    activationCode ? findCodeByString(env, activationCode) : Promise.resolve(null),
    env.db.prepare("SELECT reason, expires_at FROM banned_ips WHERE ip = ?1")
      .bind(ip).first<{ reason: string | null; expires_at: number | null }>(),
    getDirectLink(env, token),
  ]);

  if (activationCode && codeRow) {
    const check = checkCodeUsable(codeRow as any);
    if (!check.ok) {
      return errorPage(req, 403,
        { zh: "激活码不可用", en: "Activation Code Unavailable" },
        { zh: check.message || check.reason || "该激活码不可用", en: check.message || "This activation code is not available" },
        { siteTitle: settings.siteTitle });
    }
    activateCodeIfNeeded(env, codeRow!).catch(() => {});
  }

  if (ban) {
    if (ban.expires_at && ban.expires_at < Date.now()) {
      env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(ip).run().catch(() => {});
    } else {
      return errorPage(req, 403, { zh: "访问已被封禁", en: "Access Banned" },
        { zh: ban.reason || "该 IP 已被暂时封禁。", en: ban.reason || "This IP has been banned." });
    }
  }

  if (!row) return errorPage(req, 404, { zh: "直链不存在", en: "Not Found" },
    { zh: "该直链无效或已被管理员删除。", en: "Direct link invalid or removed." });
  if (row.revoked) return errorPage(req, 410, { zh: "直链已失效", en: "Link Revoked" },
    { zh: "该直链已被撤销。", en: "Direct link revoked." });
  if (row.expires_at && row.expires_at < Date.now()) return errorPage(req, 410, { zh: "直链已过期", en: "Link Expired" },
    { zh: "该直链已超过有效期。", en: "Direct link expired." });
  if (row.max_downloads && row.download_count >= row.max_downloads) return errorPage(req, 410, { zh: "下载次数已达上限", en: "Download Limit Reached" },
    { zh: `名额已用完。`, en: `Quota used up.` });

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (!whitelisted && !usingCode && settings.trafficLimitBytes > 0 && settings.trafficUsedBytes >= settings.trafficLimitBytes) {
      return errorPage(req, 503, { zh: "下载已暂停", en: "Downloads Paused" },
        { zh: "本月流量已达预设限额。", en: "Monthly traffic quota reached." },
        { siteTitle: settings.siteTitle });
    }
  }

  {
    const whitelisted = isAdminWhitelisted(ip, settings.adminIps);
    const usingCode = !!codeRow;
    if (!whitelisted && !usingCode && settings.maxDownloadsPerIp > 0) {
      const since = settings.countWindowHours > 0 ? Date.now() - settings.countWindowHours * 3600_000 : 0;
      const { c } = (await env.db.prepare(
        "SELECT COUNT(*) AS c FROM download_logs WHERE share_id = ?1 AND ip = ?2 AND created_at > ?3"
      ).bind(token, ip, since).first<{ c: number }>()) ?? { c: 0 };
      if (c >= settings.maxDownloadsPerIp) {
        if (settings.autoBan) {
          const expiresAt = settings.banHours > 0 ? Date.now() + settings.banHours * 3600_000 : null;
          await env.db.prepare(
            `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
          ).bind(ip, `重复下载直链「${row.name}」超过 ${settings.maxDownloadsPerIp} 次`, Date.now(), expiresAt).run();
        }
        return errorPage(req, 403, { zh: "重复下载被拦截", en: "Duplicate Download Blocked" },
          { zh: `同一 IP 在统计窗口内下载此资源的次数已达上限。`, en: `IP download limit reached.` },
          { siteTitle: settings.siteTitle });
      }
    }
  }

  // 名额必须在所有闸门之后占用（同上：被限流挡掉的请求不该烧次数）
  if (row.max_downloads) {
    const r = await env.db.prepare(
      `UPDATE direct_links SET download_count = download_count + 1 WHERE id = ?1 AND download_count < ?2`
    ).bind(token, row.max_downloads).run();
    if ((r.meta.changes ?? 0) === 0)
      return errorPage(req, 410, { zh: "下载次数已达上限", en: "Download Limit Reached" },
        { zh: `名额已用完。`, en: `Quota used up.` });
  }

  return streamFile(req, env, ctx, row, token, "direct");
}

/* ════════════════════════════════════════════════════════════════════
 * streamFile —— 共享的"从存储后端读取 → 流式输出 → 后台记日志"逻辑
 * handleDownload（分享链接）和 handleDirectDownload（直链）共用此函数
 * ════════════════════════════════════════════════════════════════════ */

interface StreamFileRow {
  file_id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  download_name?: string | null;
}

async function streamFile(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  row: StreamFileRow,
  token: string,
  kind: "share" | "direct"
): Promise<Response> {
  const ip = clientIp(req);
  const ua = req.headers.get("user-agent") ?? "";
  const country = req.headers.get("cf-ipcountry") ?? "";
  const settings = await getSettings(env);

  const urlCode = new URL(req.url).searchParams.get("code");
  const headerCode = req.headers.get("x-activation-code");
  const activationCode = (urlCode || headerCode || "").trim().toUpperCase() || null;
  const codeRow = activationCode ? await findCodeByString(env, activationCode) : null;

  const range = parseRange(req.headers.get("range"), row.size);
  let obj;
  try {
    const st = await storage(env);
    obj = await st.get(row.key, range ? { offset: range.offset, length: range.length } : undefined);
  } catch (err: any) {
    console.error("[download] storage error:", err);
    return errorPage(req, 502, { zh: "存储服务错误", en: "Storage Error" },
      { zh: "无法从存储后端读取文件。", en: "Cannot read file from storage." });
  }
  if (!obj)
    return errorPage(req, 404, { zh: "文件不存在", en: "File Not Found" },
      { zh: "文件可能已被删除。", en: "File may have been deleted." });

  const headers = new Headers();
  headers.set("content-type", obj.contentType);
  headers.set("etag", obj.etag);
  headers.set("accept-ranges", "bytes");
  headers.set("cache-control", "no-store");
  const displayName = row.download_name || row.name;
  const { addSecurityHeaders } = await import("./pages");
  addSecurityHeaders(headers, { isDownload: true });
  const { inline } = applyDisposition(headers, {
    mime: obj.contentType,
    name: displayName,
    inline: wantsInline(req),
  });
  // 默认下载 CSP 是 default-src 'none'，媒体分片续读与 PDF 会被它自己挡掉
  if (inline) headers.set("Content-Security-Policy", inlineCsp());
  const servedLen = range ? range.length : obj.size;
  headers.set("content-length", String(servedLen));
  if (range) {
    headers.set("content-range", `bytes ${range.offset}-${range.offset + servedLen - 1}/${row.size}`);
  }

  // 后台记录
  const bytes = servedLen;
  const codeId = codeRow ? codeRow.code : null;
  ctx.waitUntil(
    (async () => {
      const { browser, os } = parseUA(ua);

      if (env.analytics) {
        try {
          const latitude = req.headers.get("cf-ip-latitude") ?? "";
          const longitude = req.headers.get("cf-ip-longitude") ?? "";
          env.analytics.writeDataPoint({
            blobs: [
              country, row.name, browser, os, token,
              codeId ?? "none", latitude, longitude,
              settings.storageProvider || "r2",
            ],
            doubles: [bytes, 1],
            indexes: [token],
          });
        } catch { /* ignore */ }
      }

      await env.db.prepare(
        `INSERT INTO download_logs(share_id, file_id, file_name, ip, ua, browser, os, country, bytes, created_at, activation_code)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`
      )
        // 直链也记 download_logs —— share_id 字段存 direct link token 方便追踪
        .bind(token, row.file_id, row.name, ip, ua.slice(0, 500), browser, os, country, bytes, Date.now(), codeId)
        .run();
      await addTraffic(env, bytes);
      if (codeRow) {
        const dr = await deductQuota(env, codeRow, bytes);
        if (!dr.ok) {
          console.warn(`[code-decline] code=${codeRow.code} reason=${dr.reason} msg=${dr.message}`);
        }
      }
    })()
  );

  return new Response(obj.body, { status: range ? 206 : 200, headers });
}
