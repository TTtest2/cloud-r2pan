import type { Env } from "./types";
import { ensureSchema, randomId } from "./db";
import { generateCodes, makeBatchId, formatCodeStatus, findCodeByString } from "./codes";
import { getSettings, updateSettings } from "./settings";
import { checkAdminKey, createSession, verifySession, clientIp, rateLimit, requireAdminIp } from "./auth";
import { pickLang } from "./i18n";
import { hashPassword } from "./public";
import { parseUA } from "./ua";
import { encryptSecret, decryptSecret, totpGenerateSecret, totpVerify, totpUri, totpGenerateRecoveryCodes, sha256Hex, safeEqual, hashWebDAVPassword } from "./crypto";
import { getStorageProvider as storage } from "./storage";
import { getFolderTree, createFolder, invalidateFolderTree } from "./folders";
import { applyDisposition, inlineCsp, wantsInline } from "./preview";
import { escapeLike } from "./market";
import { deleteObjects, purgeFiles, removeFiles, restoreFiles } from "./trash";
import { runScheduledCleanup } from "./cron";
import { formatPickupCode, revealPickupCode } from "./pickup";
import { CHUNK_MAX, abortUpload, completeUpload, initUpload, partTooLarge, uploadPart } from "./uploads";
import { claimBySha, dedupeAfterWrite, etagFp, findBySha, normalizeSha } from "./dedupe";
import {
  declaredSize,
  formatMb,
  postUploadRejection,
  preUploadRejection,
  usedStorageBytes,
} from "./limits";

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json;charset=utf-8", "cache-control": "no-store" },
  });

/** API 错误消息跟随请求语言（浏览器 fetch 自动携带 Accept-Language） */
const msg = (req: Request, zh: string, en: string) => (pickLang(req) === "zh" ? zh : en);

/** 安全解析 JSON body（失败返回空对象） */
async function readJson<T>(req: Request): Promise<Partial<T>> {
  try {
    return (await req.json()) as Partial<T>;
  } catch {
    return {};
  }
}

/** 单次批量操作的上限：D1 的 IN(...) 参数个数与 R2 并发删除都需要有界 */
const BATCH_LIMIT = 100;

/** 规范化批量接口的 ids：只接受字符串、去重去空、截断到上限 */
function normalizeIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (typeof item !== "string") continue;
    const id = item.trim();
    if (id && id.length <= 64) seen.add(id);
    if (seen.size >= BATCH_LIMIT) break;
  }
  return [...seen];
}

interface ShareForDirect {
  id: string;
  file_id: string;
  created_at: number;
  expires_at: number | null;
  max_downloads: number | null;
  download_name: string | null;
}

/**
 * 派生直链的语句：写一行 direct_links + 把 id 回指到 shares.direct_id。
 * notes 存 `share:<分享 id>`，分享被删除/清理时按它反查删除直链。
 * ⚠️ 有密码的分享不要派生直链 —— 直链按设计不带密码，派生等于绕过密码。
 */
function shareDirectLinkStmts(env: Env, dlId: string, s: ShareForDirect) {
  return [
    env.db.prepare(
      `INSERT INTO direct_links(id, file_id, created_at, expires_at, max_downloads, download_name, notes)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)`
    ).bind(dlId, s.file_id, s.created_at, s.expires_at, s.max_downloads, s.download_name, `share:${s.id}`),
    env.db.prepare("UPDATE shares SET direct_id = ?1 WHERE id = ?2").bind(dlId, s.id),
  ];
}

/** 文件名清洗：去路径分隔符 / 控制字符，限长 */
function sanitizeName(name: string): string {
  const cleaned = name
    .replace(/[\\/]/g, "_")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, 180);
  return cleaned || "unnamed";
}

async function requireAuth(req: Request, env: Env): Promise<Response | null> {
  if (!(await verifySession(req, env))) {
    return json({ error: "unauthorized" }, 401);
  }
  return null;
}

/** 写入登录安全日志 —— 登录/登出/失败/限流 全部走这里 */
async function writeLoginLog(
  env: Env,
  req: Request,
  action: string,
  result: string,
  reason: string | null = null
): Promise<void> {
  try {
    const ua = req.headers.get("user-agent") ?? "";
    const { browser, os } = parseUA(ua);
    // Cloudflare 下 country 由 CF-IPCountry 头提供
    const country = req.headers.get("cf-ipcountry") ?? null;
    await env.db
      .prepare(
        "INSERT INTO login_logs(action, ip, ua, browser, os, country, result, reason, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
      )
      .bind(action, clientIp(req), ua || null, browser, os, country, result, reason, Date.now())
      .run();
  } catch {
    // 日志写入失败不影响主流程
  }
}

/** 上传被体积闸门挡下时的提示文案 */
function uploadRejectMsg(req: Request, r: { code: "too_large" | "quota_exceeded"; limitBytes: number }): string {
  const mb = formatMb(r.limitBytes);
  return r.code === "too_large"
    ? msg(req, `文件超过单个文件上限 ${mb} MB`, `File exceeds the ${mb} MB per-file limit`)
    : msg(req, `存储空间不足（总配额 ${mb} MB）`, `Not enough storage quota (limit ${mb} MB)`);
}

export async function handleAdminApi(
  req: Request,
  env: Env,
  ctx: ExecutionContext,
  path: string
): Promise<Response> {
  try {
  await ensureSchema(env);
  const method = req.method;
  const url = new URL(req.url);

  // ── IP 白名单门禁 ── 空 = 不限制；非空 = 仅白名单 IP 能访问所有 /api/admin/*
  {
    const s = await getSettings(env);
    const denied = requireAdminIp(clientIp(req), s.adminIps);
    if (denied) return denied;
  }

  // ── 登录（支持 2FA 两阶段） ──────────────────────────────
  if (path === "/api/admin/login" && method === "POST") {
    const ip = clientIp(req);
    if (!rateLimit(ip, "admin-login")) {
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "rate_limited"));
      return json({ error: msg(req, "尝试过于频繁，请稍后再试", "Too many attempts. Please try again later.") }, 429);
    }
    if (!env.admin)
      return json({ error: msg(req, "未设置 admin 密钥，请先执行 npx wrangler secret put admin", "admin is not set. Run: npx wrangler secret put admin") }, 500);
    const body = await readJson<{ key: string; code?: string }>(req);
    if (!body.key || !checkAdminKey(env, body.key)) {
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "invalid_key"));
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }

    // 密码正确 —— 检查是否需要 2FA
    const s = await getSettings(env);
    const needsTotp = s.totpEnabled && s.totpSecretCipher;

    if (needsTotp) {
      // 没带 code → 要求 2FA
      if (!body.code) {
        return json({ need_2fa: true });
      }

      // 先尝试 TOTP
      const totpSecret = await decryptSecret(s.totpSecretCipher!, env.admin);
      const totpOk = totpSecret ? await totpVerify(totpSecret, body.code) : false;

      if (totpOk) {
        ctx.waitUntil(writeLoginLog(env, req, "login", "success", "2fa_totp"));
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            "content-type": "application/json;charset=utf-8",
            "set-cookie": await createSession(env, url.protocol === "https:"),
            "cache-control": "no-store",
          },
        });
      }

      // TOTP 失败 → 尝试恢复码（两种来源：Cloudflare Secret 优先 → D1 恢复码）
      const normalized = body.code.replace(/\s+/g, "").toUpperCase();

      // 1) Cloudflare Secret 恢复码（超级恢复，用一次不消耗）
      const cloudflareRecovery = env.totp_recovery?.trim();
      if (cloudflareRecovery && safeEqual(normalized, cloudflareRecovery.replace(/\s+/g, "").toUpperCase())) {
        // 用了云变量恢复码 —— 自动重置 2FA（因为 secret 可能丢了）
        await updateSettings(env, {
          totp_enabled: "0",
          totp_secret_cipher: "",
          totp_recovery_hash: "",
        });
        ctx.waitUntil(writeLoginLog(env, req, "login", "success", "recovery_cloudflare"));
        return new Response(JSON.stringify({ ok: true, recovery_used: true, totp_reset: true }), {
          headers: {
            "content-type": "application/json;charset=utf-8",
            "set-cookie": await createSession(env, url.protocol === "https:"),
            "cache-control": "no-store",
          },
        });
      }

      // 2) D1 存储的恢复码列表（消耗型，用一次删一次）
      if (s.totpRecoveryHash) {
        const hashes = s.totpRecoveryHash.split(",").filter(Boolean);
        const inputHash = await sha256Hex(normalized);
        let matched = -1;
        for (let i = 0; i < hashes.length; i++) {
          if (safeEqual(inputHash, hashes[i])) { matched = i; break; }
        }
        if (matched >= 0) {
          // 从列表中移除已使用的恢复码
          hashes.splice(matched, 1);
          await updateSettings(env, { totp_recovery_hash: hashes.join(",") });
          // 恢复码通过 → 自动重置 2FA
          await updateSettings(env, {
            totp_enabled: "0",
            totp_secret_cipher: "",
          });
          ctx.waitUntil(writeLoginLog(env, req, "login", "success", "recovery_code"));
          return new Response(JSON.stringify({ ok: true, recovery_used: true, totp_reset: true }), {
            headers: {
              "content-type": "application/json;charset=utf-8",
              "set-cookie": await createSession(env, url.protocol === "https:"),
              "cache-control": "no-store",
            },
          });
        }
      }

      // 都不对
      ctx.waitUntil(writeLoginLog(env, req, "login", "fail", "invalid_2fa"));
      return json({ error: msg(req, "2FA 验证失败", "Invalid 2FA code") }, 401);
    }

    // 无需 2FA → 直接登录成功
    ctx.waitUntil(writeLoginLog(env, req, "login", "success"));
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": await createSession(env, url.protocol === "https:"),
        "cache-control": "no-store",
      },
    });
  }

  // ── 以下全部需要会话 ──────────────────────────────
  const unauthorized = await requireAuth(req, env);
  if (unauthorized) return unauthorized;

  // 登出
  if (path === "/api/admin/logout" && method === "POST") {
    const secure = url.protocol === "https:";
    ctx.waitUntil(writeLoginLog(env, req, "logout", "success"));
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json;charset=utf-8",
        "set-cookie": `cd_admin=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`,
      },
    });
  }

  // 会话检查
  if (path === "/api/admin/session" && method === "GET") {
    const s = await getSettings(env);
    return json({
      ok: true,
      site_title: s.siteTitle,
      max_upload_mb: Math.round(s.maxUploadBytes / 1024 ** 2),
      totp_enabled: s.totpEnabled,
      cloudflare_recovery: !!env.totp_recovery,
      recovery_remaining: s.totpRecoveryHash ? s.totpRecoveryHash.split(",").filter(Boolean).length : 0,
    });
  }

  // ── 概览统计 ──────────────────────────────────────
  if (path === "/api/admin/stats" && method === "GET") {
    // getSettings 内部已做跨月自动兜底，无需此处重复检查和 DB 写入
    const s = await getSettings(env);
    const [files, trash, liveBytes, trashBytes, shares, activeShares, totalDownloads, todayStat, chartRows, recent, banned] =
      await Promise.all([
        env.db.prepare("SELECT COUNT(*) AS c FROM files WHERE deleted_at IS NULL").first<{ c: number }>(),
        env.db.prepare("SELECT COUNT(*) AS c FROM files WHERE deleted_at IS NOT NULL").first<{ c: number }>(),
        // 按 key 去重后再求和：内容去重让多个 files 行共用同一个对象
        env.db.prepare("SELECT COALESCE(SUM(s), 0) AS bytes FROM (SELECT MIN(size) AS s FROM files GROUP BY key)").first<{ bytes: number }>(),
        env.db
          .prepare("SELECT COALESCE(SUM(s), 0) AS bytes FROM (SELECT MIN(size) AS s FROM files WHERE deleted_at IS NOT NULL GROUP BY key)")
          .first<{ bytes: number }>(),
        env.db.prepare("SELECT COUNT(*) AS c FROM shares WHERE origin IS NULL OR origin <> 'drop'").first<{ c: number }>(),
        env.db.prepare(
          "SELECT COUNT(*) AS c FROM shares WHERE (origin IS NULL OR origin <> 'drop') AND revoked = 0 AND (expires_at IS NULL OR expires_at > ?1) AND (max_downloads IS NULL OR download_count < max_downloads)"
        )
          .bind(Date.now())
          .first<{ c: number }>(),
        env.db.prepare("SELECT COALESCE(SUM(downloads), 0) AS c FROM traffic_stats").first<{ c: number }>(),
        env.db.prepare("SELECT bytes, downloads FROM traffic_stats WHERE day = ?1")
          .bind(new Date().toISOString().slice(0, 10))
          .first<{ bytes: number; downloads: number }>(),
        env.db.prepare(
          "SELECT day, bytes, downloads FROM traffic_stats WHERE day >= date('now', '-13 days') ORDER BY day"
        ).all<{ day: string; bytes: number; downloads: number }>(),
        env.db.prepare(
          "SELECT file_name, ip, browser, os, country, bytes, created_at FROM download_logs ORDER BY id DESC LIMIT 10"
        ).all(),
        env.db.prepare("SELECT COUNT(*) AS c FROM banned_ips").first<{ c: number }>(),
      ]);

    // 补齐 14 天（无数据的天补 0）
    const chartMap = new Map((chartRows.results ?? []).map((r) => [r.day, r]));
    const chart: { day: string; downloads: number; bytes: number }[] = [];
    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400_000).toISOString().slice(0, 10);
      const r = chartMap.get(d);
      chart.push({ day: d, downloads: r?.downloads ?? 0, bytes: r?.bytes ?? 0 });
    }

    const quotaExceeded = s.trafficLimitBytes > 0 && s.trafficUsedBytes >= s.trafficLimitBytes;
    return json({
      traffic: {
        used: s.trafficUsedBytes,
        limit: s.trafficLimitBytes,
        percent:
          s.trafficLimitBytes > 0
            ? Math.min(100, Math.round((s.trafficUsedBytes / s.trafficLimitBytes) * 100))
            : 0,
        month: s.trafficMonth,
        quota_exceeded: quotaExceeded,
      },
      counts: {
        files: files?.c ?? 0,
        trash_files: trash?.c ?? 0,
        shares: shares?.c ?? 0,
        active_shares: activeShares?.c ?? 0,
        downloads_total: totalDownloads?.c ?? 0,
        downloads_today: todayStat?.downloads ?? 0,
        bytes_today: todayStat?.bytes ?? 0,
        banned: banned?.c ?? 0,
      },
      storage: {
        // 按对象 key 去重后的真实占用：files.size 是写入时存储回报的字节数，
        // 回收站里的对象还没删，所以它也算占用 —— 只有彻底清除才会腾出空间。
        bytes: Number(liveBytes?.bytes ?? 0) || 0,
        files: files?.c ?? 0,
        trash_bytes: Number(trashBytes?.bytes ?? 0) || 0,
      },
      chart,
      recent: recent.results ?? [],
    });
  }

  // ── 文件夹：列表（整棵树平铺，带完整路径，便于按位置筛选与展示） ──
  if (path === "/api/admin/folders" && method === "GET") {
    const { results } = await env.db.prepare(
      `SELECT fo.id, fo.name, fo.parent_id, fo.created_at,
              (SELECT COUNT(*) FROM files fl WHERE fl.folder_id = fo.id AND fl.deleted_at IS NULL) AS file_count,
              (SELECT COALESCE(SUM(fl.size), 0) FROM files fl WHERE fl.folder_id = fo.id AND fl.deleted_at IS NULL) AS total_size,
              (SELECT COUNT(*) FROM folders ch WHERE ch.parent_id = fo.id) AS subfolder_count
       FROM folders fo`
    ).all<{ id: string; name: string; parent_id: string | null; created_at: number; file_count: number; total_size: number; subfolder_count: number }>();
    const tree = await getFolderTree(env);
    const folders = (results ?? [])
      .map((f) => ({ ...f, path: tree.pathOf(f.id) ?? "/" + f.name }))
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return json({ folders });
  }

  // ── 文件夹：创建（parent_id 省略 = 顶层） ──────────────────
  if (path === "/api/admin/folders" && method === "POST") {
    const body = await req.json().catch(() => null) as { name?: string; parent_id?: string | null } | null;
    const raw = (body?.name ?? "").trim();
    if (!raw) return json({ error: msg(req, "文件夹名不能为空", "Folder name is required") }, 400);
    const name = sanitizeName(raw);

    let parentId: string | null = null;
    if (body?.parent_id) {
      const tree = await getFolderTree(env);
      if (!tree.get(body.parent_id)) {
        return json({ error: msg(req, "父目录不存在", "Parent folder not found") }, 404);
      }
      parentId = body.parent_id;
    }
    const created = await createFolder(env, parentId, name);
    if (!created) {
      return json({ error: msg(req, "同一位置下已有同名文件夹", "A folder with this name already exists here") }, 409);
    }
    return json({ ok: true, id: created.id, name: created.name, parent_id: created.parent_id }, 201);
  }

  // ── 文件夹：删除（只允许空目录；非空要把内容先移走） ────────
  const folderMatch = /^\/api\/admin\/folders\/([^/]+)$/.exec(path);
  if (folderMatch && method === "DELETE") {
    const folderId = decodeURIComponent(folderMatch[1]);
    const folder = await env.db.prepare("SELECT id FROM folders WHERE id = ?1").bind(folderId).first();
    if (!folder) return json({ error: msg(req, "文件夹不存在", "Folder not found") }, 404);
    const busy = await env.db.prepare(
      `SELECT (SELECT COUNT(*) FROM files WHERE folder_id = ?1 AND deleted_at IS NULL) AS files,
              (SELECT COUNT(*) FROM folders WHERE parent_id = ?1) AS subfolders`
    ).bind(folderId).first<{ files: number; subfolders: number }>();
    if ((busy?.files ?? 0) > 0 || (busy?.subfolders ?? 0) > 0) {
      return json({
        error: msg(req, "文件夹非空，请先把里面的文件和子目录移走或删掉", "Folder is not empty — move or delete its contents first"),
        files: busy?.files ?? 0,
        subfolders: busy?.subfolders ?? 0,
      }, 409);
    }
    await env.db.prepare("DELETE FROM folders WHERE id = ?1").bind(folderId).run();
    invalidateFolderTree();
    return json({ ok: true });
  }

  // ── 文件列表（分页 + 搜索 + 排序）──────────────────
  if (path === "/api/admin/files" && method === "GET") {
    const sp = new URL(req.url).searchParams;
    const folder = sp.get("folder"); // null=全部 | "root"=根目录 | 其他=文件夹 id
    const trashed = sp.get("trash") === "1"; // 1 = 回收站视图
    const q = sp.get("q")?.trim() ?? "";
    const page = Math.max(1, Number(sp.get("page")) || 1);
    const size = Math.min(200, Math.max(10, Number(sp.get("size")) || 50));
    const sortKey = sp.get("sort");
    const sortCol =
      sortKey === "name" ? "f.name COLLATE NOCASE"
      : sortKey === "size" ? "f.size"
      : sortKey === "deleted_at" ? "f.deleted_at"
      : "f.uploaded_at";
    const sortDir = sp.get("dir") === "asc" ? "ASC" : "DESC";

    const frags: string[] = [trashed ? "f.deleted_at IS NOT NULL" : "f.deleted_at IS NULL"];
    const binds: (string | number)[] = [];
    if (folder === "root") frags.push("f.folder_id IS NULL");
    else if (folder) {
      frags.push("f.folder_id = ?");
      binds.push(folder);
    }
    if (q) {
      frags.push("f.name LIKE ? ESCAPE '\\'");
      binds.push(`%${escapeLike(q)}%`);
    }
    const where = frags.length ? `WHERE ${frags.join(" AND ")}` : "";

    // 分享数/下载数用一次聚合 JOIN 取，避免每个文件两趟相关子查询
    const shareAgg = `(SELECT file_id, COUNT(*) AS n, COALESCE(SUM(download_count), 0) AS d FROM shares GROUP BY file_id)`;
    const [countRow, pageRows] = await Promise.all([
      env.db.prepare(`SELECT COUNT(*) AS c FROM files f ${where}`).bind(...binds).first<{ c: number }>(),
      env.db
        .prepare(
          `SELECT f.id, f.name, f.size, f.mime, f.uploaded_at, f.folder_id, f.deleted_at,
                  COALESCE(sc.n, 0) AS share_count, COALESCE(sc.d, 0) AS download_count
           FROM files f LEFT JOIN ${shareAgg} sc ON sc.file_id = f.id
           ${where} ORDER BY ${sortCol} ${sortDir}, f.id DESC LIMIT ? OFFSET ?`
        )
        .bind(...binds, size, (page - 1) * size)
        .all<{ id: string; name: string; size: number; mime: string; uploaded_at: number; folder_id: string | null; deleted_at: number | null; share_count: number; download_count: number }>(),
    ]);
    return json({ files: pageRows?.results ?? [], total: countRow?.c ?? 0, page, size });
  }

  // ── 管理员直接下载（不生成分享/直链，也不受公开下载的那套限制约束） ──
  const fileDlMatch = /^\/api\/admin\/files\/([^/]+)\/download$/.exec(path);
  if (fileDlMatch && method === "GET") {
    const file = await env.db
      .prepare("SELECT name, key FROM files WHERE id = ?1 AND deleted_at IS NULL")
      .bind(fileDlMatch[1])
      .first<{ name: string; key: string }>();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    const st = await storage(env);
    const obj = await st.get(file.key);
    if (!obj) return json({ error: msg(req, "存储对象已不存在", "Object missing in storage") }, 404);
    const headers = new Headers({
      "content-type": obj.contentType,
      "content-length": String(obj.size),
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "accept-ranges": "bytes",
    });
    const { inline } = applyDisposition(headers, {
      mime: obj.contentType,
      name: file.name,
      inline: wantsInline(req),
    });
    if (inline) headers.set("Content-Security-Policy", inlineCsp());
    if (obj.etag) headers.set("etag", obj.etag);
    return new Response(obj.body, { headers });
  }

  // ── 上传文件（原始流式 body，文件名放 X-File-Name 头） ──
  if (path === "/api/admin/upload" && method === "POST") {
    const rawName = req.headers.get("x-file-name");
    if (!rawName) return json({ error: msg(req, "缺少 X-File-Name 头", "Missing X-File-Name header") }, 400);
    let name: string;
    try {
      name = sanitizeName(decodeURIComponent(rawName));
    } catch {
      name = sanitizeName(rawName);
    }
    if (!req.body) return json({ error: msg(req, "请求体为空", "Empty request body") }, 400);
    const folderRaw = req.headers.get("x-folder-id")?.trim();
    let folderId: string | null = null;
    if (folderRaw) {
      const fo = await env.db.prepare("SELECT id FROM folders WHERE id = ?1").bind(folderRaw).first<{ id: string }>();
      if (!fo) return json({ error: msg(req, "目标文件夹不存在", "Target folder not found") }, 400);
      folderId = fo.id;
    }
    const id = randomId(14);
    const key = `files/${id}`;
    const mime = req.headers.get("content-type") || "application/octet-stream";
    const st = await storage(env);

    const settings = await getSettings(env);
    const declared = declaredSize(req);
    const usedBytes = settings.storageQuotaBytes > 0 ? await usedStorageBytes(env) : 0;
    const rejected = preUploadRejection(settings, usedBytes, declared);
    if (rejected) {
      return json(
        { error: rejected.code, limit_mb: formatMb(rejected.limitBytes), message: uploadRejectMsg(req, rejected) },
        rejected.status
      );
    }

    // 注意：这里必须把 req.body 原样交给存储层。R2 只接受"长度已知"的流
    // （请求体本身或 FixedLengthStream），任何 pipeThrough 包装都会让它报
    // "Provided readable stream must have a known length" —— 上传全挂。
    let resultSize = 0;
    let resultEtag: string | null = null;
    try {
      const res = await st.put(key, req.body, {
        contentType: mime,
        contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
        contentLength: declared ?? undefined,
      });
      resultSize = res.size;
      resultEtag = res.etag ?? null;
    } catch (err: any) {
      await st.delete(key).catch(() => {});
      return json({ error: msg(req, "存储写入失败", "Storage write failed"), detail: String(err?.message || err) }, 500);
    }
    // 上限与配额都按落盘后的真实体积判定（声明的 Content-Length 可以撒谎，size 不能）
    const rejectedAfter = postUploadRejection(settings, usedBytes, resultSize);
    if (rejectedAfter) {
      // 对象删掉、行不落库，等于什么都没发生
      await st.delete(key).catch(() => {});
      return json(
        { error: rejectedAfter.code, limit_mb: formatMb(rejectedAfter.limitBytes), message: uploadRejectMsg(req, rejectedAfter) },
        rejectedAfter.status
      );
    }
    // ── Bug #4 修复：D1 写入失败时清理已写入的 storage 对象 ──
    const sha = normalizeSha(req.headers.get("x-content-sha256"));
    const etagFpVal = resultEtag ? etagFp(resultEtag) : null;
    try {
      await env.db.prepare(
        "INSERT INTO files(id, key, name, size, mime, uploaded_at, folder_id, sha256, etag) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"
      )
        .bind(id, key, name, resultSize, mime, Date.now(), folderId, sha, etagFpVal)
        .run();
    } catch (dbErr) {
      ctx.waitUntil(st.delete(key).catch(() => {}));
      console.error("upload: D1 insert failed, cleaned up storage object:", dbErr);
      return json({ error: msg(req, "数据库写入失败，请重试", "Database write failed. Please retry.") }, 500);
    }
    const { deduped } = await dedupeAfterWrite(env, { id, key, size: resultSize }, etagFpVal, (k) => {
      ctx.waitUntil(st.delete(k).catch(() => {}));
    });
    return json({ ok: true, id, name, size: resultSize, deduped }, 201);
  }

  // ── 秒传：先查指纹，命中就只写一行元数据（一个字节都不用传） ──
  if (path === "/api/admin/upload/check" && method === "POST") {
    const body = await readJson<{ sha256?: string; size?: number }>(req);
    const sha = normalizeSha(body.sha256);
    if (!sha) return json({ ok: false, error: "bad_sha256" }, 400);
    const size = Number.isFinite(body.size) && (body.size as number) > 0 ? Math.floor(body.size as number) : null;
    const hit = await findBySha(env, sha, size);
    return json({ ok: true, exists: !!hit, id: hit?.id ?? null, name: hit?.name ?? null, size: hit?.size ?? null });
  }

  if (path === "/api/admin/upload/claim" && method === "POST") {
    const body = await readJson<{ sha256?: string; name?: string; folder_id?: string | null }>(req);
    const sha = normalizeSha(body.sha256);
    if (!sha) return json({ error: msg(req, "缺少或非法的 sha256", "Missing or malformed sha256") }, 400);
    const raw = (body.name ?? "").trim();
    if (!raw) return json({ error: msg(req, "缺少文件名", "Missing file name") }, 400);
    let name: string;
    try {
      name = sanitizeName(decodeURIComponent(raw));
    } catch {
      name = sanitizeName(raw);
    }
    let folderId: string | null = null;
    const rawFolder = typeof body.folder_id === "string" ? body.folder_id.trim() : "";
    if (rawFolder) {
      const fo = await env.db.prepare("SELECT id FROM folders WHERE id = ?1").bind(rawFolder).first<{ id: string }>();
      if (!fo) return json({ error: msg(req, "目标文件夹不存在", "Target folder not found") }, 400);
      folderId = fo.id;
    }
    const settings = await getSettings(env);
    const r = await claimBySha(env, settings, sha, name, folderId, randomId);
    if (!r.ok) return json({ error: r.code, ...(r.limitMb ? { limit_mb: r.limitMb } : {}) }, r.status);
    return json({ ok: true, id: r.id, name: r.name, size: r.size, deduped: true }, 201);
  }

  // ── 分片上传：init / part / complete / abort（突破单请求 100 MB） ──
  if (path === "/api/admin/upload/init" && method === "POST") {
    const body = await readJson<{ name?: string; size?: number; mime?: string; sha256?: string; folder_id?: string | null }>(req);
    const raw = (body.name ?? "").trim();
    if (!raw) return json({ error: msg(req, "缺少文件名", "Missing file name") }, 400);
    let name: string;
    try {
      name = sanitizeName(decodeURIComponent(raw));
    } catch {
      name = sanitizeName(raw);
    }
    let folderId: string | null = null;
    const rawFolder = typeof body.folder_id === "string" ? body.folder_id.trim() : "";
    if (rawFolder) {
      const fo = await env.db.prepare("SELECT id FROM folders WHERE id = ?1").bind(rawFolder).first<{ id: string }>();
      if (!fo) return json({ error: msg(req, "目标文件夹不存在", "Target folder not found") }, 400);
      folderId = fo.id;
    }
    const declared = Number.isFinite(body.size) && (body.size as number) > 0 ? Math.floor(body.size as number) : null;
    const settings = await getSettings(env);
    const r = await initUpload(env, settings, {
      name,
      mime: (body.mime ?? "").trim() || "application/octet-stream",
      folder_id: folderId,
      size: declared,
      sha256: body.sha256 ?? null,
    });
    if (!r.ok) {
      return json(
        { error: r.rejection.code, limit_mb: formatMb(r.rejection.limitBytes), message: uploadRejectMsg(req, r.rejection) },
        r.rejection.status
      );
    }
    return json({ ok: true, id: r.session.id, chunk_size: r.chunk_size, max_part_mb: formatMb(CHUNK_MAX) }, 201);
  }

  if (path === "/api/admin/upload/part" && method === "PUT") {
    const sp = new URL(req.url).searchParams;
    const sessionId = sp.get("id") ?? "";
    const partNumber = Number(sp.get("part"));
    if (!sessionId || !req.body) return json({ error: msg(req, "缺少会话或请求体", "Missing session id or body") }, 400);
    if (partTooLarge(req)) {
      return json({ error: "too_large", limit_mb: formatMb(CHUNK_MAX) }, 413);
    }
    try {
      const r = await uploadPart(env, sessionId, partNumber, req.body);
      if (!r.ok) return json({ error: r.code }, r.status);
      return json({ ok: true, etag: r.etag, part: partNumber });
    } catch (err: any) {
      console.error("upload part failed:", err);
      return json({ error: msg(req, "分片上传失败，请重试", "Part upload failed. Please retry.") }, 502);
    }
  }

  if (path === "/api/admin/upload/complete" && method === "POST") {
    const body = await readJson<{ id?: string; parts?: { partNumber: number; etag: string }[] }>(req);
    if (!body.id) return json({ error: msg(req, "缺少会话 id", "Missing upload id") }, 400);
    const settings = await getSettings(env);
    try {
      const r = await completeUpload(env, settings, body.id, body.parts ?? []);
      if (!r.ok) {
        return json(
          {
            error: r.code,
            ...(typeof r.limitBytes === "number" ? { limit_mb: formatMb(r.limitBytes) } : {}),
          },
          r.status
        );
      }
      return json({ ok: true, id: r.id, name: r.name, size: r.size, deduped: r.deduped }, 201);
    } catch (err: any) {
      console.error("upload complete failed:", err);
      return json({ error: msg(req, "合并分片失败，请重试", "Multipart complete failed. Please retry.") }, 502);
    }
  }

  if (path === "/api/admin/upload" && method === "DELETE") {
    const sessionId = new URL(req.url).searchParams.get("id") ?? "";
    if (!sessionId) return json({ error: msg(req, "缺少会话 id", "Missing upload id") }, 400);
    const ok = await abortUpload(env, sessionId);
    if (!ok) return json({ error: msg(req, "会话不存在或已结束", "Upload session not found") }, 404);
    return json({ ok: true });
  }

  // ── 批量删除文件（默认进回收站；mode=purge 彻底删除） ──
  if (path === "/api/admin/files/batch-delete" && method === "POST") {
    const body = await readJson<{ ids?: string[]; mode?: string }>(req);
    const ids = normalizeIds(body.ids);
    if (!ids.length) return json({ error: msg(req, "请先选择文件", "No files selected") }, 400);
    const s = await getSettings(env);
    const r =
      body.mode === "purge"
        ? await purgeFiles(env, ids)
        : await removeFiles(env, ids, s.trashRetentionDays);
    const gone = r.soft + r.purged;
    if (!gone) return json({ error: msg(req, "文件不存在或已被删除", "Files not found") }, 404);
    ctx.waitUntil(deleteObjects(env, r.keys));
    return json({
      ok: true,
      deleted: gone,
      trashed: r.soft,
      purged: r.purged,
      skipped: ids.length - gone,
    });
  }

  // ── 批量移动文件到文件夹（folder_id 为空 = 移回根目录） ──
  if (path === "/api/admin/files/batch-move" && method === "POST") {
    const body = await readJson<{ ids?: string[]; folder_id?: string | null }>(req);
    const ids = normalizeIds(body.ids);
    if (!ids.length) return json({ error: msg(req, "请先选择文件", "No files selected") }, 400);
    const rawFolder = typeof body.folder_id === "string" ? body.folder_id.trim() : "";
    let folderId: string | null = null;
    if (rawFolder) {
      const fo = await env.db.prepare("SELECT id FROM folders WHERE id = ?1").bind(rawFolder).first<{ id: string }>();
      if (!fo) return json({ error: msg(req, "目标文件夹不存在", "Target folder not found") }, 400);
      folderId = fo.id;
    }
    const ph = ids.map((_, i) => `?${i + 2}`).join(", ");
    const r = await env.db
      .prepare(`UPDATE files SET folder_id = ?1 WHERE id IN (${ph}) AND deleted_at IS NULL`)
      .bind(folderId, ...ids)
      .run();
    return json({ ok: true, moved: r.meta.changes ?? 0, folder_id: folderId });
  }

  // ── 删除文件：默认进回收站，?purge=1 立即彻底删除 ──────────
  const fileMatch = /^\/api\/admin\/files\/([^/]+)$/.exec(path);
  if (fileMatch && method === "DELETE") {
    const fileId = decodeURIComponent(fileMatch[1]);
    const s = await getSettings(env);
    const purge = url.searchParams.get("purge") === "1";
    const r = purge
      ? await purgeFiles(env, [fileId])
      : await removeFiles(env, [fileId], s.trashRetentionDays);
    if (!r.soft && !r.purged) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    ctx.waitUntil(deleteObjects(env, r.keys));
    return json({ ok: true, trashed: r.soft > 0 });
  }

  // ── 回收站：恢复 / 彻底删除 / 清空 ─────────────────────
  if (path === "/api/admin/files/batch-restore" && method === "POST") {
    const body = await readJson<{ ids?: string[] }>(req);
    const ids = normalizeIds(body.ids);
    if (!ids.length) return json({ error: msg(req, "请先选择文件", "No files selected") }, 400);
    const r = await restoreFiles(env, ids);
    if (!r.restored) return json({ error: msg(req, "文件不在回收站里", "Nothing to restore") }, 404);
    invalidateFolderTree();
    return json({ ok: true, restored: r.restored, moved_to_root: r.toRoot });
  }

  if (path === "/api/admin/trash/cleanup" && method === "POST") {
    const body = await readJson<{ all?: boolean; ids?: string[] }>(req);
    const s = await getSettings(env);
    let ids = normalizeIds(body.ids);
    if (!ids.length) {
      // 未指定 id：清到期条目（all=1 时不看保留期，整站倒空）
      const { results } = await env.db
        .prepare(
          body.all
            ? `SELECT id FROM files WHERE deleted_at IS NOT NULL ORDER BY deleted_at LIMIT 100`
            : `SELECT id FROM files WHERE deleted_at IS NOT NULL AND deleted_at < ?1 ORDER BY deleted_at LIMIT 100`
        )
        .bind(...(body.all ? [] : [Date.now() - s.trashRetentionDays * 86_400_000]))
        .all<{ id: string }>();
      ids = (results ?? []).map((r) => r.id);
    }
    if (!ids.length) return json({ ok: true, purged: 0 });
    const r = await purgeFiles(env, ids);
    ctx.waitUntil(deleteObjects(env, r.keys));
    return json({ ok: true, purged: r.purged });
  }

  // ── 创建分享 ──────────────────────────────────────
  if (path === "/api/admin/shares" && method === "POST") {
    const body = await readJson<{
      file_id?: string | null;
      folder_id?: string | null;
      expires_hours: number | null;
      max_downloads: number | null;
      password: string | null;
      download_name?: string | null;
      is_market?: boolean;
      market_title?: string | null;
      market_desc?: string | null;
    }>(req);
    const fileId = (body.file_id ?? "").trim();
    const folderId = (body.folder_id ?? "").trim();
    if (!fileId && !folderId)
      return json({ error: msg(req, "缺少 file_id 或 folder_id", "Missing file_id or folder_id") }, 400);
    if (fileId && folderId)
      return json({ error: msg(req, "一条分享只能指向文件或目录之一", "A share points at either a file or a folder") }, 400);

    let isFolder = false;
    if (fileId) {
      const file = await env.db.prepare("SELECT id FROM files WHERE id = ?1 AND deleted_at IS NULL").bind(fileId).first();
      if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    } else {
      const fo = await env.db.prepare("SELECT id FROM folders WHERE id = ?1").bind(folderId).first();
      if (!fo) return json({ error: msg(req, "目录不存在", "Folder not found") }, 404);
      isFolder = true;
    }
    const expiresAt =
      body.expires_hours && body.expires_hours > 0 ? Date.now() + body.expires_hours * 3600_000 : null;
    const maxDownloads =
      body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
    const password =
      typeof body.password === "string" && body.password.trim() ? body.password.trim() : null;
    const passwordHash = password ? await hashPassword(password) : null;
    // 可逆加密存储密码明文，管理员之后可查看
    const passwordCipher = password ? await encryptSecret(password, env.admin) : null;
    const downloadName =
      !isFolder && typeof body.download_name === "string" && body.download_name.trim() ? body.download_name.trim() : null;
    const isMarket = !isFolder && body.is_market ? 1 : 0;
    if (isMarket && passwordHash) {
      return json({ error: msg(req, "带访问口令的分享不能上架到下载市场", "Password-protected shares cannot be listed on the marketplace") }, 400);
    }
    const marketTitle =
      typeof body.market_title === "string" && body.market_title.trim() ? body.market_title.trim() : null;
    const marketDesc =
      typeof body.market_desc === "string" && body.market_desc.trim() ? body.market_desc.trim() : null;
    const id = randomId(10);
    await env.db.prepare(
      `INSERT INTO shares(id, file_id, folder_id, created_at, expires_at, max_downloads, password_hash, password_cipher, download_name, is_market, market_title, market_desc)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`
    )
      .bind(id, isFolder ? "" : fileId, isFolder ? folderId : null, Date.now(), expiresAt, maxDownloads, passwordHash, passwordCipher, downloadName, isMarket, marketTitle, marketDesc)
      .run();

    let directUrl: string | null = null;
    if (!passwordHash && !isFolder) {
      const dlId = randomId(12);
      await env.db.batch(shareDirectLinkStmts(env, dlId, {
        id,
        file_id: fileId,
        created_at: Date.now(),
        expires_at: expiresAt,
        max_downloads: maxDownloads,
        download_name: downloadName,
      }));
      directUrl = `/d/${dlId}`;
    }
    return json({ ok: true, id, url: `/s/${id}`, direct_url: directUrl }, 201);
  }

  // ── 分享列表（分页；口令只在显式点开时单独取，不随列表批量下发） ──
  if (path === "/api/admin/shares" && method === "GET") {
    const sp = new URL(req.url).searchParams;
    const limit = Math.min(500, Math.max(1, Number(sp.get("limit")) || 100));
    const offset = Math.max(0, Number(sp.get("offset")) || 0);
    const totalRow = await env.db.prepare("SELECT COUNT(*) AS c FROM shares WHERE origin IS NULL OR origin <> 'drop'").first<{ c: number }>();
    const { results } = await env.db.prepare(
      `SELECT s.id, s.file_id, s.folder_id, s.created_at, s.expires_at, s.max_downloads, s.download_count, s.revoked,
              s.password_hash, s.download_name, s.direct_id,
              s.is_market, s.market_views, s.market_title, s.market_desc,
              f.name AS file_name, f.size AS file_size, f.mime AS file_mime,
              fo.name AS folder_name
       FROM shares s
       LEFT JOIN files f ON f.id = s.file_id
       LEFT JOIN folders fo ON fo.id = s.folder_id
       WHERE s.origin IS NULL OR s.origin <> 'drop'
       ORDER BY s.created_at DESC LIMIT ?1 OFFSET ?2`
    ).bind(limit, offset).all();
    const now = Date.now();
    // 这个功能上线前创建的分享没有直链，这里按需补建（有密码的不补：直链等于绕过密码；
    // 目录分享也不补 —— /d/:id 指向的是单个文件；投递行更不补 —— 那等于绕过取件码）
    const backfill = (results ?? []).filter((s: any) =>
      !s.direct_id && !s.folder_id && !s.password_hash && !s.revoked &&
      !(s.expires_at && s.expires_at < now) &&
      !(s.max_downloads && s.download_count >= s.max_downloads));
    if (backfill.length) {
      const stmts = backfill.flatMap((s: any) => {
        const dlId = randomId(12);
        s.direct_id = dlId;
        return shareDirectLinkStmts(env, dlId, s);
      });
      await env.db.batch(stmts);
    }
    const shares = (results ?? []).map((s: any) => ({
      ...s,
      kind: s.folder_id ? "folder" : "file",
      display_name: s.folder_id ? `📁 ${s.folder_name ?? "（目录已删除）"}` : s.file_name,
      has_password: !!s.password_hash,
      password_hash: undefined,
      url: `/s/${s.id}`,
      direct_url: s.direct_id ? `/d/${s.direct_id}` : null,
      status: s.revoked
        ? "revoked"
        : s.expires_at && s.expires_at < now
          ? "expired"
          : s.max_downloads && s.download_count >= s.max_downloads
            ? "maxed"
            : "active",
    }));
    return json({ shares, total: totalRow?.c ?? 0, limit, offset });
  }

  // ── 查看单条分享的访问口令（管理员主动点开时才解密） ──
  const sharePwMatch = /^\/api\/admin\/shares\/([^/]+)\/password$/.exec(path);
  if (sharePwMatch && method === "GET") {
    const shareId = decodeURIComponent(sharePwMatch[1]);
    const row = await env.db
      .prepare("SELECT password_cipher FROM shares WHERE id = ?1")
      .bind(shareId)
      .first<{ password_cipher: string | null }>();
    if (!row) return json({ error: msg(req, "分享不存在", "Share not found") }, 404);
    if (!row.password_cipher) return json({ password: null });
    const password = await decryptSecret(row.password_cipher, env.admin);
    return json({ password: password ?? "" });
  }

  // ── 手动跑一轮定时清理（与 cron 同一个入口，返回报告） ──
  if (path === "/api/admin/cleanup/run" && method === "POST") {
    const report = await runScheduledCleanup(env);
    return json(report);
  }

  // ── 清理失效分享（过期 / 已撤销 / 达上限） + 孤儿 files + 孤儿 R2 对象 ──
  if (path === "/api/admin/shares/cleanup" && method === "POST") {
    const now = Date.now();
    // 1. 删除失效 shares（投递行不在这里 —— 只删分享行会把投件文件变成看不见
    //    却仍在计费的孤儿；它的行与对象由 cron 的到期投递那一步一起清）
    const deleted = await env.db.prepare(
      "DELETE FROM shares WHERE (origin IS NULL OR origin <> 'drop') AND (revoked = 1 OR (expires_at IS NOT NULL AND expires_at < ?1) OR (max_downloads IS NOT NULL AND download_count >= max_downloads))"
    )
      .bind(now)
      .run();

    // 1b. 派生直链跟着分享一起清掉（只认 notes='share:xxx'，手工建的直链不动）
    await env.db.prepare(
      `DELETE FROM direct_links
       WHERE notes LIKE 'share:%'
         AND id NOT IN (SELECT direct_id FROM shares WHERE direct_id IS NOT NULL)`
    ).run();

    // 2. 查出孤儿 files：没有任何 share 引用的文件（LEFT JOIN 反查）
    //    ⚠️ 必须排除回收站条目 —— 它们的分享行是故意保留的，删除时机由保留期说了算
    const orphans = await env.db.prepare(
      `SELECT f.id, f.key FROM files f
       LEFT JOIN shares s ON s.file_id = f.id
       WHERE s.id IS NULL AND f.deleted_at IS NULL`
    ).all<{ id: string; key: string }>();

    const orphanIds = (orphans.results ?? []).map((o) => o.id);

    // 3. 孤儿 files 进回收站 —— 只是没被分享过而已，不该被一键销毁；
    //    保留期为 0 时（关闭回收站）才等价于原来的物理删除。
    const s = await getSettings(env);
    const trashed = await removeFiles(env, orphanIds, s.trashRetentionDays);
    ctx.waitUntil(deleteObjects(env, trashed.keys));

    return json({
      ok: true,
      deleted_shares: deleted.meta.changes ?? 0,
      orphan_files: trashed.soft + trashed.purged,
      orphan_trashed: trashed.soft,
    });
  }

  // ── 撤销/删除分享 ─────────────────────────────────
  const shareMatch = /^\/api\/admin\/shares\/([^/]+)$/.exec(path);
  if (shareMatch && method === "DELETE") {
    const r = await env.db.prepare("DELETE FROM shares WHERE id = ?1").bind(shareMatch[1]).run();
    if ((r.meta.changes ?? 0) === 0) return json({ error: msg(req, "分享不存在", "Share not found") }, 404);
    await env.db.prepare("DELETE FROM direct_links WHERE notes = ?1").bind(`share:${shareMatch[1]}`).run();
    return json({ ok: true });
  }

  // ── 批量撤销分享（只删链接，文件保留） ────────────
  if (path === "/api/admin/shares/batch-revoke" && method === "POST") {
    const body = await readJson<{ ids?: string[] }>(req);
    const ids = normalizeIds(body.ids);
    if (!ids.length) return json({ error: msg(req, "请先选择分享链接", "No shares selected") }, 400);
    const ph = ids.map((_, i) => `?${i + 1}`).join(", ");
    const r = await env.db.prepare(`DELETE FROM shares WHERE id IN (${ph})`).bind(...ids).run();
    await env.db
      .prepare(`DELETE FROM direct_links WHERE notes IN (${ph})`)
      .bind(...ids.map((i) => `share:${i}`))
      .run();
    return json({ ok: true, revoked: r.meta.changes ?? 0, skipped: ids.length - (r.meta.changes ?? 0) });
  }

  // ── 投递箱：匿名投递的专用视图（正常文件列表照样看得见它们，因为它们真的占配额） ──
  if (path === "/api/admin/pickups" && method === "GET") {
    const sp = new URL(req.url).searchParams;
    const limit = Math.min(200, Math.max(1, Number(sp.get("limit")) || 100));
    const offset = Math.max(0, Number(sp.get("offset")) || 0);
    const { results } = await env.db
      .prepare(
        `SELECT sh.id AS share_id, f.id AS file_id, f.name, f.size, f.mime, f.key,
                sh.created_at, sh.expires_at, sh.origin_ip, sh.download_count, sh.pickup_claims, sh.revoked,
                CASE WHEN sh.max_downloads = 1 THEN 1 ELSE 0 END AS one_shot
         FROM shares sh JOIN files f ON f.id = sh.file_id
         WHERE sh.origin = 'drop' AND f.deleted_at IS NULL
         ORDER BY sh.created_at DESC LIMIT ?1 OFFSET ?2`
      )
      .bind(limit, offset)
      .all();
    const totals = await env.db
      .prepare(
        `SELECT COUNT(*) AS c, COALESCE(SUM(size), 0) AS bytes FROM (
           SELECT DISTINCT f.key, f.size
           FROM shares sh JOIN files f ON f.id = sh.file_id
           WHERE sh.origin = 'drop' AND f.deleted_at IS NULL
         )`
      )
      .first<{ c: number; bytes: number }>();
    return json({
      drops: results ?? [],
      total: totals?.c ?? 0,
      bytes: totals?.bytes ?? 0,
      quota_bytes: (await getSettings(env)).pickupTotalQuotaBytes,
      limit,
      offset,
    });
  }

  // 取件码只在管理员点"查看码"时单条解密，不随列表批量下发
  const pickupCodeMatch = /^\/api\/admin\/pickups\/([^/]+)\/code$/.exec(path);
  if (pickupCodeMatch && method === "GET") {
    const id = decodeURIComponent(pickupCodeMatch[1]);
    const row = await env.db
      .prepare("SELECT pickup_cipher FROM shares WHERE id = ?1 AND origin = 'drop'")
      .bind(id)
      .first<{ pickup_cipher: string | null }>();
    if (!row) return json({ error: msg(req, "投递不存在", "Drop not found") }, 404);
    const code = await revealPickupCode(env, row.pickup_cipher);
    if (!code) return json({ error: msg(req, "口令密钥换过，旧码无法回看（请重新投递）", "Stored code can no longer be decrypted (admin key changed)") }, 409);
    return json({ ok: true, code: formatPickupCode(code) });
  }

  // 入库：文件挪出投递箱变成普通文件，投递行连同取件码一起消失
  if (path === "/api/admin/pickups/promote" && method === "POST") {
    const body = await readJson<{ ids?: string[]; folder_id?: string | null }>(req);
    const ids = normalizeIds(body.ids);
    if (!ids.length) return json({ error: msg(req, "请先选择投件", "No files selected") }, 400);
    const raw = (body.folder_id ?? "").trim();
    let folderId: string | null = null;
    if (raw && raw !== "root") {
      const fo = await env.db.prepare("SELECT id FROM folders WHERE id = ?1").bind(raw).first();
      if (!fo) return json({ error: msg(req, "目标文件夹不存在", "Target folder not found") }, 404);
      folderId = raw;
    }
    const ph = ids.map((_, i) => `?${i + 1}`).join(", ");
    const { results } = await env.db
      .prepare(
        `SELECT f.id FROM shares sh JOIN files f ON f.id = sh.file_id
         WHERE sh.origin = 'drop' AND f.id IN (${ph})`
      )
      .bind(...ids)
      .all<{ id: string }>();
    const mine = (results ?? []).map((r) => r.id);
    if (!mine.length) return json({ error: msg(req, "选中的不是投件", "Nothing to promote") }, 404);
    const ph2 = mine.map((_, i) => `?${i + 1}`).join(", ");
    await env.db.batch([
      env.db.prepare(`UPDATE files SET folder_id = ?${mine.length + 1} WHERE id IN (${ph2})`).bind(...mine, folderId),
      env.db.prepare(`DELETE FROM shares WHERE origin = 'drop' AND file_id IN (${ph2})`).bind(...mine),
    ]);
    invalidateFolderTree();
    return json({ ok: true, promoted: mine.length, folder_id: folderId, code_revoked: true });
  }

  // 销毁：不等保留期，立刻连行带对象清掉
  if (path === "/api/admin/pickups/destroy" && method === "POST") {
    const body = await readJson<{ ids?: string[] }>(req);
    const ids = normalizeIds(body.ids);
    if (!ids.length) return json({ error: msg(req, "请先选择投件", "No files selected") }, 400);
    const ph = ids.map((_, i) => `?${i + 1}`).join(", ");
    const { results } = await env.db
      .prepare(
        `SELECT f.id FROM shares sh JOIN files f ON f.id = sh.file_id
         WHERE sh.origin = 'drop' AND f.id IN (${ph})`
      )
      .bind(...ids)
      .all<{ id: string }>();
    const mine = (results ?? []).map((r) => r.id);
    if (!mine.length) return json({ error: msg(req, "选中的不是投件", "Nothing to destroy") }, 404);
    const r = await purgeFiles(env, mine);
    ctx.waitUntil(deleteObjects(env, r.keys));
    return json({ ok: true, destroyed: r.purged });
  }

  // ── 编辑市场字段（开关 + 标题 + 描述） ────────────
  const shareMarketMatch = /^\/api\/admin\/shares\/([^/]+)\/market$/.exec(path);
  if (shareMarketMatch && method === "PUT") {
    const id = shareMarketMatch[1];
    const body = await readJson<{ is_market?: boolean; market_title?: string | null; market_desc?: string | null }>(req);
    const existing = await env.db
      .prepare("SELECT id, password_hash, folder_id FROM shares WHERE id = ?1")
      .bind(id)
      .first<{ id: string; password_hash: string | null; folder_id: string | null }>();
    if (!existing) return json({ error: msg(req, "分享不存在", "Share not found") }, 404);
    if (body.is_market && existing.password_hash) {
      return json({ error: msg(req, "带访问口令的分享不能上架到下载市场", "Password-protected shares cannot be listed on the marketplace") }, 400);
    }
    if (body.is_market && existing.folder_id) {
      return json({ error: msg(req, "目录分享不能上架到下载市场（条目必须指向单个文件）", "Directory shares cannot be listed on the marketplace (entries must point at a single file)") }, 400);
    }
    const isMarket = body.is_market === undefined ? null : (body.is_market ? 1 : 0);
    const mTitle = typeof body.market_title === "string" ? (body.market_title.trim() || null) : null;
    const mDesc = typeof body.market_desc === "string" ? (body.market_desc.trim() || null) : null;
    // 动态拼 SQL，只更新传入的字段
    const sets: string[] = [];
    const binds: any[] = [];
    if (isMarket !== null) { sets.push("is_market = ?" + (binds.length + 1)); binds.push(isMarket); }
    if (body.market_title !== undefined) { sets.push("market_title = ?" + (binds.length + 1)); binds.push(mTitle); }
    if (body.market_desc !== undefined) { sets.push("market_desc = ?" + (binds.length + 1)); binds.push(mDesc); }
    if (sets.length === 0) return json({ ok: true });
    binds.push(id);
    await env.db.prepare(`UPDATE shares SET ${sets.join(", ")} WHERE id = ?${binds.length}`).bind(...binds).run();
    return json({ ok: true });
  }

  // ── 管理端市场列表 ──────────────────────────────────
  if (path === "/api/admin/market" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("size")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const filterOnly = url.searchParams.get("only") === "market" ? " AND s.is_market = 1" : "";
    const where = q
      ? ` AND (f.name LIKE ?1 OR COALESCE(s.market_title, '') LIKE ?1 OR COALESCE(s.market_desc, '') LIKE ?1)`
      : "";
    const base = `FROM shares s JOIN files f ON f.id = s.file_id WHERE s.revoked = 0 AND (s.origin IS NULL OR s.origin <> 'drop')${filterOnly}${where}`;
    const countRow: any = await env.db.prepare(`SELECT COUNT(*) AS c ${base}`).bind(...(q ? [`%${q}%`] : [])).first();
    const total = countRow?.c ?? 0;
    const { results }: any = await env.db.prepare(
      `SELECT s.id, s.file_id, s.created_at, s.download_count, s.is_market, s.market_views, s.market_title, s.market_desc,
              f.name AS file_name, f.size AS file_size
       ${base} ORDER BY s.created_at DESC LIMIT ?${q ? 2 : 1} OFFSET ?${q ? 3 : 2}`
    ).bind(...(q ? [`%${q}%`, perPage, (page - 1) * perPage] : [perPage, (page - 1) * perPage])).all();
    return json({ total, page, size: perPage, rows: results ?? [] });
  }

  // ── 下载记录（分页 + 筛选） ────────────────────────
  if (path === "/api/admin/logs" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("per_page")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const where: string[] = [];
    const binds: (string | number)[] = [];
    if (q) {
      where.push("(ip LIKE ?1 OR file_name LIKE ?1)");
      binds.push(`%${q}%`);
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [total, rows] = await Promise.all([
      env.db.prepare(`SELECT COUNT(*) AS c FROM download_logs ${whereSql}`)
        .bind(...binds)
        .first<{ c: number }>(),
      env.db.prepare(
        `SELECT id, share_id, file_name, ip, browser, os, country, bytes, created_at
         FROM download_logs ${whereSql} ORDER BY id DESC LIMIT ?${binds.length + 1} OFFSET ?${binds.length + 2}`
      )
        .bind(...binds, perPage, (page - 1) * perPage)
        .all(),
    ]);
    return json({
      logs: rows.results ?? [],
      total: total?.c ?? 0,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil((total?.c ?? 0) / perPage)),
    });
  }

  // ── 清除记录（全部 / N 天前） ──────────────────────
  if (path === "/api/admin/logs" && method === "DELETE") {
    const mode = url.searchParams.get("mode") ?? "all";
    let sql: string;
    const binds: number[] = [];
    if (mode === "older") {
      const days = Math.max(1, Number(url.searchParams.get("days")) || 30);
      sql = "DELETE FROM download_logs WHERE created_at < ?1";
      binds.push(Date.now() - days * 86400_000);
    } else {
      sql = "DELETE FROM download_logs";
    }
    const r = await env.db.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 封禁列表 ──────────────────────────────────────
  if (path === "/api/admin/bans" && method === "GET") {
    const { results } = await env.db.prepare(
      "SELECT ip, reason, banned_at, expires_at FROM banned_ips ORDER BY banned_at DESC"
    ).all();
    return json({ bans: results ?? [] });
  }

  // ── 手动封禁 ──────────────────────────────────────
  if (path === "/api/admin/bans" && method === "POST") {
    const body = await readJson<{ ip: string; reason: string; hours: number | null }>(req);
    const ip = body.ip?.trim();
    if (!ip || !/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return json({ error: msg(req, "IP 格式无效", "Invalid IP format") }, 400);
    const expiresAt = body.hours && body.hours > 0 ? Date.now() + body.hours * 3600_000 : null;
    await env.db.prepare(
      `INSERT INTO banned_ips(ip, reason, banned_at, expires_at) VALUES(?1, ?2, ?3, ?4)
       ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = excluded.banned_at, expires_at = excluded.expires_at`
    )
      .bind(ip, body.reason?.slice(0, 200) || "管理员手动封禁", Date.now(), expiresAt)
      .run();
    return json({ ok: true }, 201);
  }

  // ── 解封 ──────────────────────────────────────────
  const banMatch = /^\/api\/admin\/bans\/([^/]+)$/.exec(path);
  if (banMatch && method === "DELETE") {
    await env.db.prepare("DELETE FROM banned_ips WHERE ip = ?1").bind(decodeURIComponent(banMatch[1])).run();
    return json({ ok: true });
  }

  // ── 登录安全日志（分页 + 筛选） ────────────────────────
  if (path === "/api/admin/login-logs" && method === "GET") {
    const page = Math.max(1, Number(url.searchParams.get("page")) || 1);
    const perPage = Math.min(100, Math.max(10, Number(url.searchParams.get("per_page")) || 20));
    const q = url.searchParams.get("q")?.trim();
    const action = url.searchParams.get("action")?.trim();
    const result = url.searchParams.get("result")?.trim();
    const where: string[] = [];
    const binds: (string | number)[] = [];
    let idx = 1;
    if (q) {
      where.push(`(ip LIKE ?${idx} OR browser LIKE ?${idx} OR os LIKE ?${idx})`);
      binds.push(`%${q}%`);
      idx++;
    }
    if (action) {
      where.push(`action = ?${idx}`);
      binds.push(action);
      idx++;
    }
    if (result) {
      where.push(`result = ?${idx}`);
      binds.push(result);
      idx++;
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const [total, rows] = await Promise.all([
      env.db.prepare(`SELECT COUNT(*) AS c FROM login_logs ${whereSql}`).bind(...binds).first<{ c: number }>(),
      env.db
        .prepare(
          `SELECT id, action, ip, browser, os, country, result, reason, created_at
           FROM login_logs ${whereSql} ORDER BY id DESC LIMIT ?${idx} OFFSET ?${idx + 1}`
        )
        .bind(...binds, perPage, (page - 1) * perPage)
        .all(),
    ]);
    // 统计：最近 24h 登录失败次数
    const fail24h = await env.db
      .prepare(
        "SELECT COUNT(*) AS c FROM login_logs WHERE action = 'login' AND result = 'fail' AND created_at >= ?1"
      )
      .bind(Date.now() - 24 * 3600_000)
      .first<{ c: number }>();
    return json({
      logs: rows.results ?? [],
      total: total?.c ?? 0,
      page,
      per_page: perPage,
      pages: Math.max(1, Math.ceil((total?.c ?? 0) / perPage)),
      fail_last_24h: fail24h?.c ?? 0,
    });
  }

  // ── 清除登录日志（全部 / N 天前） ──────────────────────
  if (path === "/api/admin/login-logs" && method === "DELETE") {
    const mode = url.searchParams.get("mode") ?? "all";
    let sql: string;
    const binds: number[] = [];
    if (mode === "older") {
      const days = Math.max(1, Number(url.searchParams.get("days")) || 30);
      sql = "DELETE FROM login_logs WHERE created_at < ?1";
      binds.push(Date.now() - days * 86400_000);
    } else {
      sql = "DELETE FROM login_logs";
    }
    const r = await env.db.prepare(sql).bind(...binds).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 2FA 状态查询 ───────────────────────────────────
  if (path === "/api/admin/2fa/status" && method === "GET") {
    const s = await getSettings(env);
    return json({
      enabled: s.totpEnabled && !!s.totpSecretCipher,
      cloudflare_recovery: !!env.totp_recovery,
      recovery_remaining: s.totpRecoveryHash ? s.totpRecoveryHash.split(",").filter(Boolean).length : 0,
    });
  }

  // ── 2FA Setup：生成新 secret（未启用，需要 verify+enable 才生效） ──
  if (path === "/api/admin/2fa/setup" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    // 如果已经启用，需要先 disable 再 setup（或者覆盖）
    const secret = totpGenerateSecret();
    const s = await getSettings(env);
    const siteTitle = s.siteTitle || "cloud-r2pan";
    const uri = totpUri(secret, siteTitle, "admin");
    return json({
      secret, // 仅本次返回，前端展示二维码用
      uri,
    });
  }

  // ── 2FA Enable：验证通过后写入 settings（加密存储）并生成恢复码 ──
  if (path === "/api/admin/2fa/enable" && method === "POST") {
    const body = await readJson<{ admin_key: string; code: string; secret: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    if (!/^[A-Z2-7]{16,}$/.test((body.secret || "").toUpperCase())) {
      return json({ error: msg(req, "Secret 格式无效", "Invalid secret format") }, 400);
    }
    const code = (body.code || "").trim();
    if (!/^\d{6}$/.test(code)) {
      return json({ error: msg(req, "请输入 6 位验证码", "Please enter 6-digit code") }, 400);
    }
    const secret = body.secret!.toUpperCase();
    const ok = await totpVerify(secret, code);
    if (!ok) {
      return json({ error: msg(req, "验证码错误", "Invalid verification code") }, 401);
    }
    // 验证通过 → 加密存 secret + 生成恢复码
    const cipher = await encryptSecret(secret, env.admin);
    const recoveryCodes = totpGenerateRecoveryCodes(8);
    const recoveryHash = (await Promise.all(recoveryCodes.map((c) => sha256Hex(c.replace(/\s+/g, ""))))).join(",");
    await updateSettings(env, {
      totp_enabled: "1",
      totp_secret_cipher: cipher,
      totp_recovery_hash: recoveryHash,
    });
    return json({
      ok: true,
      recovery_codes: recoveryCodes, // 只这一次明文返回，前端提示用户保存
    });
  }

  // ── 2FA Disable：关闭 2FA（需验证 admin key） ──
  if (path === "/api/admin/2fa/disable" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    await updateSettings(env, {
      totp_enabled: "0",
      totp_secret_cipher: "",
      totp_recovery_hash: "",
    });
    return json({ ok: true });
  }

  // ── 重新生成恢复码（覆盖旧的，旧的全部失效） ──
  if (path === "/api/admin/2fa/regen-recovery" && method === "POST") {
    const body = await readJson<{ admin_key: string }>(req);
    if (!body.admin_key || !checkAdminKey(env, body.admin_key)) {
      return json({ error: msg(req, "管理密钥错误", "Invalid admin key") }, 401);
    }
    const s = await getSettings(env);
    if (!s.totpEnabled || !s.totpSecretCipher) {
      return json({ error: msg(req, "2FA 未启用", "2FA is not enabled") }, 400);
    }
    const recoveryCodes = totpGenerateRecoveryCodes(8);
    const recoveryHash = (await Promise.all(recoveryCodes.map((c) => sha256Hex(c.replace(/\s+/g, ""))))).join(",");
    await updateSettings(env, { totp_recovery_hash: recoveryHash });
    return json({ ok: true, recovery_codes: recoveryCodes });
  }

  // ══════════════════════════════════════════════════════
  // 直链（Direct Link）CRUD —— 与分享链接完全独立
  //   POST   /api/admin/direct-links            创建
  //   GET    /api/admin/direct-links            列表
  //   GET    /api/admin/direct-links/:id        详情
  //   PUT    /api/admin/direct-links/:id        更新（过期/次数/撤销/备注）
  //   DELETE /api/admin/direct-links/:id        删除
  // ══════════════════════════════════════════════════════

  // ── 创建直链 ──
  if (path === "/api/admin/direct-links" && method === "POST") {
    const body = await readJson<{
      file_id: string;
      expires_hours: number | null;
      max_downloads: number | null;
      download_name?: string | null;
      notes?: string | null;
    }>(req);
    if (!body.file_id) return json({ error: msg(req, "缺少 file_id", "Missing file_id") }, 400);
    const file = await env.db.prepare("SELECT id FROM files WHERE id = ?1 AND deleted_at IS NULL").bind(body.file_id).first();
    if (!file) return json({ error: msg(req, "文件不存在", "File not found") }, 404);
    const expiresAt =
      body.expires_hours && body.expires_hours > 0 ? Date.now() + body.expires_hours * 3600_000 : null;
    const maxDownloads =
      body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
    const downloadName =
      typeof body.download_name === "string" && body.download_name.trim() ? body.download_name.trim() : null;
    const notes =
      typeof body.notes === "string" && body.notes.trim() ? body.notes.trim().slice(0, 200) : null;
    const id = randomId(12);
    await env.db.prepare(
      `INSERT INTO direct_links(id, file_id, created_at, expires_at, max_downloads, download_name, notes)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)`
    )
      .bind(id, body.file_id, Date.now(), expiresAt, maxDownloads, downloadName, notes)
      .run();
    return json({ ok: true, id, url: `/d/${id}` }, 201);
  }

  // ── 直链列表 ──
  if (path === "/api/admin/direct-links" && method === "GET") {
    const q = new URL(req.url).searchParams.get("q")?.trim();
    const where = q
      ? ` AND (f.name LIKE ?1 OR COALESCE(dl.notes,'') LIKE ?1)`
      : "";
    const bindVals = q ? [`%${q}%`] : [];
    const { results } = await env.db
      .prepare(
        `SELECT dl.id, dl.file_id, dl.created_at, dl.expires_at, dl.max_downloads, dl.download_count, dl.revoked,
                dl.download_name, dl.notes,
                f.name AS file_name, f.size AS file_size, f.mime AS file_mime
         FROM direct_links dl JOIN files f ON f.id = dl.file_id
         WHERE 1=1 ${where}
         ORDER BY dl.created_at DESC`
      )
      .bind(...bindVals)
      .all();
    const now = Date.now();
    const list = (results ?? []).map((dl: any) => ({
      ...dl,
      url: `/d/${dl.id}`,
      status: dl.revoked
        ? "revoked"
        : dl.expires_at && dl.expires_at < now
          ? "expired"
          : dl.max_downloads && dl.download_count >= dl.max_downloads
            ? "maxed"
            : "active",
    }));
    return json({ direct_links: list });
  }

  // ── 直链详情 / 更新 / 删除 ──
  const dlMatch = /^\/api\/admin\/direct-links\/([^/]+)$/.exec(path);
  if (dlMatch) {
    const dlId = dlMatch[1];

    if (method === "GET") {
      const row = await env.db
        .prepare(
          `SELECT dl.*, f.name AS file_name, f.size AS file_size, f.mime AS file_mime
           FROM direct_links dl JOIN files f ON f.id = dl.file_id
           WHERE dl.id = ?1`
        )
        .bind(dlId)
        .first();
      if (!row) return json({ error: msg(req, "直链不存在", "Direct link not found") }, 404);
      return json({ ...row, url: `/d/${(row as any).id}` });
    }

    if (method === "PUT") {
      const body = await readJson<{
        expires_hours?: number | null;
        max_downloads?: number | null;
        download_name?: string | null;
        notes?: string | null;
        revoked?: boolean;
      }>(req);
      const row: any = await env.db.prepare("SELECT id FROM direct_links WHERE id = ?1").bind(dlId).first();
      if (!row) return json({ error: msg(req, "直链不存在", "Direct link not found") }, 404);

      const sets: string[] = [];
      const vals: any[] = [];

      if (body.expires_hours !== undefined) {
        const exp = body.expires_hours && body.expires_hours > 0
          ? Date.now() + body.expires_hours * 3600_000
          : null;
        sets.push("expires_at = ?" + (vals.length + 1));
        vals.push(exp);
      }
      if (body.max_downloads !== undefined) {
        const m = body.max_downloads && body.max_downloads > 0 ? Math.floor(body.max_downloads) : null;
        sets.push("max_downloads = ?" + (vals.length + 1));
        vals.push(m);
      }
      if (body.download_name !== undefined) {
        const v = typeof body.download_name === "string" && body.download_name.trim()
          ? body.download_name.trim()
          : null;
        sets.push("download_name = ?" + (vals.length + 1));
        vals.push(v);
      }
      if (body.notes !== undefined) {
        const v = typeof body.notes === "string" && body.notes.trim()
          ? body.notes.trim().slice(0, 200)
          : null;
        sets.push("notes = ?" + (vals.length + 1));
        vals.push(v);
      }
      if (typeof body.revoked === "boolean") {
        sets.push("revoked = ?" + (vals.length + 1));
        vals.push(body.revoked ? 1 : 0);
      }

      if (sets.length > 0) {
        vals.push(dlId);
        await env.db.prepare(
          `UPDATE direct_links SET ${sets.join(", ")} WHERE id = ?${vals.length}`
        ).bind(...vals).run();
      }
      return json({ ok: true });
    }

    if (method === "DELETE") {
      // 先查出关联的 file_id 用于清理孤儿
      const before: any = await env.db.prepare("SELECT file_id FROM direct_links WHERE id = ?1").bind(dlId).first();
      const r = await env.db.prepare("DELETE FROM direct_links WHERE id = ?1").bind(dlId).run();
      if ((r.meta.changes ?? 0) === 0) return json({ error: msg(req, "直链不存在", "Direct link not found") }, 404);
      // 清理孤儿：如果该 file_id 不再被任何 shares 或 direct_links 引用，不自动删（管理员可手动清理）
      void before;
      return json({ ok: true });
    }
  }

  // ── 清理失效直链 ──
  if (path === "/api/admin/direct-links/cleanup" && method === "POST") {
    const now = Date.now();
    const r = await env.db.prepare(
      `DELETE FROM direct_links WHERE revoked = 1
        OR (expires_at IS NOT NULL AND expires_at < ?1)
        OR (max_downloads IS NOT NULL AND download_count >= max_downloads)`
    ).bind(now).run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 读取设置 ──────────────────────────────────────
  if (path === "/api/admin/settings" && method === "GET") {
    const s = await getSettings(env);
    // 读 OAuth2 providers 列表给前端展示卡片
    const providers = await env.db
      .prepare("SELECT id, label, provider_type, client_id, scope, enabled, updated_at FROM oauth_providers ORDER BY updated_at DESC")
      .all<{ id: string; label: string; provider_type: string; client_id: string; scope: string; enabled: number; updated_at: number }>();
    const enabledProviders = providers.results.filter((p) => p.enabled);
    return json({
      site_title: s.siteTitle,
      max_upload_mb: s.maxUploadBytes / 1024 ** 2,
      storage_quota_mb: s.storageQuotaBytes / 1024 ** 2,
      trash_retention_days: s.trashRetentionDays,
      pickup_enabled: s.pickupEnabled,
      pickup_max_upload_mb: s.pickupMaxUploadBytes / 1024 ** 2,
      pickup_total_quota_mb: s.pickupTotalQuotaBytes / 1024 ** 2,
      pickup_per_ip_daily_count: s.pickupPerIpDailyCount,
      pickup_per_ip_daily_mb: s.pickupPerIpDailyBytes / 1024 ** 2,
      pickup_code_style: s.pickupCodeStyle,
      pickup_per_ip_daily_claims: s.pickupPerIpDailyClaims,
      pickup_retention_days: s.pickupRetentionDays,
      traffic_limit_gb: s.trafficLimitBytes / 1024 ** 3,
      max_downloads_per_ip: s.maxDownloadsPerIp,
      count_window_hours: s.countWindowHours,
      auto_ban: s.autoBan,
      ban_hours: s.banHours,
      traffic_used_bytes: s.trafficUsedBytes,
      // Turnstile
      turnstile_mode: s.turnstileMode,
      turnstile_threshold: s.turnstileThreshold,
      turnstile_sitekey_override: s.turnstileSitekeyOverride,
      cloudflare_turnstile_sitekey: !!env.turnstile_sitekey,
      cloudflare_turnstile_secret: !!env.turnstile_secret,
      turnstile_secret_configured: !!s.turnstileSecretCipher,
      // OAuth2 总开关 + providers 概要
      oauth_enabled: s.oauthEnabled,
      oauth_providers: providers.results.map((p) => ({
        id: p.id,
        label: p.label,
        provider_type: p.provider_type,
        client_id: p.client_id,
        scope: p.scope,
        enabled: !!p.enabled,
        secret_configured: true, // 列表里不暴露 secret 是否配，只在详情里展示
      })),
      oauth_has_enabled_providers: enabledProviders.length > 0,
      // IP 白名单
      admin_ips: s.adminIps,
      // WebDAV（只报状态，不下发哈希）
      webdav_enabled: s.webdavEnabled,
      webdav_username: s.webdavUsername,
      webdav_has_password: !!s.webdavPasswordHash,
      // 下载市场首页
      home_redirect_market: s.homeRedirectMarket,
      // 激活码浮动按钮
      codes_floating_button_enabled: s.codesFloatingButtonEnabled,
      codes_floating_button_position: s.codesFloatingButtonPosition,
      // 存储后端
      storage_provider: s.storageProvider || "r2",
      storage_has_r2: !!env.r2,
      s3_endpoint: s.s3Endpoint,
      s3_region: s.s3Region,
      s3_bucket: s.s3Bucket,
      s3_access_key_id: s.s3AccessKeyId,
      s3_addressing_style: s.s3AddressingStyle || "path",
      s3_secret_configured: !!s.s3SecretKeyCipher,
      // Analytics Engine
      analytics_engine_available: !!env.analytics,
    });
  }

  // ── 更新设置（可调常数） ──────────────────────────
  if (path === "/api/admin/settings" && method === "PUT") {
    const body = await readJson<Record<string, unknown>>(req);
    const patch: Record<string, string> = {};
    if (typeof body.site_title === "string" && body.site_title.trim())
      patch.site_title = body.site_title.trim().slice(0, 50);
    const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null);
    const gb = num(body.traffic_limit_gb);
    if (gb !== null) patch.traffic_limit_bytes = String(Math.round(gb * 1024 ** 3));
    // 单文件上限：分片上传之后不再受"一次请求 100 MB"约束，
    // 真正的天花板是存储配额与这里设的值（合并完会用真实字节数复核，撒谎没用）
    const uploadMb = num(body.max_upload_mb);
    if (uploadMb !== null) patch.max_upload_mb = String(Math.min(51_200, Math.max(0, Math.floor(uploadMb))));
    const quotaMb = num(body.storage_quota_mb); // 0 = 不限
    if (quotaMb !== null) patch.storage_quota_mb = String(Math.floor(quotaMb));
    // 回收站保留期：0 = 关闭（删除即物理删除）；上限 90 天，因为软删除仍占存储
    const keepDays = num(body.trash_retention_days);
    if (keepDays !== null) patch.trash_retention_days = String(Math.min(90, Math.max(0, Math.floor(keepDays))));
    // 取件码投递 —— 公网可写的口子，四道配额都必须留在这里可收
    if (typeof body.pickup_enabled === "boolean") patch.pickup_enabled = body.pickup_enabled ? "1" : "0";
    const dropMb = num(body.pickup_max_upload_mb);
    if (dropMb !== null) patch.pickup_max_upload_mb = String(Math.min(100, Math.max(0, Math.floor(dropMb))));
    const dropTotalMb = num(body.pickup_total_quota_mb);
    if (dropTotalMb !== null) patch.pickup_total_quota_mb = String(Math.floor(dropTotalMb));
    const dropPerIp = num(body.pickup_per_ip_daily_count);
    if (dropPerIp !== null) patch.pickup_per_ip_daily_count = String(Math.floor(dropPerIp));
    const dropPerIpMb = num(body.pickup_per_ip_daily_mb);
    if (dropPerIpMb !== null) patch.pickup_per_ip_daily_mb = String(Math.floor(dropPerIpMb));
    if (body.pickup_code_style === "alnum8" || body.pickup_code_style === "digits6")
      patch.pickup_code_style = body.pickup_code_style;
    const dropClaims = num(body.pickup_per_ip_daily_claims);
    if (dropClaims !== null) patch.pickup_per_ip_daily_claims = String(Math.floor(dropClaims));
    const dropDays = num(body.pickup_retention_days);
    if (dropDays !== null) patch.pickup_retention_days = String(Math.min(90, Math.max(1, Math.floor(dropDays))));
    const perIp = num(body.max_downloads_per_ip);
    if (perIp !== null) patch.max_downloads_per_ip = String(Math.floor(perIp));
    const window = num(body.count_window_hours);
    if (window !== null) patch.count_window_hours = String(Math.floor(window));
    const banHours = num(body.ban_hours);
    if (banHours !== null) patch.ban_hours = String(Math.floor(banHours));
    if (typeof body.auto_ban === "boolean") patch.auto_ban = body.auto_ban ? "1" : "0";
    // Turnstile
    if (typeof body.turnstile_mode === "string") {
      const m = body.turnstile_mode as string;
      if (["off", "on_share", "on_download", "both"].includes(m)) {
        patch.turnstile_mode = m;
      }
    }
    const th = num(body.turnstile_threshold);
    if (th !== null) patch.turnstile_threshold = String(Math.floor(th));
    if (typeof body.turnstile_sitekey_override === "string") {
      // 允许清空；sitekey 会被分享页写进 HTML 属性，只接受纯字母数字形态
      const sk = body.turnstile_sitekey_override.trim();
      if (sk !== "" && !/^[A-Za-z0-9_-]{10,100}$/.test(sk)) {
        return json({ error: "invalid_turnstile_sitekey" }, 400);
      }
      patch.turnstile_sitekey_override = sk;
    }
    // Turnstile Secret —— 如果 Modal 里传了新密码则加密存；空字符串则清掉；__keep__ 表示保留
    if (typeof body.turnstile_secret === "string") {
      const raw = body.turnstile_secret.trim();
      if (raw === "") {
        patch.turnstile_secret_cipher = "";
      } else if (raw !== "__keep__") {
        const cipher = await encryptSecret(raw, env.admin);
        if (cipher) patch.turnstile_secret_cipher = cipher;
      }
      // raw === "__keep__" 或不传 → 保留原值不动
    }
    // OAuth2 总开关（具体 provider 配置由 /api/admin/oauth/providers CRUD 管理）
    if (typeof body.oauth_enabled === "boolean") patch.oauth_enabled = body.oauth_enabled ? "1" : "0";

    // 管理员 IP 白名单
    if (typeof body.admin_ips === "string") {
      patch.admin_ips = body.admin_ips.trim();
    }

    // ── WebDAV 挂载 ──
    if (typeof body.webdav_enabled === "boolean") patch.webdav_enabled = body.webdav_enabled ? "1" : "0";
    if (typeof body.webdav_username === "string") {
      const u = body.webdav_username.trim().slice(0, 64);
      if (u && !/^[A-Za-z0-9._@-]+$/.test(u)) {
        return json({ error: msg(req, "用户名只允许字母、数字与 . _ @ -", "Username may only contain letters, digits and . _ @ -") }, 400);
      }
      if (u) patch.webdav_username = u;
    }
    if (typeof body.webdav_password === "string") {
      // 空串 = 清掉口令（没有口令时 WebDAV 一律拒绝，等于关掉访问能力）
      if (body.webdav_password === "") patch.webdav_password_hash = "";
      else if (body.webdav_password.length < 8 || body.webdav_password.length > 256) {
        return json({ error: msg(req, "WebDAV 口令需 8-256 位", "WebDAV password must be 8-256 characters") }, 400);
      } else {
        patch.webdav_password_hash = await hashWebDAVPassword(body.webdav_password);
      }
    }

    // 下载市场作为首页
    if (typeof body.home_redirect_market === "boolean") {
      patch.home_redirect_market = body.home_redirect_market ? "1" : "0";
    }

    // 激活码浮动按钮
    if (typeof body.codes_floating_button_enabled === "boolean") {
      patch.codes_floating_button_enabled = body.codes_floating_button_enabled ? "1" : "0";
    }
    if (typeof body.codes_floating_button_position === "string") {
      const pos = body.codes_floating_button_position;
      if (pos === "top-right" || pos === "top-left") {
        patch.codes_floating_button_position = pos;
      }
    }

    // ── 存储后端 ──
    if (typeof body.storage_provider === "string") {
      const sp = body.storage_provider;
      if (sp === "r2" || sp === "s3") {
        patch.storage_provider = sp;
      }
    }
    if (typeof body.s3_endpoint === "string") patch.s3_endpoint = body.s3_endpoint.trim();
    if (typeof body.s3_region === "string") patch.s3_region = body.s3_region.trim();
    if (typeof body.s3_bucket === "string") patch.s3_bucket = body.s3_bucket.trim();
    if (typeof body.s3_access_key_id === "string") patch.s3_access_key_id = body.s3_access_key_id.trim();
    if (typeof body.s3_addressing_style === "string") {
      const style = body.s3_addressing_style;
      if (style === "path" || style === "virtual") patch.s3_addressing_style = style;
    }
    // S3 Secret Access Key —— 和 turnstile_secret 同样的三种处理模式
    if (typeof body.s3_secret_key === "string") {
      const raw = body.s3_secret_key.trim();
      if (raw === "") {
        patch.s3_secret_key_cipher = "";
      } else if (raw !== "__keep__") {
        const cipher = await encryptSecret(raw, env.admin);
        if (cipher) patch.s3_secret_key_cipher = cipher;
      }
      // raw === "__keep__" 或不传 → 保留原值不动
    }

    await updateSettings(env, patch);

    // 单 IP 上限调成不限 / 关掉自动封禁后，要顺手解除此前自动封禁的 IP：
    // 下载入口先查 banned_ips 再看限额，否则管理员会以为设置没生效
    let unbanned = 0;
    if ("max_downloads_per_ip" in patch || "auto_ban" in patch) {
      const after = await getSettings(env);
      if (after.maxDownloadsPerIp === 0 || !after.autoBan) {
        // 只清下载流程自动写入的那批（reason 固定是「重复下载…超过 N 次」），手动封禁不动
        const r = await env.db
          .prepare(`DELETE FROM banned_ips WHERE reason LIKE '重复下载%超过%次%'`)
          .run();
        unbanned = r.meta.changes ?? 0;
      }
    }
    return json({ ok: true, unbanned });
  }

  // ── 清空 Turnstile 访问计数 ────────────────────────
  if (path === "/api/admin/turnstile/visits" && method === "DELETE") {
    const days = Number(new URL(req.url).searchParams.get("days"));
    const before = days > 0 ? new Date(Date.now() - days * 86400_000).toISOString().slice(0, 10) : null;
    const r = before
      ? await env.db.prepare("DELETE FROM turnstile_visits WHERE day < ?1").bind(before).run()
      : await env.db.prepare("DELETE FROM turnstile_visits").run();
    return json({ ok: true, deleted: r.meta.changes ?? 0 });
  }

  // ── 重置本月流量 ──────────────────────────────────
  if (path === "/api/admin/traffic/reset" && method === "POST") {
    await updateSettings(env, {
      traffic_used_bytes: "0",
      traffic_month: new Date().toISOString().slice(0, 7),
    });
    return json({ ok: true });
  }

  // ══════════════════════════════════════════════════════
  // OAuth2 Provider CRUD —— 多 Provider 管理
  //   GET    /api/admin/oauth/providers             列表
  //   POST   /api/admin/oauth/providers             创建
  //   GET    /api/admin/oauth/providers/:id          详情
  //   PUT    /api/admin/oauth/providers/:id          更新
  //   DELETE /api/admin/oauth/providers/:id          删除
  //   POST   /api/admin/oauth/providers/:id/toggle   启用/禁用
  // ══════════════════════════════════════════════════════

  const oauthProvidersPath = "/api/admin/oauth/providers";
  const m = path.match(/^\/api\/admin\/oauth\/providers\/([^/]+)(\/(toggle))?$/);

  // GET /api/admin/oauth/providers —— 列表（返回不含 secret 的安全摘要）
  if (path === oauthProvidersPath && method === "GET") {
    const rows = await env.db
      .prepare("SELECT id, label, provider_type, client_id, scope, custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field, enabled, client_secret_cipher IS NOT NULL as has_secret, created_at, updated_at FROM oauth_providers ORDER BY updated_at DESC")
      .all<{ id: string; label: string; provider_type: string; client_id: string; scope: string; custom_authorize_url: string; custom_token_url: string; custom_userinfo_url: string; custom_token_field: string; enabled: number; has_secret: number; created_at: number; updated_at: number }>();
    return json({
      providers: rows.results.map((p) => ({
        id: p.id,
        label: p.label,
        provider_type: p.provider_type,
        client_id: p.client_id,
        scope: p.scope,
        custom_authorize_url: p.custom_authorize_url,
        custom_token_url: p.custom_token_url,
        custom_userinfo_url: p.custom_userinfo_url,
        custom_token_field: p.custom_token_field,
        enabled: !!p.enabled,
        secret_configured: !!p.has_secret,
        created_at: p.created_at,
        updated_at: p.updated_at,
      })),
    });
  }

  // POST /api/admin/oauth/providers —— 创建
  if (path === oauthProvidersPath && method === "POST") {
    const body = await readJson<{
      label?: string;
      provider_type?: string;
      client_id?: string;
      client_secret?: string;
      scope?: string;
      custom_authorize_url?: string;
      custom_token_url?: string;
      custom_userinfo_url?: string;
      custom_token_field?: string;
      enabled?: boolean;
    }>(req);
    const validTypes = ["github", "google", "microsoft", "discord", "custom"];
    const providerType = (body.provider_type && validTypes.includes(body.provider_type))
      ? body.provider_type
      : "github";
    const label = (body.label || providerType).trim().slice(0, 40);
    const clientId = (body.client_id || "").trim();
    if (!clientId) return json({ error: "client_id_required" }, 400);
    const scope = (body.scope || "").trim() || "openid email profile";
    const now = Date.now();
    const id = randomId();
    let secretCipher: string | null = null;
    if (body.client_secret && body.client_secret.trim()) {
      secretCipher = await encryptSecret(body.client_secret.trim(), env.admin);
      if (!secretCipher) return json({ error: "secret_encrypt_failed" }, 500);
    }
    await env.db
      .prepare(
        `INSERT INTO oauth_providers(id, label, provider_type, client_id, client_secret_cipher, scope,
            custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field,
            enabled, created_at, updated_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)`
      )
      .bind(
        id,
        label,
        providerType,
        clientId,
        secretCipher,
        scope,
        (body.custom_authorize_url || "").trim(),
        (body.custom_token_url || "").trim(),
        (body.custom_userinfo_url || "").trim(),
        (body.custom_token_field || "access_token").trim(),
        body.enabled === false ? 0 : 1,
        now,
        now
      )
      .run();
    return json({ ok: true, id });
  }

  // PUT /api/admin/oauth/providers/:id —— 更新
  if (m && !m[3] && method === "PUT") {
    const id = m[1];
    const row = await env.db
      .prepare("SELECT * FROM oauth_providers WHERE id = ?1")
      .bind(id)
      .first<Record<string, unknown>>();
    if (!row) return json({ error: "not_found" }, 404);
    const body = await readJson<{
      label?: string;
      provider_type?: string;
      client_id?: string;
      client_secret?: string; // 非空=更新；空字符串=清除；不传=保留
      scope?: string;
      custom_authorize_url?: string;
      custom_token_url?: string;
      custom_userinfo_url?: string;
      custom_token_field?: string;
      enabled?: boolean;
    }>(req);

    const now = Date.now();
    const updates: string[] = ["updated_at = ?1"];
    const values: unknown[] = [now];

    if (typeof body.label === "string" && body.label.trim()) {
      updates.push("label = ?" + (values.length + 1));
      values.push(body.label.trim().slice(0, 40));
    }
    if (typeof body.provider_type === "string") {
      const valid = ["github", "google", "microsoft", "discord", "custom"];
      if (valid.includes(body.provider_type)) {
        updates.push("provider_type = ?" + (values.length + 1));
        values.push(body.provider_type);
      }
    }
    if (typeof body.client_id === "string") {
      updates.push("client_id = ?" + (values.length + 1));
      values.push(body.client_id.trim());
    }
    if (typeof body.scope === "string") {
      updates.push("scope = ?" + (values.length + 1));
      values.push(body.scope.trim());
    }
    if (typeof body.custom_authorize_url === "string") {
      updates.push("custom_authorize_url = ?" + (values.length + 1));
      values.push(body.custom_authorize_url.trim());
    }
    if (typeof body.custom_token_url === "string") {
      updates.push("custom_token_url = ?" + (values.length + 1));
      values.push(body.custom_token_url.trim());
    }
    if (typeof body.custom_userinfo_url === "string") {
      updates.push("custom_userinfo_url = ?" + (values.length + 1));
      values.push(body.custom_userinfo_url.trim());
    }
    if (typeof body.custom_token_field === "string" && body.custom_token_field.trim()) {
      updates.push("custom_token_field = ?" + (values.length + 1));
      values.push(body.custom_token_field.trim());
    }
    if (typeof body.enabled === "boolean") {
      updates.push("enabled = ?" + (values.length + 1));
      values.push(body.enabled ? 1 : 0);
    }
    // Client secret：三种处理模式
    if (typeof body.client_secret === "string") {
      if (body.client_secret === "") {
        // 显式清除
        updates.push("client_secret_cipher = NULL");
      } else if (body.client_secret.trim() !== "__keep__") {
        // 更新为新密码
        const cipher = await encryptSecret(body.client_secret.trim(), env.admin);
        if (!cipher) return json({ error: "secret_encrypt_failed" }, 500);
        updates.push("client_secret_cipher = ?" + (values.length + 1));
        values.push(cipher);
      }
      // 其他情况（undefined 或 __keep__）：保留原值不动
    }

    values.push(id);
    const sql = `UPDATE oauth_providers SET ${updates.join(", ")} WHERE id = ?${values.length}`;
    await env.db.prepare(sql).bind(...values).run();
    return json({ ok: true });
  }

  // DELETE /api/admin/oauth/providers/:id
  if (m && !m[3] && method === "DELETE") {
    const id = m[1];
    await env.db.prepare("DELETE FROM oauth_providers WHERE id = ?1").bind(id).run();
    return json({ ok: true });
  }

  // POST /api/admin/oauth/providers/:id/toggle —— 切换启用/禁用
  if (m && m[3] === "toggle" && method === "POST") {
    const id = m[1];
    await env.db
      .prepare("UPDATE oauth_providers SET enabled = 1 - enabled, updated_at = ?1 WHERE id = ?2")
      .bind(Date.now(), id)
      .run();
    return json({ ok: true });
  }

  // ─═════════════════════════════════════════════════════════════════
  // 激活码管理
  // ─═════════════════════════════════════════════════════════════════

  // POST /api/admin/codes/generate — 批量生成
  // body: { plan_name, traffic_bytes, days_valid, count, quota_message?, batch_id?, notes? }
  if (path === "/api/admin/codes/generate" && method === "POST") {
    const body = await readJson<{
      plan_name?: string;
      traffic_bytes?: number;
      days_valid?: number;
      count?: number;
      quota_message?: string;
      batch_id?: string;
      notes?: string;
    }>(req);
    const count = Math.max(1, Math.min(10000, Number(body.count) || 100));
    const traffic = Math.max(0, Number(body.traffic_bytes) || 0);
    const days = Math.max(0, Number(body.days_valid) || 0);
    if (traffic === 0 && days === 0) {
      return json({ error: msg(req, "至少设置流量额度或有效天数之一", "Set at least traffic OR days_valid") }, 400);
    }

    const batchIdRaw = (body.batch_id ?? "").trim();
    const batchId = batchIdRaw ? batchIdRaw : makeBatchId();
    const now = Date.now();
    const ids = generateCodes(count);

    // 用 batch 高效插入
    const stmts = ids.map((code) =>
      env.db
        .prepare(
          `INSERT INTO activation_codes
           (id, code, plan_id, traffic_bytes, used_bytes, days_valid, quota_message, status, batch_id, notes, created_at, activated_at, expires_at)
           VALUES(?1, ?2, ?3, ?4, 0, ?5, ?6, 'unused', ?7, ?8, ?9, NULL, NULL)`
        )
        .bind(
          randomId(12),
          code,
          body.plan_name || null,
          traffic,
          days,
          (typeof body.quota_message === "string" && body.quota_message.trim()) || null,
          batchId,
          (typeof body.notes === "string" && body.notes.trim()) || null,
          now
        )
    );
    await env.db.batch(stmts);
    return json({ ok: true, batch_id: batchId, count, codes: ids.slice(0, 50) });
  }

  // GET /api/admin/codes — 列表（支持 ?status=&batch_id=&plan=&page=&export=1）
  if (path === "/api/admin/codes" && method === "GET") {
    const sp = new URL(req.url).searchParams;
    const status = sp.get("status");
    const batchId = sp.get("batch_id");
    const plan = sp.get("plan");
    const q = sp.get("q");
    const exportCsv = sp.get("export") === "1";
    const page = Math.max(1, Number(sp.get("page")) || 1);
    const pageSize = Math.min(500, Math.max(10, Number(sp.get("size")) || 50));
    const offset = (page - 1) * pageSize;

    const where: string[] = [];
    const binds: any[] = [];
    // effective_status 表达式：revoked 优先，然后动态 expired/exhausted，否则取原始 status
    const effectiveStatusExpr = `CASE WHEN status = 'revoked' THEN 'revoked'
      WHEN expires_at IS NOT NULL AND expires_at < ? THEN 'expired'
      WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 'exhausted'
      ELSE status END`;
    const now = Date.now();
    if (status) { where.push(`(${effectiveStatusExpr}) = ?`); binds.push(now, status); }
    if (batchId) { where.push("batch_id = ?"); binds.push(batchId); }
    if (plan) { where.push("plan_id = ?"); binds.push(plan); }
    if (q) { where.push("(code LIKE ? OR notes LIKE ?)"); binds.push(`%${q}%`, `%${q}%`); }

    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";
    const countSql = `SELECT COUNT(*) AS c FROM activation_codes ${whereSql}`;
    const listSql = `SELECT * FROM activation_codes ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`;

    const total = (await env.db.prepare(countSql).bind(...binds).first<{ c: number }>())?.c ?? 0;
    const results = (await env.db.prepare(listSql).bind(...binds, pageSize, offset).all()).results as any[];

    const rows = results.map((r) => {
      const status = formatCodeStatus(r);
      // 计算 effective status：在 DB status 基础上，叠加动态过期/耗尽判断
      let effectiveStatus: string = r.status;
      if (r.status !== "revoked") {
        if (r.expires_at && r.expires_at < now) effectiveStatus = "expired";
        else if (r.traffic_bytes > 0 && r.used_bytes >= r.traffic_bytes) effectiveStatus = "exhausted";
      }
      return {
        id: r.id,
        code: r.code,
        plan_id: r.plan_id,
        batch_id: r.batch_id,
        notes: r.notes,
        traffic_bytes: r.traffic_bytes,
        used_bytes: r.used_bytes,
        days_valid: r.days_valid,
        quota_message: r.quota_message,
        status: effectiveStatus,
        remaining: status?.remaining,
        pct: status?.pct,
        expired: status?.expired,
        created_at: r.created_at,
        activated_at: r.activated_at,
        expires_at: r.expires_at,
      };
    });

    if (exportCsv) {
      const csvRows = [
        "code,plan_id,batch_id,traffic_bytes,used_bytes,days_valid,status,quota_message,notes,created_at,activated_at,expires_at",
      ];
      const allResults = (await env.db.prepare(`SELECT * FROM activation_codes ${whereSql} ORDER BY created_at DESC`).bind(...binds).all()).results as any[];
      for (const r of allResults) {
        const esc = (v: any) => {
          if (v == null) return "";
          const s = String(v).replace(/"/g, '""');
          return /[",\n]/.test(s) ? `"${s}"` : s;
        };
        csvRows.push(
          [r.code, r.plan_id ?? "", r.batch_id ?? "", r.traffic_bytes, r.used_bytes, r.days_valid, r.status, esc(r.quota_message), esc(r.notes), r.created_at ?? "", r.activated_at ?? "", r.expires_at ?? ""].join(",")
        );
      }
      const body = csvRows.join("\n");
      const filename = `activation_codes_${new Date().toISOString().slice(0, 10)}.csv`;
      return new Response(body, {
        status: 200,
        headers: {
          "content-type": "text/csv;charset=utf-8",
          "content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`,
        },
      });
    }

    return json({ rows, total, page, page_size: pageSize });
  }

  // POST /api/admin/codes/:id/revoke — 作废一个码
  const codeRevokeMatch = /^\/api\/admin\/codes\/([^/]+)\/revoke$/.exec(path);
  if (codeRevokeMatch && method === "POST") {
    await env.db.prepare("UPDATE activation_codes SET status = 'revoked' WHERE id = ?1 AND status != 'revoked'").bind(codeRevokeMatch![1]).run();
    return json({ ok: true });
  }

  // POST /api/admin/codes/batch-revoke — 按 batch_id 整批作废
  if (path === "/api/admin/codes/batch-revoke" && method === "POST") {
    const body = await readJson<{ batch_id?: string; codes?: string[] }>(req);
    if (body.batch_id) {
      const r = await env.db.prepare("UPDATE activation_codes SET status = 'revoked' WHERE batch_id = ?1 AND status != 'revoked'").bind(body.batch_id).run();
      return json({ ok: true, updated: r.meta.changes ?? 0 });
    }
    const codes: string[] = (body.codes ?? []) as string[];
    if (codes.length > 0) {
      // 统一 trim + 大写，与 findCodeByString 的查询口径一致
      const normalized = codes.map((c) => c.trim().toUpperCase()).filter(Boolean);
      const stmts = normalized.map((c) =>
        env.db.prepare("UPDATE activation_codes SET status = 'revoked' WHERE code = ?1 AND status != 'revoked'").bind(c)
      );
      await env.db.batch(stmts);
      return json({ ok: true, count: normalized.length });
    }
    return json({ error: msg(req, "缺少 batch_id 或 codes", "Missing batch_id or codes") }, 400);
  }

  // GET /api/admin/codes/batches — 列出所有 batch_id（用于过滤 UI）
  if (path === "/api/admin/codes/batches" && method === "GET") {
    const rows = (await env.db.prepare(
      "SELECT batch_id, COUNT(*) AS n FROM activation_codes WHERE batch_id IS NOT NULL GROUP BY batch_id ORDER BY MAX(created_at) DESC"
    ).all()).results as any[];
    return json({ batches: rows.map((r) => ({ batch_id: r.batch_id, count: r.n })) });
  }

  // GET /api/admin/codes/usage?batch=&plan= — 流量用量汇总
  if (path === "/api/admin/codes/usage" && method === "GET") {
    const sp = new URL(req.url).searchParams;
    const where: string[] = [];
    const binds: any[] = [];
    if (sp.get("batch")) { where.push("batch_id = ?"); binds.push(sp.get("batch")); }
    if (sp.get("plan")) { where.push("plan_id = ?"); binds.push(sp.get("plan")); }
    const whereSql = where.length ? "WHERE " + where.join(" AND ") : "";

    // 用 effective status 替代原始 status，确保动态过期/耗尽的码也被正确统计
    const now = Date.now();
    const summary = await env.db.prepare(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 0
                  WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 0
                  WHEN status = 'unused' THEN 1 ELSE 0 END) AS unused,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 0
                  WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 0
                  WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
         SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 1 ELSE 0 END) AS expired,
         SUM(CASE WHEN status = 'revoked' THEN 0
                  WHEN expires_at IS NOT NULL AND expires_at < ? THEN 0
                  WHEN traffic_bytes > 0 AND used_bytes >= traffic_bytes THEN 1 ELSE 0 END) AS exhausted,
         SUM(used_bytes) AS used_bytes,
         SUM(traffic_bytes) AS total_bytes
       FROM activation_codes ${whereSql}`
    ).bind(now, now, now, now, ...binds).first() as any;

    // 各 batch 汇总
    const batches = where.length ? [] : (await env.db.prepare(
      `SELECT batch_id, COUNT(*) AS n, SUM(used_bytes) AS used_bytes, SUM(traffic_bytes) AS total_bytes
       FROM activation_codes
       WHERE batch_id IS NOT NULL
       GROUP BY batch_id
       ORDER BY MAX(created_at) DESC`
    ).all()).results;

    return json({ summary, batches });
  }

  // ─══════════════════════════════════════════════════════════
  // 存储后端连通性测试
  // POST /api/admin/storage/test
  // body: { provider?, endpoint?, region?, bucket?, access_key_id?, secret_key?, addressing_style? }
  //   不传则使用 settings 里已配置的值
  // ─══════════════════════════════════════════════════════════
  if (path === "/api/admin/storage/test" && method === "POST") {
    const body = await readJson<any>(req);
    const s = await getSettings(env);

    // 如果 body 里没传任何 S3 字段，用 settings 里的
    const useS3 =
      (body.provider ?? s.storageProvider) === "s3" &&
      (body.endpoint ?? s.s3Endpoint) &&
      (body.bucket ?? s.s3Bucket);

    if (useS3) {
      const secret = body.secret_key?.trim()
        ? body.secret_key.trim()
        : (s.s3SecretKeyCipher ? await decryptSecret(s.s3SecretKeyCipher, env.admin) : null);
      if (!secret || !(body.access_key_id ?? s.s3AccessKeyId)) {
        return json({ ok: false, error: "missing_s3_credentials" }, 400);
      }
      const { createS3Provider } = await import("./storage");
      const cfg = {
        endpoint: body.endpoint ?? s.s3Endpoint!,
        region: body.region ?? s.s3Region ?? "us-east-1",
        bucket: body.bucket ?? s.s3Bucket!,
        accessKeyId: (body.access_key_id ?? s.s3AccessKeyId!).trim(),
        secretAccessKey: secret,
        addressingStyle: (body.addressing_style ?? s.s3AddressingStyle ?? "path") as "path" | "virtual",
      };
      try {
        const prov = createS3Provider(cfg);
        const testKey = `_r2pan-test-${Date.now()}`;
        // 写一个测试对象
        await prov.put(testKey, new TextEncoder().encode("cloud-r2pan storage test"), {
          contentType: "text/plain",
        });
        // 读回验证
        const obj = await prov.get(testKey);
        const head = await prov.head(testKey);
        // 清理
        await prov.delete(testKey);
        return json({
          ok: true,
          provider: "s3",
          endpoint: cfg.endpoint,
          bucket: cfg.bucket,
          head_ok: !!head,
          head_size: head?.size ?? 0,
        });
      } catch (err: any) {
        return json({
          ok: false,
          error: "s3_test_failed",
          message: String(err?.message ?? err),
          detail: err?.stack ?? "",
        }, 502);
      }
    } else {
      // R2 模式 —— 直接 head 一个已知 key 或 list 试一下
      if (!env.r2) {
        return json({ ok: false, error: "no_r2_binding_and_no_s3_configured" }, 400);
      }
      try {
        // 尝试 list（轻量，能连通就行）
        const listed = await env.r2.list({ limit: 1 });
        return json({
          ok: true,
          provider: "r2",
          bucket: "cloud-r2pan",
          objects_found: listed.objects?.length ?? 0,
          has_more: !!listed.truncated,
        });
      } catch (err: any) {
        return json({
          ok: false,
          error: "r2_test_failed",
          message: String(err?.message ?? err),
        }, 502);
      }
    }
  }

  // ─══════════════════════════════════════════════════════════
  // 全球分布统计 —— 用于「全球分布」Tab 的地球仪
  // GET /api/admin/global/stats?since_days=7
  //   返回每个国家的下载次数、字节数、活跃 IP 数
  // ─══════════════════════════════════════════════════════════
  if (path === "/api/admin/global/stats" && method === "GET") {
    const sinceDays = Math.min(365, Math.max(1, Number(new URL(req.url).searchParams.get("since_days")) || 30));
    const since = Date.now() - sinceDays * 86400_000;
    const countrySql = `
      SELECT
        COALESCE(NULLIF(country, ''), 'ZZ') AS country,
        COUNT(*) AS downloads,
        COALESCE(SUM(bytes), 0) AS bytes,
        COUNT(DISTINCT ip) AS unique_ips,
        COUNT(DISTINCT file_name) AS unique_files
      FROM download_logs
      WHERE created_at > ?1
      GROUP BY country
      ORDER BY downloads DESC
    `;
    const { results }: any = await env.db.prepare(countrySql).bind(since).all();
    const totalSql = `
      SELECT COUNT(*) AS total_downloads, COALESCE(SUM(bytes), 0) AS total_bytes, COUNT(DISTINCT COALESCE(NULLIF(country, ''), 'ZZ')) AS countries_seen
      FROM download_logs WHERE created_at > ?1
    `;
    const totals: any = await env.db.prepare(totalSql).bind(since).first();

    // Analytics Engine 可用性（给前端展示提示）
    return json({
      since_days: sinceDays,
      totals: {
        downloads: totals?.total_downloads ?? 0,
        bytes: totals?.total_bytes ?? 0,
        countries_seen: totals?.countries_seen ?? 0,
      },
      countries: (results ?? []).map((r: any) => ({
        country: r.country,
        downloads: r.downloads,
        bytes: r.bytes,
        unique_ips: r.unique_ips,
        unique_files: r.unique_files,
      })),
      analytics_engine_available: !!env.analytics,
      // Analytics Engine 绑定后，下次部署可以升级为经纬度精确查询
      geo_source: "d1_download_logs",
    });
  }

  return json({ error: "not_found" }, 404);
  } catch (e: any) {
    const ref = randomId(6);
    console.error(`[handleAdminApi ref=${ref}]`, e?.stack || e);
    return json({
      error: "server_error",
      ref,
      message: msg(req, `服务端错误（ref=${ref}），请到 Worker 日志查询`, `Server error (ref=${ref}); see Worker logs`),
    }, 500);
  }
}
