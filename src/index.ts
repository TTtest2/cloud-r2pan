import type { Env } from "./types";
import { ensureSchema } from "./db";
import { handleAdminApi } from "./admin";
import { handleDownload, handleDirectDownload, handleShareInfo, handleShareChildren, handleVerify } from "./public";
import { serveAdminPage, serveSharePage, serveMarketPage, servePickupPage, errorPage } from "./pages";
import {
  handleOAuthStart,
  handleOAuthCallback,
  handleOAuthSession,
  handleOAuthLogout,
  handleOAuthProviders,
} from "./oauth_handlers";
import { findCodeByString, formatCodeStatus, checkCodeUsable, isCodeLenientFormat } from "./codes";
import { clientIp, rateLimit, rateLimitRetryAfter } from "./auth";
import { parseMarketParams, queryMarket } from "./market";
import { handlePickupClaim, handlePickupDownload, handlePickupDrop, handlePickupStatus } from "./pickup";
import { runScheduledCleanup } from "./cron";

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await route(req, env, ctx);
    } catch (err) {
      console.error("unhandled error:", err);
      return errorPage(
        req,
        500,
        { zh: "服务出错了", en: "Something Went Wrong" },
        { zh: "服务器内部错误，请稍后重试。", en: "An internal server error occurred. Please try again later." }
      );
    }
  },

  /** wrangler.jsonc 里的 triggers.cron 每小时指向这里 */
  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    await ensureSchema(env);
    ctx.waitUntil(
      runScheduledCleanup(env)
        .then((report) => console.log("[cron] cleanup " + JSON.stringify(report)))
        .catch((err) => console.error("[cron] cleanup failed:", err))
    );
  },
};

async function route(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // 首页：根据管理员设置决定去向（默认 → /admin；开启后 → /market）
  if (path === "/") {
    await ensureSchema(env);
    const { getSettings } = await import("./settings");
    const s = await getSettings(env);
    const target = s.homeRedirectMarket ? "/market" : "/admin";
    return Response.redirect(new URL(target, url).toString(), 302);
  }

  // 管理后台页面
  if (path === "/admin" || path === "/admin/") {
    return serveAdminPage();
  }

  // 管理 API
  if (path.startsWith("/api/admin/")) {
    return handleAdminApi(req, env, ctx, path);
  }

  // ══════════════ OAuth2 路由 ══════════════
  await ensureSchema(env);

  if (path === "/oauth/providers" && req.method === "GET") {
    return handleOAuthProviders(req, env);
  }
  if (path === "/oauth/start" && req.method === "GET") {
    return handleOAuthStart(req, env);
  }
  if (path === "/oauth/callback" && req.method === "GET") {
    return handleOAuthCallback(req, env);
  }
  if (path === "/oauth/session" && req.method === "GET") {
    return handleOAuthSession(req, env);
  }
  if (path === "/oauth/logout" && req.method === "POST") {
    return handleOAuthLogout(req);
  }

  // ══════════════════════════════════════════════════════════════
  // 公开激活码查询接口（任何人可以查某个码的余额 / 状态）
  // GET /api/codes/status?code=R2PAN-XXXX-XXXX-XXXX
  // ══════════════════════════════════════════════════════════════
  if (path === "/api/codes/status" && req.method === "GET") {
    await ensureSchema(env);
    // ① IP 限流 —— 公开端点，防枚举爆破
    const ip = clientIp(req);
    if (!rateLimit(ip, "codes", 30)) {
      return Response.json(
        { ok: false, error: "rate_limited", message: "请求过于频繁，请稍后再试" },
        { status: 429, headers: { "Retry-After": String(rateLimitRetryAfter(ip, "codes")) } }
      );
    }
    const code = (new URL(req.url).searchParams.get("code") || "").trim().toUpperCase();
    if (!code) {
      return Response.json({ ok: false, error: "missing_code" }, { status: 400 });
    }
    // ② 格式校验 —— 纯垃圾字符直接 400，不消耗限流配额也不查 DB
    if (!isCodeLenientFormat(code)) {
      return Response.json({ ok: false, error: "bad_format", message: "激活码格式不正确" }, { status: 400 });
    }
    const row = await findCodeByString(env, code);
    if (!row) {
      return Response.json({ ok: false, error: "not_found", message: "码不存在" }, { status: 404 });
    }
    const check = checkCodeUsable(row as any);
    const status = formatCodeStatus(row as any);
    return Response.json({
      ok: true,
      code: row.code,
      usable: check.ok,
      reason: check.reason,
      message: check.message,
      status,
    });
  }

  // ══════════════════════════════════════════════════════════════
  // 取件码投递 —— 码既是地址也是凭据（详见 src/pickup.ts 头注释）
  //   POST /api/pickup            投件，回一枚取件码
  //   POST /api/pickup/claim      输码 → 文件信息 + 短时效下载票据
  //   GET  /api/pickup/download   票据 → 走与分享链接同一条闸门流水线
  // ══════════════════════════════════════════════════════════════
  if (path === "/api/pickup/status" && req.method === "GET") {
    await ensureSchema(env);
    return handlePickupStatus(req, env);
  }
  if (path === "/api/pickup" && req.method === "POST") {
    await ensureSchema(env);
    return handlePickupDrop(req, env, ctx);
  }
  if (path === "/api/pickup/claim") {
    await ensureSchema(env);
    if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
    return handlePickupClaim(req, env);
  }
  if (path === "/api/pickup/download") {
    await ensureSchema(env);
    if (req.method !== "GET" && req.method !== "HEAD") return new Response("Method Not Allowed", { status: 405 });
    return handlePickupDownload(req, env, ctx);
  }

  // ══════════════════════════════════════════════════════════════
  // 下载市场 —— 公开页面 + API
  // ══════════════════════════════════════════════════════════════
  // 市场 HTML 页面
  if ((path === "/market" || path === "/market/") && (req.method === "GET" || req.method === "HEAD")) {
    return serveMarketPage(req);
  }
  // 取件页 HTML
  if ((path === "/pickup" || path === "/pickup/") && (req.method === "GET" || req.method === "HEAD")) {
    return servePickupPage(req);
  }
  // 市场搜索/排序 API（SQL 在 src/market.ts，便于单测）
  if (path === "/api/market" && req.method === "GET") {
    await ensureSchema(env);
    const params = parseMarketParams(new URL(req.url).searchParams);
    return Response.json(await queryMarket(env, params));
  }

  // 公开分享页 /s/:token[...]
  const shareMatch = /^\/s\/([A-Za-z0-9]+)(\/.*)?$/.exec(path);
  if (shareMatch) {
    await ensureSchema(env);
    const token = shareMatch[1];
    const sub = shareMatch[2] ?? "";
    if (sub === "" || sub === "/") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return serveSharePage(req);
    }
    if (sub === "/info") {
      return handleShareInfo(req, env, token);
    }
    if (sub === "/children") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      const ip = clientIp(req);
      if (!rateLimit(ip, "share-children:" + token, 60)) {
        return Response.json(
          { error: "too_many_attempts", message: "请求过于频繁，请稍后再试" },
          { status: 429, headers: { "Retry-After": String(rateLimitRetryAfter(ip, "share-children:" + token)) } }
        );
      }
      return handleShareChildren(req, env, token);
    }
    if (sub === "/verify") {
      if (req.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      // 密码校验必须限流：这是唯一的分享密码入口
      // 按 IP+token 分桶，避免同一个 NAT 后面有人误刷就把所有人的分享页锁死
      const ip = clientIp(req);
      if (!rateLimit(ip, "share-verify:" + token, 10)) {
        return Response.json(
          { error: "too_many_attempts", message: "尝试过于频繁，请稍后再试" },
          { status: 429, headers: { "Retry-After": String(rateLimitRetryAfter(ip, "share-verify:" + token)) } }
        );
      }
      return handleVerify(req, env, token);
    }
    if (sub === "/download") {
      if (req.method !== "GET" && req.method !== "HEAD") {
        return new Response("Method Not Allowed", { status: 405 });
      }
      return handleDownload(req, env, ctx, token);
    }
    return notFound(req);
  }

  // ══════════════════════════════════════════════════════════════
  // 直链 /d/:id —— 独立入口，走 direct_links 表
  // 与分享链接 /s/:id 是完全独立的 API、独立的 token、独立的鉴权
  // 创建直链: POST /api/admin/direct-links
  // ══════════════════════════════════════════════════════════════
  const directMatch = /^\/d\/([A-Za-z0-9]+)$/.exec(path);
  if (directMatch) {
    if (req.method !== "GET" && req.method !== "HEAD") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    await ensureSchema(env);
    return handleDirectDownload(req, env, ctx, directMatch[1]);
  }

  // ══════════════════════════════════════════════════════════════
  // WebDAV 服务 —— 挂载点 /webdav/*
  // 通过 HTTP Basic Auth 保护，启用后可在 Finder/Explorer 等直接挂载
  // ══════════════════════════════════════════════════════════════
  if (path === "/webdav" || path.startsWith("/webdav/")) {
    await ensureSchema(env);
    const { handleWebDAV } = await import("./webdav");
    return handleWebDAV(req, env, ctx);
  }

  return notFound(req);
}

function notFound(req: Request): Response {
  return errorPage(
    req,
    404,
    { zh: "页面不存在", en: "Not Found" },
    { zh: "请求的地址无效。", en: "The requested address is invalid." }
  );
}
