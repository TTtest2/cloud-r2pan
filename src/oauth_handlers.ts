/**
 * OAuth2 HTTP 处理函数 —— 多 Provider 模式
 *
 * 路由:
 *   GET  /oauth/start?provider=xxx          → 重定向到 Provider 授权页
 *   GET  /oauth/callback?code=...&state=...  → Provider 回调
 *   GET  /oauth/session                     → 返回当前 OAuth 会话状态
 *   POST /oauth/logout                      → 清除 OAuth Cookie
 *   GET  /oauth/providers                   → 返回所有启用的 Provider 列表（给分享页渲染按钮）
 *
 * 所有 Provider 配置均来自 D1 的 oauth_providers 表。
 */

import type { Env } from "./types";
import { getSettings } from "./settings";
import { decryptSecret } from "./crypto";
import {
  getBuiltinProvider,
  BUILTIN_PROVIDERS,
  createOAuthState,
  verifyOAuthState,
  buildAuthorizeUrl,
  exchangeCode,
  fetchUserInfo,
  signOAuthSession,
  verifyOAuthSession,
  deriveRedirectUri,
  type OAuthProvider,
} from "./oauth";

/* ═══════════ 从 D1 构造 OAuthProvider ═══════════ */

interface OAuthProviderRow {
  id: string;
  label: string;
  provider_type: string;
  client_id: string;
  client_secret_cipher: string | null;
  scope: string;
  custom_authorize_url: string;
  custom_token_url: string;
  custom_userinfo_url: string;
  custom_token_field: string;
  enabled: number;
}

function rowToProvider(row: OAuthProviderRow): OAuthProvider | null {
  const base = getBuiltinProvider(row.provider_type);
  if (!base) return null;
  if (row.provider_type === "custom") {
    // 自定义 Provider —— 必填所有 URL
    if (!row.custom_authorize_url || !row.custom_token_url || !row.custom_userinfo_url) return null;
    return {
      id: row.provider_type,
      name: row.label || "Custom",
      authorize_url: row.custom_authorize_url,
      token_url: row.custom_token_url,
      userinfo_url: row.custom_userinfo_url,
      default_scope: row.scope || "openid email profile",
      token_field: row.custom_token_field || "access_token",
    };
  }
  return { ...base, default_scope: row.scope || base.default_scope };
}

async function fetchProviderRow(env: Env, dbId: string): Promise<OAuthProviderRow | null> {
  const row = await env.db
    .prepare("SELECT id, label, provider_type, client_id, client_secret_cipher, scope, custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field, enabled FROM oauth_providers WHERE id = ?1")
    .bind(dbId)
    .first<OAuthProviderRow>();
  return row ?? null;
}

async function listEnabledProviders(env: Env): Promise<OAuthProviderRow[]> {
  const rows = await env.db
    .prepare("SELECT id, label, provider_type, client_id, client_secret_cipher, scope, custom_authorize_url, custom_token_url, custom_userinfo_url, custom_token_field, enabled FROM oauth_providers WHERE enabled = 1")
    .all<OAuthProviderRow>();
  return rows.results;
}

/* ═══════════ GET /oauth/providers —— 分享页用 ═══════════
 * 返回启用中的 Provider 列表（不含敏感信息，只够渲染按钮）。
 * 如果 settings.oauth_enabled=false 则返回空数组。
 */
export async function handleOAuthProviders(req: Request, env: Env): Promise<Response> {
  const settings = await getSettings(env);
  if (!settings.oauthEnabled) return Response.json({ providers: [], enabled: false });
  const rows = await listEnabledProviders(env);
  const origin = new URL(req.url).origin;
  const providers = rows
    .filter((r) => r.client_id) // 没有 client_id 的不能用
    .map((r) => {
      const p = rowToProvider(r);
      return {
        id: r.id,
        label: r.label,
        provider_type: r.provider_type,
        name: p?.name ?? r.provider_type,
        start_url: `/oauth/start?provider=${encodeURIComponent(r.id)}`,
        client_id: r.client_id,
      };
    });
  return Response.json({ providers, enabled: providers.length > 0 });
}

/* ═══════════ GET /oauth/start?provider=<provider_id>&redirect=<path> ═══════════ */
export async function handleOAuthStart(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const providerDbId = url.searchParams.get("provider") || "";
  const redirectTo = localRedirect(url.searchParams.get("redirect") ?? "");

  const settings = await getSettings(env);
  if (!settings.oauthEnabled) {
    return Response.json({ error: "oauth_disabled" }, { status: 400 });
  }

  const row = await fetchProviderRow(env, providerDbId);
  if (!row || !row.enabled) {
    return Response.json({ error: "provider_not_found_or_disabled" }, { status: 400 });
  }
  if (!row.client_id) {
    return Response.json({ error: "client_id_missing" }, { status: 500 });
  }

  const provider = rowToProvider(row);
  if (!provider) {
    return Response.json({ error: "provider_broken" }, { status: 500 });
  }

  const redirectUri = deriveRedirectUri(req);
  // state 里存 D1 provider 的 db id，callback 时直接查回完整 provider
  const state = await createOAuthState(env, row.id, redirectUri);
  const authorizeUrl = buildAuthorizeUrl(
    provider,
    row.client_id,
    redirectUri,
    row.scope || provider.default_scope,
    state
  );

  // 把 redirectTo 写进 Cookie
  const cookie = `cd_oauth_redirect=${encodeURIComponent(redirectTo)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`;
  return new Response(null, {
    status: 302,
    headers: {
      location: authorizeUrl,
      "set-cookie": cookie,
    },
  });
}

/* ═══════════ GET /oauth/callback ═══════════ */
export async function handleOAuthCallback(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code") || "";
  const state = url.searchParams.get("state") || "";
  const error = url.searchParams.get("error");
  if (error) {
    return redirectBackWithMsg(req, "oauth_error: " + error);
  }
  if (!code || !state) {
    return redirectBackWithMsg(req, "oauth_missing_code");
  }

  // 1. 校验 state（一次性消费 + TTL）
  const verify = await verifyOAuthState(env, state);
  if (!verify.ok || !verify.provider_id) {
    return redirectBackWithMsg(req, "oauth_state_invalid");
  }

  // 从 state 拿的是 provider_type（github/google...），我们需要回查 Db 里对应的 enabled provider
  // 但 state 存的是 provider_type，可能有多个同类型 provider。我们改用：state 里存 db id
  // 让我们调整 state 里的 provider_id 语义 —— 现在的 createOAuthState 存 provider_type
  // 改为存 db id
  // 但改动 createOAuthState 会影响 state 结构...让我们看看 state 表
  // CREATE TABLE oauth_states(state TEXT, provider_id TEXT, redirect_uri TEXT, expires_at INTEGER)
  // provider_id 现在存的是 provider_type。我们改成存 db id。
  // 但 handleOAuthStart 里已经在 createOAuthState 时用了 provider_type。
  // 让我们改 handleOAuthStart 的调用：createOAuthState(env, providerDbId, redirectUri)
  // 然后这里直接 fetchProviderRow(env, verify.provider_id) 即可
  // （我们已经在 handleOAuthStart 里把 providerDbId 传进去了，看看：）

  // 好，现在 provider_id 字段存的是 D1 里的 provider db id，直接查
  const providerDbId = verify.provider_id;
  const row = await fetchProviderRow(env, providerDbId);
  if (!row) {
    return redirectBackWithMsg(req, "oauth_provider_missing");
  }
  const provider = rowToProvider(row);
  if (!provider) {
    return redirectBackWithMsg(req, "oauth_provider_broken");
  }
  if (!row.client_secret_cipher) {
    return redirectBackWithMsg(req, "oauth_credentials_missing");
  }

  // 2. 解密 Client Secret
  const clientSecret = await decryptSecret(row.client_secret_cipher, env.admin);
  if (!clientSecret) {
    return redirectBackWithMsg(req, "oauth_secret_decrypt_failed");
  }

  // 3. code → access_token
  const redirectUri = verify.redirect_uri!;
  const token = await exchangeCode(provider, code, redirectUri, row.client_id, clientSecret);
  if (!token) {
    return redirectBackWithMsg(req, "oauth_exchange_failed");
  }

  // 4. 拉用户信息
  const user = await fetchUserInfo(provider, token.accessToken);
  if (!user) {
    return redirectBackWithMsg(req, "oauth_userinfo_failed");
  }

  // 5. 发 OAuth 会话 Cookie
  // cookie 里存的是 db id，方便 later check 时知道用的是哪个 provider
  const { cookie, secure } = await signOAuthSession(env, providerDbId, user.id);
  const originalRedirect = parseCookie(req.headers.get("cookie"), "cd_oauth_redirect") || "/";

  const setCookieParts: string[] = [cookie, "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=3600"];
  if (url.protocol === "https:" && secure) setCookieParts.push("Secure");
  const setCookie = setCookieParts.join("; ");
  const clearRedirect = "cd_oauth_redirect=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";

  const headers = new Headers();
  headers.set("location", localRedirect(originalRedirect));
  headers.append("set-cookie", setCookie);
  headers.append("set-cookie", clearRedirect);
  return new Response(null, { status: 302, headers });
}

/* ═══════════ GET /oauth/session ═══════════ */
export async function handleOAuthSession(req: Request, env: Env): Promise<Response> {
  const result = await verifyOAuthSession(env, req.headers.get("cookie"));
  if (!result.ok) {
    return Response.json({ authenticated: false });
  }
  // 查 provider 类型用于前端显示
  const row = await fetchProviderRow(env, result.providerId);
  return Response.json({
    authenticated: true,
    provider_db_id: result.providerId,
    provider_type: row?.provider_type ?? "unknown",
    provider_label: row?.label ?? result.providerId,
    user_id: result.userId,
  });
}

/* ═══════════ POST /oauth/logout ═══════════ */
export async function handleOAuthLogout(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const secure = url.protocol === "https:";
  const cookie = `cd_oauth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? "; Secure" : ""}`;
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "content-type": "application/json",
      "set-cookie": cookie,
      "cache-control": "no-store",
    },
  });
}

/* ═══════════ 辅助函数 ═══════════ */

/** 跳转目标只允许站内绝对路径；//host、/\\host、带 origin 的 URL 一律回落到 "/" */
export function localRedirect(raw: string): string {
  const BASE = "https://pan.local";
  let u: URL;
  try {
    u = new URL(raw || "/", BASE);
  } catch {
    return "/";
  }
  return u.origin === BASE ? u.pathname + u.search : "/";
}

function parseCookie(header: string | null, name: string): string {
  if (!header) return "";
  const re = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`);
  const m = re.exec(header);
  return m ? decodeURIComponent(m[1]) : "";
}

function redirectBackWithMsg(req: Request, msg: string): Response {
  const redirectTo = parseCookie(req.headers.get("cookie"), "cd_oauth_redirect") || "/";
  const url = new URL(redirectTo, "https://localhost");
  url.searchParams.set("oauth_error", msg);
  const setCookie = "cd_oauth_redirect=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0";
  return new Response(null, {
    status: 302,
    headers: {
      location: `${url.pathname}${url.search}`,
      "set-cookie": setCookie,
    },
  });
}
