import type { Env } from "./types";

/* ═══════════ Settings 内存缓存 ═══════════
 * 问题：getSettings() 每次都 SELECT * FROM settings 全表查询，
 *       下载 / 分享 / OAuth / Turnstile 等高频路径都要调，
 *       白白多一次 D1 往返。
 *
 * 策略：isolate 内缓存 + 5 秒 TTL + updateSettings 主动失效。
 *       5 秒足够短（管理员改完最多 5 秒全量生效），
 *       又足够把同一波并发请求合并掉，D1 压力骤降。
 *       跨 isolate 不同步，靠 TTL 自愈（可接受，因为管理员不会每秒改设置）。
 */
const SETTINGS_CACHE_TTL_MS = 5_000; // 5 秒
let _cachedSettings: Settings | null = null;
let _cachedAt = 0;

/** 主动失效缓存 —— updateSettings 后调用 */
export function invalidateSettingsCache(): void {
  _cachedSettings = null;
  _cachedAt = 0;
}

/** 可调参数（均可在管理后台修改） */
export interface Settings {
  siteTitle: string;
  /** 月度流量限额（字节），0 = 不限 */
  trafficLimitBytes: number;
  /** 本月已用流量（字节） */
  trafficUsedBytes: number;
  /** 当前统计月份 YYYY-MM */
  trafficMonth: string;
  /** 单 IP 对同一分享的最大下载次数，0 = 不限 */
  maxDownloadsPerIp: number;
  /** 重复下载统计窗口（小时），0 = 永久 */
  countWindowHours: number;
  /** 超限后是否自动封禁 */
  autoBan: boolean;
  /** 自动封禁时长（小时），0 = 永久 */
  banHours: number;
  /** 2FA 是否已启用 */
  totpEnabled: boolean;
  /** TOTP secret（D1 中存的是用 admin 加密后的密文） */
  totpSecretCipher: string | null;
  /** 恢复码列表（D1 中存的是 hash 后的值，用逗号分隔） */
  totpRecoveryHash: string | null;
  /**
   * Turnstile 模式：
   *   "off"        = 关闭
   *   "on_share"   = 打开分享链接时触发
   *   "on_download"= 点击下载时触发
   *   "both"       = 分享链接打开和下载都可以触发（按阈值）
   */
  turnstileMode: "off" | "on_share" | "on_download" | "both";
  /** 每天每个 IP 触发 Turnstile 的访问次数阈值。0 = 每次都弹。 */
  turnstileThreshold: number;
  /** Turnstile sitekey 覆盖（如果没在 Cloudflare Secret 里配，可在这里写） */
  turnstileSitekeyOverride: string | null;
  /** Turnstile secret（Cloudflare 侧的 SK 开头密钥）—— 用 admin AES-GCM 加密后存 */
  turnstileSecretCipher: string | null;

  // ═══════ OAuth2 下载鉴权 ═══════
  /** 是否启用 OAuth2 下载验证 */
  oauthEnabled: boolean;
  /** 使用哪个 Provider（github/google/microsoft/discord/custom） */
  oauthProvider: string;
  /** OAuth2 Client ID（明文存，可公开） */
  oauthClientId: string;
  /** OAuth2 Client Secret —— 用 admin AES-GCM 加密后存 */
  oauthClientSecretCipher: string | null;
  /** OAuth2 默认 scope */
  oauthScope: string;
  /** 自定义 Provider: authorize_url */
  oauthCustomAuthorizeUrl: string;
  /** 自定义 Provider: token_url */
  oauthCustomTokenUrl: string;
  /** 自定义 Provider: userinfo_url */
  oauthCustomUserinfoUrl: string;
  /** 自定义 Provider: token 返回字段名 */
  oauthCustomTokenField: string;

  // ═══════ 管理员 IP 白名单 ═══════
  /**
   * 允许访问 /admin 和 /api/admin 的 IP 列表（CIDR 或精确 IP，逗号分隔）。
   * 为空 = 不限制；非空 = 仅这些 IP 能访问管理员接口。
   * 这些 IP 的下载流量不受 trafficLimitBytes 限额约束。
   */
  adminIps: string;

  // ═══════ 下载市场首页 ═══════
  /** 是否将根路径 "/" 重定向到下载市场（而不是 /admin）。默认 false。 */
  homeRedirectMarket: boolean;

  // ═══════ 激活码浮动按钮（分享页右上角的卡片图标） ═══════
  /** 是否在分享页显示激活码浮动按钮。默认 true。 */
  codesFloatingButtonEnabled: boolean;
  /** 浮动按钮位置：top-right（右上）或 top-left（左上）。默认 top-right。 */
  codesFloatingButtonPosition: "top-right" | "top-left";

  // ═══════ 存储后端（R2 / S3 兼容） ═══════
  /**
   * 存储后端选择：
   *   null 或 "r2"  —— 使用 Cloudflare R2 binding（默认，零配置）
   *   "s3"          —— 使用通用 S3 兼容存储（需要配置下面所有 s3_* 字段）
   */
  storageProvider: "r2" | "s3" | null;
  /** S3 endpoint，如 https://s3.amazonaws.com 或 https://oss-cn-hangzhou.aliyuncs.com */
  s3Endpoint: string | null;
  /** S3 region，如 us-east-1、ap-southeast-1 */
  s3Region: string | null;
  /** S3 bucket 名称 */
  s3Bucket: string | null;
  /** S3 Access Key ID（明文存） */
  s3AccessKeyId: string | null;
  /** S3 Secret Access Key —— 用 admin AES-GCM 加密后存 */
  s3SecretKeyCipher: string | null;
  /** S3 addressing style: "path"（默认）或 "virtual" */
  s3AddressingStyle: "path" | "virtual" | null;

  // ═══════ WebDAV 支持 ═══════
  /** 是否启用 WebDAV 服务（挂载点 /webdav/） */
  webdavEnabled: boolean;
  /** WebDAV Basic Auth 用户名（默认 "webdav"） */
  webdavUsername: string;
  /** WebDAV Basic Auth 密码哈希（salt:sha256hex） */
  webdavPasswordHash: string | null;
  /** WebDAV 可访问的根目录（默认 "/" = 全部文件；可设 "/shared" 等限制范围） */
  webdavRootPath: string;
}

export const DEFAULT_SETTINGS: Settings = {
  siteTitle: "cloud-r2pan",
  trafficLimitBytes: 10 * 1024 ** 3, // 10 GB
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
  webdavRootPath: "/",
};

function toInt(v: unknown, fallback: number): number {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

export async function getSettings(env: Env): Promise<Settings> {
  // ① 命中内存缓存 —— 5 秒内直接返回，零 D1 开销
  const now = Date.now();
  if (_cachedSettings && now - _cachedAt < SETTINGS_CACHE_TTL_MS) {
    return _cachedSettings;
  }

  const { results } = await env.db.prepare(
    "SELECT key, value FROM settings"
  ).all<{ key: string; value: string }>();
  const map = new Map((results ?? []).map((r) => [r.key, r.value]));

  // ── Bug #1 修复：跨月自动兜底 ──────────────────────────────────
  // 任何调用 getSettings 的地方（下载检查、stats API、settings API、session API）
  // 都会自动得到本月正确的流量值，不再出现"上月用完→本月锁死"的死锁。
  // 此处仅修正内存返回值，DB 实际清零由后续写入操作（addTraffic / stats）自愈。
  const currentMonth = new Date().toISOString().slice(0, 7);
  const storedMonth = map.get("traffic_month") ?? "";
  let trafficUsedBytes = toInt(map.get("traffic_used_bytes"), 0);
  let trafficMonth = storedMonth;
  if (storedMonth && storedMonth !== currentMonth && trafficUsedBytes > 0) {
    trafficUsedBytes = 0;
    trafficMonth = currentMonth;
  }

  const result: Settings = {
    siteTitle: map.get("site_title") ?? DEFAULT_SETTINGS.siteTitle,
    trafficLimitBytes: toInt(map.get("traffic_limit_bytes"), DEFAULT_SETTINGS.trafficLimitBytes),
    trafficUsedBytes,
    trafficMonth,
    maxDownloadsPerIp: toInt(map.get("max_downloads_per_ip"), DEFAULT_SETTINGS.maxDownloadsPerIp),
    countWindowHours: toInt(map.get("count_window_hours"), DEFAULT_SETTINGS.countWindowHours),
    autoBan: (map.get("auto_ban") ?? "1") === "1",
    banHours: toInt(map.get("ban_hours"), DEFAULT_SETTINGS.banHours),
    totpEnabled: map.get("totp_enabled") === "1",
    totpSecretCipher: map.get("totp_secret_cipher") ?? null,
    totpRecoveryHash: map.get("totp_recovery_hash") ?? null,
    turnstileMode: (map.get("turnstile_mode") ?? DEFAULT_SETTINGS.turnstileMode) as Settings["turnstileMode"],
    turnstileThreshold: toInt(map.get("turnstile_threshold"), DEFAULT_SETTINGS.turnstileThreshold),
    turnstileSitekeyOverride: map.get("turnstile_sitekey_override") ?? null,
    turnstileSecretCipher: map.get("turnstile_secret_cipher") ?? null,
    // OAuth2
    oauthEnabled: map.get("oauth_enabled") === "1",
    oauthProvider: map.get("oauth_provider") ?? DEFAULT_SETTINGS.oauthProvider,
    oauthClientId: map.get("oauth_client_id") ?? "",
    oauthClientSecretCipher: map.get("oauth_client_secret_cipher") ?? null,
    oauthScope: map.get("oauth_scope") ?? DEFAULT_SETTINGS.oauthScope,
    oauthCustomAuthorizeUrl: map.get("oauth_custom_authorize_url") ?? "",
    oauthCustomTokenUrl: map.get("oauth_custom_token_url") ?? "",
    oauthCustomUserinfoUrl: map.get("oauth_custom_userinfo_url") ?? "",
    oauthCustomTokenField: map.get("oauth_custom_token_field") ?? DEFAULT_SETTINGS.oauthCustomTokenField,
    adminIps: map.get("admin_ips") ?? "",
    homeRedirectMarket: map.get("home_redirect_market") === "1",
    // 激活码浮动按钮
    codesFloatingButtonEnabled: map.get("codes_floating_button_enabled") !== "0", // 默认 true
    codesFloatingButtonPosition: (map.get("codes_floating_button_position") ?? DEFAULT_SETTINGS.codesFloatingButtonPosition) as Settings["codesFloatingButtonPosition"],
    // 存储后端
    storageProvider: (map.get("storage_provider") ?? "r2") as Settings["storageProvider"],
    s3Endpoint: map.get("s3_endpoint") ?? null,
    s3Region: map.get("s3_region") ?? null,
    s3Bucket: map.get("s3_bucket") ?? null,
    s3AccessKeyId: map.get("s3_access_key_id") ?? null,
    s3SecretKeyCipher: map.get("s3_secret_key_cipher") ?? null,
    s3AddressingStyle: (map.get("s3_addressing_style") ?? "path") as Settings["s3AddressingStyle"],
    // WebDAV
    webdavEnabled: map.get("webdav_enabled") === "1",
    webdavUsername: map.get("webdav_username") ?? DEFAULT_SETTINGS.webdavUsername,
    webdavPasswordHash: map.get("webdav_password_hash") ?? null,
    webdavRootPath: map.get("webdav_root_path") ?? DEFAULT_SETTINGS.webdavRootPath,
  };

  // ② 写入内存缓存
  _cachedSettings = result;
  _cachedAt = Date.now();
  return result;
}

/** 更新设置（仅覆盖传入的字段） */
export async function updateSettings(env: Env, patch: Partial<Record<string, string>>): Promise<void> {
  const upserts = Object.entries(patch).map(([key, value]) =>
    env.db.prepare(
      "INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(key, String(value))
  );
  if (upserts.length > 0) await env.db.batch(upserts);
  // 主动失效缓存 —— 确保后续请求立即读到新值
  invalidateSettingsCache();
}

/**
 * 记录一次下载产生的流量（跨月自动重置）。
 *
 * ── 修复 1：累加语句命中 0 行 ──────────────────────────────
 * 原先用裸 `UPDATE settings SET value = ... WHERE key = 'traffic_used_bytes'`。
 * 这一行只在管理员点过「重置本月流量」时才存在，从未创建过的站点
 * UPDATE 匹配 0 行 → 下载多少流量都永远是 0。
 * 现在改成 `INSERT ... ON CONFLICT DO UPDATE`，行不存在就直接创建。
 *
 * ── 修复 2：跨月永远不清零 ────────────────────────────────
 * 原先 batch 的第一步就把 traffic_month 写成本月，第二步再用
 * `CASE WHEN traffic_month = 本月` 判断跨月 —— 读到的月份刚被自己改过，
 * ELSE '0' 分支不可能命中。
 * 现在的顺序是：① 按**旧的** traffic_month 条件清零 → ② 缺行时回填 →
 * ③ 原子累加 → ④ 才把 traffic_month 同步成本月。
 *
 * D1 batch 内语句在同一事务里顺序执行，累加由 SQL 自己完成（不经过
 * JS 读-改-写），并发下不会丢量；跨月时多个请求都执行 ① 也是幂等的。
 *
 * ── 修复 3：一次性回填历史流量 ──────────────────────────
 * traffic_stats（每日汇总）走的是 upsert，从来没被 bug 影响过，是可信的
 * 事实来源。若 traffic_used_bytes 行缺失（等价于管理员从未点过「重置本月
 * 流量」，因为重置会同时写入两行），就用它反推出当月真实已用流量补回一次，
 * 避免修复上线后本月流量从 0 重新数起。
 */
export async function addTraffic(env: Env, bytes: number): Promise<void> {
  const now = new Date();
  const month = now.toISOString().slice(0, 7);
  const day = now.toISOString().slice(0, 10);

  await env.db.batch([
    // ① 跨月清零：只在 traffic_month 不是本月时把已用流量归零
    //    （行不存在时本句命中 0 行，由 ③ 负责创建）
    env.db.prepare(
      `UPDATE settings SET value = '0'
       WHERE key = 'traffic_used_bytes'
         AND (SELECT value FROM settings WHERE key = 'traffic_month') IS NOT ?1`
    ).bind(month),

    // ② 一次性回填：行不存在 = 管理员从未点过「重置本月流量」（重置会同时写入两行），
    //    说明历史流量是被上面修复的那个 bug 丢掉的，按 traffic_stats 的当月合计补回。
    //    放在 ① 之后、③ 之前，保证只在真正缺行时生效一次。
    env.db.prepare(
      `INSERT INTO settings(key, value)
       SELECT 'traffic_used_bytes', COALESCE(
         (SELECT SUM(bytes) FROM traffic_stats WHERE day >= ?1), 0)
       WHERE NOT EXISTS (SELECT 1 FROM settings WHERE key = 'traffic_used_bytes')`
    ).bind(`${month}-01`),

    // ③ 原子累加，行不存在则创建
    env.db.prepare(
      `INSERT INTO settings(key, value) VALUES('traffic_used_bytes', ?1)
       ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(settings.value AS INTEGER) + CAST(excluded.value AS INTEGER) AS TEXT)`
    ).bind(String(bytes)),

    // ④ 月份同步必须在 ① 之后
    env.db.prepare(
      "INSERT INTO settings(key, value) VALUES('traffic_month', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(month),

    // ⑤ traffic_stats 每日汇总（原本就是原子累加，保持不变）
    env.db.prepare(
      "INSERT INTO traffic_stats(day, bytes, downloads) VALUES(?1, ?2, 1) ON CONFLICT(day) DO UPDATE SET bytes = bytes + excluded.bytes, downloads = downloads + excluded.downloads"
    ).bind(day, bytes),
  ]);
}
