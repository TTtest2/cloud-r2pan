import type { Env } from "./types";

/**
 * 数据库初始化 —— 首次请求时自动建表, 无需手动迁移。
 * 表结构:
 *   files              上传到 R2 的文件元数据
 *   shares             分享链接 (token 即主键)
 *   download_logs      下载记录 (IP / 浏览器 / 系统 / 流量)
 *   login_logs         管理员登录记录 (成功/失败/登出, 防盗号审计)
 *   turnstile_visits   IP 每日访问计数 (超过阈值触发 Turnstile)
 *   banned_ips         封禁名单 (支持到期自动解封)
 *   settings           可调参数 + 流量用量统计
 *   traffic_stats      每日流量/下载汇总 (用于图表)
 */
const SCHEMA_STATEMENTS: string[] = [
  // ⚠️ key 故意不加 UNIQUE：内容去重后多个 files 行会指向同一个对象，
  //    "还能不能删这个对象"由引用计数决定（见 src/trash.ts），不靠约束。
  `CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime TEXT NOT NULL DEFAULT 'application/octet-stream',
    uploaded_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS shares (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    password_hash TEXT,
    password_cipher TEXT,
    download_name TEXT,
    is_market INTEGER NOT NULL DEFAULT 0,
    market_views INTEGER NOT NULL DEFAULT 0,
    market_title TEXT,
    market_desc TEXT,
    direct_id TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_shares_file ON shares(file_id)`,
  `CREATE INDEX IF NOT EXISTS idx_shares_market ON shares(is_market, revoked)`,
  `CREATE TABLE IF NOT EXISTS direct_links (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    max_downloads INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    download_name TEXT,
    notes TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_direct_links_file ON direct_links(file_id)`,
  `CREATE TABLE IF NOT EXISTS download_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id TEXT NOT NULL,
    file_id TEXT NOT NULL,
    file_name TEXT NOT NULL,
    ip TEXT NOT NULL,
    ua TEXT,
    browser TEXT,
    os TEXT,
    country TEXT,
    bytes INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_logs_share_ip ON download_logs(share_id, ip, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_logs_created ON download_logs(created_at)`,
  `CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    ip TEXT NOT NULL,
    ua TEXT,
    browser TEXT,
    os TEXT,
    country TEXT,
    result TEXT NOT NULL,
    reason TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_login_logs_created ON login_logs(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_login_logs_ip ON login_logs(ip)`,
  `CREATE TABLE IF NOT EXISTS turnstile_visits (
    ip TEXT NOT NULL,
    day TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(ip, day)
  )`,
  `CREATE INDEX IF NOT EXISTS idx_turnstile_day ON turnstile_visits(day)`,
  `CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at INTEGER NOT NULL,
    expires_at INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS traffic_stats (
    day TEXT PRIMARY KEY,
    bytes INTEGER NOT NULL DEFAULT 0,
    downloads INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS oauth_states (
    state TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at)`,
  `CREATE TABLE IF NOT EXISTS oauth_providers (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    client_secret_cipher TEXT,
    scope TEXT NOT NULL DEFAULT 'openid email profile',
    custom_authorize_url TEXT NOT NULL DEFAULT '',
    custom_token_url TEXT NOT NULL DEFAULT '',
    custom_userinfo_url TEXT NOT NULL DEFAULT '',
    custom_token_field TEXT NOT NULL DEFAULT 'access_token',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_oauth_providers_enabled ON oauth_providers(enabled)`,
  // ═══════════ 激活码 ═══════════
  // 每个激活码独立额度，和全局 traffic_limit_bytes 互不影响
  `CREATE TABLE IF NOT EXISTS activation_plans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    traffic_bytes INTEGER NOT NULL DEFAULT 0,
    days_valid INTEGER NOT NULL DEFAULT 0,
    quota_message TEXT,
    batch_id TEXT,
    notes TEXT,
    created_at INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS activation_codes (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    plan_id TEXT,
    traffic_bytes INTEGER NOT NULL DEFAULT 0,
    used_bytes INTEGER NOT NULL DEFAULT 0,
    days_valid INTEGER NOT NULL DEFAULT 0,
    quota_message TEXT,
    status TEXT NOT NULL DEFAULT 'unused',
    batch_id TEXT,
    notes TEXT,
    created_at INTEGER NOT NULL,
    activated_at INTEGER,
    expires_at INTEGER
  )`,
  `CREATE INDEX IF NOT EXISTS idx_codes_status ON activation_codes(status)`,
  `CREATE INDEX IF NOT EXISTS idx_codes_batch ON activation_codes(batch_id)`,
  `CREATE INDEX IF NOT EXISTS idx_codes_code ON activation_codes(code)`,
  // ═══════════ WebDAV 虚拟目录 ═══════════
  `CREATE TABLE IF NOT EXISTS directories (
    path TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
  )`,
];

let schemaReady = false;

/**
 * 确保数据库表结构存在 —— 首次请求时自动建表，无需手动迁移。
 *
 * ── Bug #5 修复：并发 DDL 风险 ──────────────────────────────────
 * 原实现每个 Isolate 都有独立的 schemaReady 布尔，冷启动时多 Isolate 会并发跑 DDL batch，
 * 虽然 CREATE TABLE IF NOT EXISTS 本身幂等，但每次都跑完整 DDL 很重。
 *
 * 新实现分层短路：
 *   1. schemaReady（内存）—— 本 Isolate 内的快速短路，零成本
 *   2. 轻量 SELECT settings —— 跨 Isolate 安全检测，schema 已就绪时极快（D1 命中索引）
 *   3. 只有表真的不存在时才执行 DDL batch —— 且用 try/catch 兜底竞态
 *
 * 绝大多数请求命中 ① 或 ②，不会触发 DDL。
 *
 * ⚠️ 注意：ALTER TABLE 迁移语句不参与 schemaReady 短路，每次 ensureSchema 都执行一遍
 * （用 try/catch 保护，列已存在时静默忽略），保证老用户库升级后列补齐。
 */

/** 所有增量迁移语句 —— 用 migration_version 追踪已执行版本，只跑未执行的 */
const MIGRATION_STATEMENTS: string[] = [
  "ALTER TABLE shares ADD COLUMN password_hash TEXT",
  "ALTER TABLE shares ADD COLUMN password_cipher TEXT",
  "ALTER TABLE shares ADD COLUMN download_name TEXT",
  "ALTER TABLE download_logs ADD COLUMN activation_code TEXT",
  "ALTER TABLE shares ADD COLUMN is_market INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE shares ADD COLUMN market_views INTEGER NOT NULL DEFAULT 0",
  "ALTER TABLE shares ADD COLUMN market_title TEXT",
  "ALTER TABLE shares ADD COLUMN market_desc TEXT",
  "CREATE INDEX IF NOT EXISTS idx_shares_market ON shares(is_market, revoked)",
  // ═══════════ WebDAV 虚拟目录 ═══════════
  "ALTER TABLE files ADD COLUMN path TEXT NOT NULL DEFAULT '/'",
  "CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)",
  // ═══════════ 目录树（顶层 parent_id IS NULL；同层不重名，跨层可重名） ═══════════
  "CREATE TABLE IF NOT EXISTS folders(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)",
  "ALTER TABLE files ADD COLUMN folder_id TEXT",
  "CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id)",
  // ═══════════ 分享派生直链（shares.direct_id → direct_links.id） ═══════════
  "ALTER TABLE shares ADD COLUMN direct_id TEXT",
  // ═══════════ 目录模型统一 Phase 1：folders 升级为 parent_id 树 ═══════════
  // 旧表的 name 上是表级 UNIQUE（全局唯一），SQLite 无法 ALTER 掉，
  // 由 migrateFolderTree 重建表去掉；这里只补列与同层唯一索引。
  "ALTER TABLE folders ADD COLUMN parent_id TEXT",
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_root_name ON folders(name) WHERE parent_id IS NULL",
  "CREATE UNIQUE INDEX IF NOT EXISTS idx_folders_child_name ON folders(parent_id, name) WHERE parent_id IS NOT NULL",
  "CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id)",
  // ═══════════ 回收站：软删除（deleted_at 非空 = 在回收站里，对象仍占存储） ═══════════
  "ALTER TABLE files ADD COLUMN deleted_at INTEGER",
  "CREATE INDEX IF NOT EXISTS idx_files_deleted ON files(deleted_at)",
  // ═══════════ 分片上传会话（id 就是将来 files.id，合并成功后该行被删掉） ═══════════
  `CREATE TABLE IF NOT EXISTS upload_sessions(
    id TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    upload_id TEXT NOT NULL,
    name TEXT NOT NULL,
    mime TEXT NOT NULL,
    folder_id TEXT,
    size_declared INTEGER,
    created_at INTEGER NOT NULL
  )`,
  "CREATE INDEX IF NOT EXISTS idx_upload_sessions_created ON upload_sessions(created_at)",
  // ═══════════ 分享整个目录 ═══════════
  // folder_id 非空 = 目录分享；此时 file_id 是 ''（shares.file_id 是 NOT NULL，
  // 老库不做表重建）。所有 `JOIN files f ON f.id = s.file_id` 因此天然不会命中目录分享，
  // 需要展示目录分享的查询必须走 folder_id。
  "ALTER TABLE shares ADD COLUMN folder_id TEXT",
  "CREATE INDEX IF NOT EXISTS idx_shares_folder ON shares(folder_id)",
  // ═══════════════ 内容去重与秒传 ═══════════════
  // 两条互补的指纹：
  //   sha256 —— 浏览器算好随上传带上（唯一能"一个字节都不传"的秒传依据）
  //   etag   —— 存储后端写完对象的回执（分片上传形如 "…-N"），服务端零成本可得，
  //             用于写后去重：发现重复就把刚写的那份对象删掉、行改指已有 key
  // 去重后同一个 key 会被多行引用 —— "还能不能删对象"只看剩余行数，不看行 id。
  "ALTER TABLE files ADD COLUMN sha256 TEXT",
  "ALTER TABLE files ADD COLUMN etag TEXT",
  "CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256) WHERE sha256 IS NOT NULL",
  "CREATE INDEX IF NOT EXISTS idx_files_etag ON files(etag) WHERE etag IS NOT NULL",
  "ALTER TABLE upload_sessions ADD COLUMN sha256 TEXT",
];

/**
 * 幂等迁移：读 settings.migration_version，只跑 index >= version 的迁移语句。
 * 这样每个迁移只执行一次，避免每次请求都白跑 9 条 ALTER。
 * migration_version 存的是"已执行到的最高下标"，默认 -1（一个都没跑过）。
 */
async function runMigrations(env: Env): Promise<void> {
  let version = -1;
  try {
    const row: any = await env.db.prepare(
      "SELECT value FROM settings WHERE key = 'migration_version'"
    ).first();
    if (row?.value) version = Number(row.value) - 1; // 存的是 len（已执行数量），转成下标
  } catch {
    // settings 表可能还不存在（首次部署），这时候全跑一遍
  }

  if (version >= MIGRATION_STATEMENTS.length - 1) return; // 最新

  // 只跑 version+1 之后的迁移
  for (let i = version + 1; i < MIGRATION_STATEMENTS.length; i++) {
    try {
      await env.db.prepare(MIGRATION_STATEMENTS[i]).run();
    } catch {
      /* 列/索引已存在，忽略（保持幂等兜底） */
    }
  }

  // 写入新版本（存数量，不是下标）
  try {
    await env.db.prepare(
      "INSERT INTO settings(key, value) VALUES('migration_version', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
    ).bind(String(MIGRATION_STATEMENTS.length)).run();
  } catch {
    /* settings 表不存在时忽略 */
  }
}

/**
 * folders：从"平铺单层 + 全局唯一名"升级为"parent_id 树 + 同层唯一名"。
 *
 * 旧表的 name 上挂着表级 UNIQUE（全局唯一），而 WebDAV 里 /a/b 与 /c/b 这种
 * 跨层同名必须允许，SQLite 又不能 ALTER 掉约束 —— 只能重建表。
 * 只在 sqlite_master 里读到旧约束时才动手，重建的 4 条 DDL 放进一个 D1 batch
 * （batch 内同一事务），中途失败不会留下半张表。
 */
export async function migrateFolderTree(env: Env): Promise<void> {
  let legacySql = "";
  try {
    const row = await env.db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'folders'")
      .first<{ sql: string | null }>();
    legacySql = row?.sql ?? "";
  } catch {
    return; // 读不到 sqlite_master：交给后面的迁移语句兜底
  }
  if (!legacySql) return;                     // 表还不存在（新部署走建表语句）
  if (!/\bUNIQUE\b/i.test(legacySql)) return; // 已经是新形状

  await env.db.batch([
    env.db.prepare(
      "CREATE TABLE folders_v2(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)"
    ),
    env.db.prepare(
      "INSERT INTO folders_v2(id, name, parent_id, created_at) SELECT id, name, NULL, created_at FROM folders"
    ),
    env.db.prepare("DROP TABLE folders"),
    env.db.prepare("ALTER TABLE folders_v2 RENAME TO folders"),
  ]);
}

/**
 * 旧 WebDAV 模型（directories 路径表 + files.path 存完整路径）→ folders 树。
 *
 * 幂等：只处理"还没归属"的行（folder_id IS NULL 且 path 不是 '/'），
 * 搬完后把根下文件的 path 归位成 '/'，于是预检查自然为假、后续冷启动零开销。
 * 万一回滚过、旧代码又写了新行，下次冷启动会再捡一次。
 */
export async function migrateLegacyFolders(env: Env): Promise<{ folders: number; files: number }> {
  const pendingDirs = await env.db.prepare("SELECT 1 FROM directories LIMIT 1").first();
  const pendingFiles = await env.db
    .prepare("SELECT 1 FROM files WHERE folder_id IS NULL AND path IS NOT NULL AND path != '/' LIMIT 1")
    .first();
  if (!pendingDirs && !pendingFiles) return { folders: 0, files: 0 };

  const idByPath = new Map<string, string | null>();
  let folders = 0;

  /** 保证 /a/b/c 这条路径上的每一层都存在，返回最内层 id（根为 null） */
  async function ensureFolderPath(path: string): Promise<string | null> {
    if (path === "/" || path === "") return null;
    if (idByPath.has(path)) return idByPath.get(path)!;
    const last = path.lastIndexOf("/");
    const parentPath = last <= 0 ? "/" : path.slice(0, last);
    const name = path.slice(last + 1);
    const parentId = await ensureFolderPath(parentPath);

    const existing = await findChild(name, parentId);
    if (existing) {
      idByPath.set(path, existing);
      return existing;
    }
    const id = randomId(14);
    try {
      await insertFolder(id, name, parentId);
      folders++;
    } catch {
      const raced = await findChild(name, parentId); // 并发迁移：别人刚建好
      if (!raced) throw new Error("migrateLegacyFolders: 无法建目录 " + path);
      return raced;
    }
    idByPath.set(path, id);
    return id;
  }

  function findChild(name: string, parentId: string | null) {
    const stmt = parentId === null
      ? env.db.prepare("SELECT id FROM folders WHERE parent_id IS NULL AND name = ?1").bind(name)
      : env.db.prepare("SELECT id FROM folders WHERE parent_id = ?1 AND name = ?2").bind(parentId, name);
    return stmt.first<{ id: string }>().then((r) => r?.id ?? null);
  }

  function insertFolder(id: string, name: string, parentId: string | null) {
    return env.db
      .prepare("INSERT INTO folders(id, name, parent_id, created_at) VALUES(?1, ?2, ?3, ?4)")
      .bind(id, name, parentId, Date.now())
      .run();
  }

  // ① 显式目录：按路径长度排序，保证父层先建
  const { results: dirs } = await env.db
    .prepare("SELECT path FROM directories ORDER BY length(path)")
    .all<{ path: string }>();
  for (const d of dirs ?? []) await ensureFolderPath(d.path);

  // ② 文件归属
  const { results: files } = await env.db
    .prepare(
      "SELECT id, name, path FROM files WHERE folder_id IS NULL AND path IS NOT NULL AND path != '/'"
    )
    .all<{ id: string; name: string; path: string }>();

  let moved = 0;
  for (const f of files ?? []) {
    const last = f.path.lastIndexOf("/");
    const parentPath = last <= 0 ? "/" : f.path.slice(0, last);
    const folderId = await ensureFolderPath(parentPath);

    // 目标目录里已有同名文件：给搬来的换个名字，绝不覆盖别人的文件
    const clash = await env.db
      .prepare(
        folderId === null
          ? "SELECT 1 FROM files WHERE folder_id IS NULL AND name = ?1 AND id != ?2 LIMIT 1"
          : "SELECT 1 FROM files WHERE folder_id = ?1 AND name = ?2 AND id != ?3 LIMIT 1"
      )
      .bind(...(folderId === null ? [f.name, f.id] : [folderId, f.name, f.id]))
      .first();
    const name = clash ? uniqueName(f.name) : f.name;

    if (folderId === null) {
      // 本来就在根：归属不变，把 path 归位成 '/'，让预检查下次直接为假
      await env.db.prepare("UPDATE files SET path = '/' WHERE id = ?1").bind(f.id).run();
    } else {
      await env.db
        .prepare("UPDATE files SET folder_id = ?1, name = ?2 WHERE id = ?3")
        .bind(folderId, name, f.id)
        .run();
    }
    moved++;
  }

  // ③ directories 表清空 —— 新树是唯一事实；旧代码靠 files.path 仍能推断出目录
  if (dirs?.length) {
    for (const d of dirs) await env.db.prepare("DELETE FROM directories WHERE path = ?1").bind(d.path).run();
  }
  console.log(`[migrateLegacyFolders] 建目录 ${folders} 个，归位文件 ${moved} 个`);
  return { folders, files: moved };
}

/** 撞名时用的兜底名字：在扩展名前插一个短后缀 */
function uniqueName(name: string): string {
  const suffix = " (migrated)";
  const dot = name.lastIndexOf(".");
  if (dot > 0) return name.slice(0, dot) + suffix + name.slice(dot);
  return name + suffix;
}

/**
 * 去掉 files.key 的 UNIQUE 约束 —— 内容去重的前提。
 *
 * 原始建表语句是 `key TEXT NOT NULL UNIQUE`，隐含"一行一个对象"。去重之后多个
 * files 行会指向同一个 key（对象只存一份，能不能删由引用计数决定），重指那一步
 * 会直接 SQLITE_CONSTRAINT 失败。SQLite 不能 ALTER 掉列上的 UNIQUE，只能重建表。
 *
 * 列是从 PRAGMA table_info 现读现拼的，所以这条迁移必须排在增量迁移**之后**
 * （deleted_at / sha256 / etag 这些列得先存在），且可以反复执行：
 * 表里没有 UNIQUE 时第一步就返回。
 */
export async function migrateFilesKeyShareable(env: Env): Promise<void> {
  let currentSql = "";
  try {
    const row = await env.db
      .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'files'")
      .first<{ sql: string | null }>();
    currentSql = row?.sql ?? "";
  } catch {
    return; // 读不到 sqlite_master：交给其它迁移兜底
  }
  if (!currentSql) return;                     // 表还不存在 → 建表语句已是新形状
  if (!/\bUNIQUE\b/i.test(currentSql)) return; // 已经能共享 key

  const { results: cols } = await env.db
    .prepare("PRAGMA table_info(files)")
    .all<{ name: string; type: string; notnull: number; dflt_value: string | null; pk: number }>();
  const list = cols ?? [];
  if (!list.length) return;

  const defs = list.map((c) => {
    const parts = [`"${c.name}"`, c.type || "TEXT"];
    if (c.pk === 1) parts.push("PRIMARY KEY");
    else if (c.notnull) parts.push("NOT NULL");
    if (c.dflt_value !== null && c.dflt_value !== undefined) parts.push(`DEFAULT ${c.dflt_value}`);
    return parts.join(" ");
  });
  const names = list.map((c) => `"${c.name}"`).join(", ");

  await env.db.batch([
    env.db.prepare(`CREATE TABLE files_v2(${defs.join(", ")})`),
    env.db.prepare(`INSERT INTO files_v2(${names}) SELECT ${names} FROM files`),
    env.db.prepare("DROP TABLE files"),
    env.db.prepare("ALTER TABLE files_v2 RENAME TO files"),
    // 重建表会带走原来的索引，这里把非唯一索引全部补回来
    env.db.prepare("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)"),
    env.db.prepare("CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id)"),
    env.db.prepare("CREATE INDEX IF NOT EXISTS idx_files_deleted ON files(deleted_at)"),
    env.db.prepare("CREATE INDEX IF NOT EXISTS idx_files_sha ON files(sha256) WHERE sha256 IS NOT NULL"),
    env.db.prepare("CREATE INDEX IF NOT EXISTS idx_files_etag ON files(etag) WHERE etag IS NOT NULL"),
  ]);
}

export async function ensureSchema(env: Env): Promise<void> {
  // ① 防御性检查：如果数据库绑定不存在，直接报错
  if (!env.db) {
    throw new Error("Database binding 'db' is not configured. " +
      "在 Cloudflare 控制台 → Worker Settings → Bindings 添加 D1 绑定，" +
      "或在 wrangler.jsonc 的 d1_databases 中声明。");
  }

  // ② 内存短路 —— 本 isolate 已确认过 schema + 迁移都就绪，直接返回，零成本
  //    Worker 冷启动 / isolate 重启时 schemaReady=false，会重新跑一遍
  if (schemaReady) return;

  // ③ 跨 Isolate 安全检测：用 sqlite_master 检查表是否存在
  let tablesExist = false;
  try {
    const row: any = await env.db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
    ).first();
    tablesExist = !!row;
  } catch {
    // 查询失败（如数据库完全损坏），继续尝试建表
  }

  if (!tablesExist) {
    // ④ 真正的建表路径（首次部署 / 库被清空时触发）
    // 用 try/catch 处理极端竞态：另一个 Isolate 刚好也在执行 DDL
    try {
      await env.db.batch(SCHEMA_STATEMENTS.map((sql) => env.db.prepare(sql)));
    } catch {
      // 竞态兜底：可能另一个 Isolate 刚建完表。
      // 再检测一次，确认表存在就算成功
      try {
        const row: any = await env.db.prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
        ).first();
        if (!row) throw new Error("schema still missing after DDL attempt");
      } catch (e) {
        // 表确实没建起来，重新抛出让上层决定
        throw e;
      }
    }
  }

  // ⑤ 目录表升级 —— 必须在增量迁移之前（新的同层唯一索引依赖重建后的列）
  await migrateFolderTree(env);

  // ⑥ 跑增量迁移（幂等，只跑未执行过的）
  await runMigrations(env);

  // ⑦ 旧 WebDAV 目录数据搬进 folders 树（幂等，无活可干时两条 LIMIT 1 就返回）
  await migrateLegacyFolders(env);

  // ⑧ 去掉 files.key 的 UNIQUE（必须排在增量迁移之后：新列要先存在）
  await migrateFilesKeyShareable(env);

  schemaReady = true;
}

/** 生成 URL 安全的随机 ID */
export function randomId(len = 12): string {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}
