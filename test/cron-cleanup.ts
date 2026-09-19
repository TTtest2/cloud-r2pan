/**
 * 定时清理测试
 *
 * cron 是唯一会"无人看着就动手"的代码，所以这里的断言比功能测试更严：
 *   - 过期的东西按语义处置（分享是撤销、直链是删行、回收站到期才真删）
 *   - 每一步都必须分批（LIMIT），否则免费档 10 ms CPU 会被一次大扫除打死
 *   - 绝不允许 cron 去扫"没有分享引用的活文件"并删除 —— 那是手动清理的权限
 *
 * 运行：
 *   npx esbuild test/cron-cleanup.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/cron-cleanup.mjs
 *   node .dev/cron-cleanup.mjs
 */
import { CLEANUP_BATCH, runScheduledCleanup } from "../src/cron";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

interface Share { id: string; file_id: string; revoked: number; expires_at: number | null }
interface Link { id: string; file_id: string; expires_at: number | null }
interface FileRow { id: string; key: string; deleted_at: number | null }

class Db {
  shares: Share[] = [];
  links: Link[] = [];
  files: FileRow[] = [];
  settings: Record<string, string> = { trash_retention_days: "7" };
  sqlLog: string[] = [];
  seenLimits: number[] = [];
  revokedIds: string[] = [];
  deletedLinkIds: string[] = [];
  purgedFileIds: string[] = [];
  abortedUploadIds: string[] = [];
  sessions: { id: string; key: string; upload_id: string; name: string; mime: string; folder_id: string | null; size_declared: number | null; created_at: number }[] = [];

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    let binds: any[] = [];
    const self = this;
    const stmt: any = {
      bind(...vals: unknown[]) {
        binds = vals as any[];
        return stmt;
      },
      async all() {
        return { results: self.dispatch(norm, binds, "all") ?? [], success: true, meta: {} };
      },
      async first() {
        return self.dispatch(norm, binds, "first");
      },
      async run() {
        self.dispatch(norm, binds, "run");
        return { success: true, meta: { changes: 1 } };
      },
    };
    return stmt;
  }
  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }

  private dispatch(sql: string, binds: any[], mode: string): any {
    this.sqlLog.push(sql);
    if (/^SELECT key, value FROM settings/.test(sql)) {
      return Object.entries(this.settings).map(([key, value]) => ({ key, value }));
    }
    if (/^SELECT id FROM shares WHERE revoked = 0 AND expires_at IS NOT NULL/.test(sql)) {
      const cutoff = Number(binds[0]);
      const limit = Number(binds[1]);
      this.seenLimits.push(Number(binds[1]));
      return this.shares.filter((s) => !s.revoked && s.expires_at !== null && s.expires_at < cutoff).slice(0, limit).map((s) => ({ id: s.id }));
    }
    if (/^UPDATE shares SET revoked = 1 WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      for (const s of this.shares) if (ids.includes(s.id)) s.revoked = 1;
      this.revokedIds.push(...ids);
      return null;
    }
    if (/^SELECT id FROM direct_links/.test(sql)) {
      const cutoff = Number(binds[0]);
      const limit = Number(binds[1]);
      this.seenLimits.push(Number(binds[1]));
      return this.links.filter((l) => l.expires_at !== null && l.expires_at < cutoff).slice(0, limit).map((l) => ({ id: l.id }));
    }
    if (/^DELETE FROM direct_links WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      this.links = this.links.filter((l) => !ids.includes(l.id));
      this.deletedLinkIds.push(...ids);
      return null;
    }
    if (/^SELECT id FROM files WHERE deleted_at IS NOT NULL AND deleted_at < \?1/.test(sql)) {
      const cutoff = Number(binds[0]);
      const limit = Number(binds[1]);
      this.seenLimits.push(Number(binds[1]));
      return this.files.filter((f) => f.deleted_at !== null && f.deleted_at < cutoff).slice(0, limit).map((f) => ({ id: f.id }));
    }
    if (/^SELECT id, key, folder_id FROM files WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      return this.files.filter((f) => ids.includes(f.id)).map((f) => ({ id: f.id, key: f.key, folder_id: null }));
    }
    if (/^DELETE FROM files WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      this.files = this.files.filter((f) => !ids.includes(f.id));
      this.purgedFileIds.push(...ids);
      return null;
    }
    if (/^DELETE FROM (shares|download_logs|direct_links) WHERE file_id IN/.test(sql)) return null;
    if (/^SELECT id, key, upload_id, name, mime, folder_id, size_declared, created_at FROM upload_sessions WHERE created_at < \?1/.test(sql)) {
      const cutoff = Number(binds[0]);
      this.seenLimits.push(Number(binds[1]));
      return this.sessions.filter((s) => s.created_at < cutoff).slice(0, Number(binds[1])).map((s) => ({ ...s }));
    }
    if (/^DELETE FROM upload_sessions WHERE id IN/.test(sql)) {
      const ids = binds.map(String);
      this.sessions = this.sessions.filter((s) => !ids.includes(s.id));
      this.abortedUploadIds.push(...ids);
      return null;
    }
    if (/^SELECT id, key FROM files WHERE deleted_at IS NULL ORDER BY RANDOM\(\)/.test(sql)) {
      const limit = Number(binds[0]);
      return this.files.filter((f) => !f.deleted_at).slice(0, limit);
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }
}

/** storage.ts 只按设置指纹造一个 provider 并绑住第一次见到的 r2，所以日志必须是全局的 */
const DELETED_KEYS: string[] = [];
const MISSING_KEYS = new Set(["files/fn"]);

function env(now: number) {
  invalidateSettingsCache();
  DELETED_KEYS.length = 0;
  const db = new Db();
  db.shares = [
    { id: "sx", file_id: "fx", revoked: 0, expires_at: now - 1000 },
    { id: "sl", file_id: "fl", revoked: 0, expires_at: now + 3_600_000 },
    { id: "sn", file_id: "fn", revoked: 0, expires_at: null },
  ];
  db.links = [
    { id: "dlx", file_id: "fx", expires_at: now - 1000 },
    { id: "dll", file_id: "fl", expires_at: now + 3_600_000 },
  ];
  db.files = [
    { id: "fx", key: "files/fx", deleted_at: null },
    { id: "fl", key: "files/fl", deleted_at: null },
    { id: "fn", key: "files/fn", deleted_at: null },
    { id: "told", key: "files/told", deleted_at: now - 30 * 86_400_000 },
    { id: "trecent", key: "files/trecent", deleted_at: now - 60_000 },
  ];
  db.sessions = [
    { id: "u-old", key: "files/u-old", upload_id: "up-old", name: "a.iso", mime: "application/octet-stream", folder_id: null, size_declared: null, created_at: now - 3 * 86_400_000 },
    { id: "u-new", key: "files/u-new", upload_id: "up-new", name: "b.iso", mime: "application/octet-stream", folder_id: null, size_declared: null, created_at: now - 60_000 },
  ];
  const r2 = {
    async get(key: string) {
      return { body: new Uint8Array(4), size: 4, httpEtag: "e", httpMetadata: {}, key };
    },
    async head(key: string) {
      return MISSING_KEYS.has(key) ? null : { size: 4, httpMetadata: {}, key };
    },
    async delete(key: string) {
      DELETED_KEYS.push(key);
    },
    resumeMultipartUpload(key: string, uploadId: string) {
      return {
        uploadId,
        async abort() {
          DELETED_KEYS.push("abort:" + key);
        },
      };
    },
  };
  return { env: { db, r2, admin: "sekret" } as any, db, deletedKeys: DELETED_KEYS };
}

async function main() {
  console.log("\n[1] 过期分享与到期直链");
  {
    const now = Date.now();
    invalidateSettingsCache();
    const h = env(now);
    const report = await runScheduledCleanup(h.env, now);
    check("过期分享被撤销而不是删行", report.shares_revoked === 1 && h.db.shares.find((s) => s.id === "sx")?.revoked === 1, JSON.stringify(report));
    check("撤销不删分享行（后台要能看到历史）", h.db.shares.length === 3, String(h.db.shares.length));
    check("未过期/永久分享不受影响", h.db.shares.filter((s) => s.id !== "sx").every((s) => s.revoked === 0));
    check("到期直链行被删掉", report.links_deleted === 1 && !h.db.links.some((l) => l.id === "dlx"), JSON.stringify(h.db.links));
    check("未到期直链保留", h.db.links.some((l) => l.id === "dll"));
  }

  console.log("\n[2] 回收站到期才真删");
  {
    const now = Date.now();
    invalidateSettingsCache();
    const h = env(now);
    const report = await runScheduledCleanup(h.env, now);
    check("超过 7 天的条目被彻底清除", report.trash_purged === 1 && !h.db.files.some((f) => f.id === "told"), JSON.stringify(report));
    check("连带删掉它的存储对象", h.deletedKeys.includes("files/told"), JSON.stringify(h.deletedKeys));
    check("保留期内的条目不动", h.db.files.some((f) => f.id === "trecent" && f.deleted_at !== null));
    check("活文件没被误删", h.db.files.filter((f) => !f.deleted_at).length === 3, JSON.stringify(h.db.files));
  }

  console.log("\n[3] 分批是硬要求（免费档 10 ms CPU / 50 子请求）");
  {
    const now = Date.now();
    invalidateSettingsCache();
    const h = env(now);
    await runScheduledCleanup(h.env, now);
    const batched = h.db.sqlLog.filter((s) => /^SELECT id FROM (shares|direct_links)/.test(s) || /deleted_at < \?1 ORDER BY deleted_at/.test(s));
    check("三类扫描都带 LIMIT", batched.length >= 3 && batched.every((s) => /LIMIT \?\d/.test(s)), JSON.stringify(batched));
    check("四类扫描的分批量都是 CLEANUP_BATCH", h.db.seenLimits.length === 4 && h.db.seenLimits.every((n) => n === CLEANUP_BATCH), JSON.stringify(h.db.seenLimits));
    check("抽查对象也限量", h.db.sqlLog.some((s) => /ORDER BY RANDOM\(\) LIMIT \?1/.test(s)), s0(h.db.sqlLog));
    check("cron 不扫孤儿文件", !h.db.sqlLog.some((s) => /LEFT JOIN shares s ON s\.file_id = f\.id/.test(s)), s0(h.db.sqlLog));
    check("cron 不物理删活文件行", h.db.purgedFileIds.every((id) => ["told"].includes(id)), JSON.stringify(h.db.purgedFileIds));
  }

  console.log("\n[4] 对象抽查只报告不处置");
  {
    const now = Date.now();
    invalidateSettingsCache();
    const h = env(now);
    const report = await runScheduledCleanup(h.env, now);
    check("报出丢字节的文件", report.missing_objects.includes("fn"), JSON.stringify(report.missing_objects));
    check("没有擅自删这条行", h.db.files.some((f) => f.id === "fn"));
    check("也没删任何对象", !h.deletedKeys.includes("files/fn"), JSON.stringify(h.deletedKeys));
  }

  console.log("\n[5] 关闭回收站时不重复劳动");
  {
    const now = Date.now();
    invalidateSettingsCache();
    const h = env(now);
    h.db.settings.trash_retention_days = "0";
    const report = await runScheduledCleanup(h.env, now);
    check("保留期 0 → 没有到期条目可清", report.trash_purged === 0 && !h.db.sqlLog.some((s) => /deleted_at < \?1 ORDER BY deleted_at/.test(s)), JSON.stringify(report));
  }

  console.log("\n[6] 超时未完成的分片上传");
  {
    const now = Date.now();
    invalidateSettingsCache();
    const h = env(now);
    const report = await runScheduledCleanup(h.env, now);
    check("中止一条超时会话", report.uploads_aborted === 1 && h.db.abortedUploadIds.join(",") === "u-old", JSON.stringify(report));
    check("没完成的分片被 abort", h.deletedKeys.includes("abort:files/u-old"), JSON.stringify(h.deletedKeys));
    check("还在传的那条不动", h.db.sessions.some((s) => s.id === "u-new"));
    check("abort 不会顺手删掉对象本身", !h.deletedKeys.includes("files/u-new") && !h.deletedKeys.includes("files/fx"), JSON.stringify(h.deletedKeys));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

function s0(log: string[]): string {
  return log.join("  ||  ").slice(0, 400);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
