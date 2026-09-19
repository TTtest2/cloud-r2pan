/**
 * 定时清理 —— Workers Cron Trigger 的正文
 *
 * 为什么必须有人定期跑：分享/直链的过期只在查询时被判断，行本身永远留在库里；
 * 回收站条目到期后要真的删对象；分片上传中断后残留的 part 会一直计费。
 * 没有定时任务，这些东西就只增不减。
 *
 * ⚠️ 免费档的两条硬约束决定了这里的写法：
 *   1. 每次调用只有 10 ms CPU —— 所以每一步都带 LIMIT 分批，不做全表清扫
 *   2. 每请求最多 50 个子请求 —— D1/R2 往返都算，所以宁少勿多，跑不完下轮再续
 *
 * 还有一条纪律：**定时任务不许无人监督地删活人的数据**。
 * 后台"清理失效分享"里那个"没有任何分享引用的文件"扫描只由管理员手动触发，
 * 绝不在 cron 里跑；cron 只处理有明确到期语义的东西（过期分享、过期直链、
 * 到期回收站、超时未完成的分片）。
 */

import type { Env } from "./types";
import { getSettings } from "./settings";
import { deleteObjects, expiredTrashIds, purgeFiles } from "./trash";

/** 单轮每步最多处理多少条 —— 撞 CPU 上限就下一轮接着跑 */
export const CLEANUP_BATCH = 100;
/** 每轮抽查多少个对象确认字节还在（R2 读操作，免费档 1000 万次/月很宽裕） */
export const PROBE_SAMPLE = 20;

export interface CleanupReport {
  shares_revoked: number;
  links_deleted: number;
  trash_purged: number;
  objects_deleted: number;
  uploads_aborted: number;
  /** 抽查中发现"行还在、对象没了"的文件 id —— 只报告，不擅自处置 */
  missing_objects: string[];
}

function inClause(ids: string[], startIndex = 1): string {
  return ids.map((_, i) => `?${startIndex + i}`).join(", ");
}

/** 撤销已过期的分享（保留行，后台还能看到"已过期"，只是不再对外可用） */
async function revokeExpiredShares(env: Env, now: number): Promise<number> {
  const { results } = await env.db
    .prepare(
      `SELECT id FROM shares
       WHERE revoked = 0 AND expires_at IS NOT NULL AND expires_at < ?1
       ORDER BY expires_at LIMIT ?2`
    )
    .bind(now, CLEANUP_BATCH)
    .all<{ id: string }>();
  const ids = (results ?? []).map((r) => r.id);
  if (!ids.length) return 0;
  await env.db
    .prepare(`UPDATE shares SET revoked = 1 WHERE id IN (${inClause(ids)})`)
    .bind(...ids)
    .run();
  return ids.length;
}

/** 删除已到期的直链（直链没有"过期后仍可恢复"的语义，行直接清掉） */
async function deleteExpiredLinks(env: Env, now: number): Promise<number> {
  const { results } = await env.db
    .prepare(
      `SELECT id FROM direct_links
       WHERE expires_at IS NOT NULL AND expires_at < ?1
       ORDER BY expires_at LIMIT ?2`
    )
    .bind(now, CLEANUP_BATCH)
    .all<{ id: string }>();
  const ids = (results ?? []).map((r) => r.id);
  if (!ids.length) return 0;
  await env.db
    .prepare(`DELETE FROM direct_links WHERE id IN (${inClause(ids)})`)
    .bind(...ids)
    .run();
  return ids.length;
}

/**
 * 抽查若干活文件，看存储对象是否还在。
 * 随机取样：跑几轮就能覆盖全站，而每次只花 PROBE_SAMPLE 次 R2 读。
 */
async function probeObjects(env: Env): Promise<string[]> {
  const { results } = await env.db
    .prepare(`SELECT id, key FROM files WHERE deleted_at IS NULL ORDER BY RANDOM() LIMIT ?1`)
    .bind(PROBE_SAMPLE)
    .all<{ id: string; key: string }>();
  const rows = results ?? [];
  if (!rows.length) return [];
  const { getStorageProvider } = await import("./storage");
  const st = await getStorageProvider(env);
  const missing: string[] = [];
  for (const r of rows) {
    try {
      const head = await st.head(r.key);
      if (!head) missing.push(r.id);
    } catch {
      /* 存储临时故障不算丢数据，下一轮再说 */
    }
  }
  return missing;
}

/** 一轮定时清理；cron 与后台"立即运行"按钮共用同一个入口 */
export async function runScheduledCleanup(env: Env, now = Date.now()): Promise<CleanupReport> {
  const s = await getSettings(env);
  const report: CleanupReport = {
    shares_revoked: 0,
    links_deleted: 0,
    trash_purged: 0,
    objects_deleted: 0,
    uploads_aborted: 0,
    missing_objects: [],
  };

  report.shares_revoked = await revokeExpiredShares(env, now);
  report.links_deleted = await deleteExpiredLinks(env, now);

  const due = await expiredTrashIds(env, s, now, CLEANUP_BATCH);
  if (due.length) {
    const r = await purgeFiles(env, due);
    report.trash_purged = r.purged;
    report.objects_deleted = r.keys.length;
    await deleteObjects(env, r.keys);
  }

  report.missing_objects = await probeObjects(env);
  return report;
}
