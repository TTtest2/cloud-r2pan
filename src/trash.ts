/**
 * 回收站 —— 软删除 / 恢复 / 彻底清除
 *
 * 为什么要软删除：以前删除是"删库 + 删对象"一步到位，误删一个文件就连带把它
 * 的分享、直链、下载记录全清了，没有任何回旋。现在删除只打 deleted_at 标记，
 * 分享与直链行原地保留（恢复后链接继续能用），到期才真删。
 *
 * ⚠️ 三条硬约束：
 *   1. 软删除期间 R2 对象还在，**照样占存储配额**（免费档 10 GB），所以回收站
 *      必须显示占用体积，且保留期有上限（settings 侧已夹到 ≤90 天）。
 *   2. 所有面向外部的读路径（分享页、直链、市场、WebDAV、后台列表）都必须带
 *      deleted_at IS NULL —— 漏一处就等于"删掉的还在被下载"。
 *   3. 彻底清除要按 key 的**剩余引用数**决定能不能删对象：内容去重后多个 files
 *      行可以共用一个 key，少算一次引用就会把别人还在用的字节删掉。
 */

import type { Env } from "./types";
import type { Settings } from "./settings";
import { getStorageProvider } from "./storage";
import { refsPerKey } from "./dedupe";

/** 未删除文件的过滤条件（读路径统一用它，别各自手写） */
export const LIVE_FILES = "deleted_at IS NULL";

/** 删除结果：进了回收站多少条、彻底删了多少条、要删哪些存储对象 */
export interface RemoveResult {
  soft: number;
  purged: number;
  keys: string[];
}

const DAY_MS = 86_400_000;

/**
 * 单条查询最多带多少个 id。
 * D1 的上限是每条查询 100 个绑定参数，而软删除那条 UPDATE 还要多绑一个时间戳，
 * 所以这里留一半余量 —— 超过就分批，绝不把用户勾选的整批 id 直接塞进 IN (...)。
 */
const MAX_BINDS = 50;

function chunks<T>(arr: T[], size = MAX_BINDS): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/** 把 id 列表变成安全的位置占位符（D1 只认 ? / ?N，不认具名参数） */
function placeholders(ids: (string | number)[]): string {
  return ids.map((_, i) => `?${i + 1}`).join(", ");
}

/** 查出这些 id 里确实存在、且状态匹配 scope 的行（按 MAX_BINDS 分批） */
async function rowsForDelete(env: Env, ids: string[], scope: "live" | "trash" | "any") {
  const extra = scope === "live" ? " AND deleted_at IS NULL" : scope === "trash" ? " AND deleted_at IS NOT NULL" : "";
  const out: { id: string; key: string; folder_id: string | null }[] = [];
  for (const part of chunks(ids)) {
    const { results } = await env.db
      .prepare(`SELECT id, key, folder_id FROM files WHERE id IN (${placeholders(part)})${extra}`)
      .bind(...part)
      .all<{ id: string; key: string; folder_id: string | null }>();
    out.push(...(results ?? []));
  }
  return out;
}

/**
 * 彻底删除：连带分享、直链、下载记录一起去掉，并返回待删的对象 key。
 * 对象删除交给调用方 waitUntil —— 存储往返慢，不能拖住 API 响应。
 */
export async function purgeFiles(env: Env, ids: string[]): Promise<RemoveResult> {
  const found = await rowsForDelete(env, ids, "any");
  if (!found.length) return { soft: 0, purged: 0, keys: [] };
  const foundIds = found.map((f) => f.id);
  // 去重后同一个 key 可能被多行引用 —— 只有最后一份引用消失时才能删对象
  const total = new Map<string, number>();
  for (const part of chunks(found.map((f) => f.key))) {
    for (const [k, n] of await refsPerKey(env, part)) total.set(k, n);
  }
  const mine = new Map<string, number>();
  for (const f of found) mine.set(f.key, (mine.get(f.key) ?? 0) + 1);
  const keys = [...mine.keys()].filter((k) => (total.get(k) ?? 0) - (mine.get(k) ?? 0) <= 0);
  for (const part of chunks(foundIds)) {
    const ph = placeholders(part);
    await env.db.batch([
      env.db.prepare(`DELETE FROM shares WHERE file_id IN (${ph})`).bind(...part),
      env.db.prepare(`DELETE FROM direct_links WHERE file_id IN (${ph})`).bind(...part),
      env.db.prepare(`DELETE FROM download_logs WHERE file_id IN (${ph})`).bind(...part),
      env.db.prepare(`DELETE FROM files WHERE id IN (${ph})`).bind(...part),
    ]);
  }
  return { soft: 0, purged: foundIds.length, keys };
}

/**
 * 删除入口：保留期 > 0 时打标记进回收站，否则等价于彻底删除。
 * keys 只在"真的要从存储里拿掉对象"时非空 —— 软删除不能删对象。
 */
export async function removeFiles(
  env: Env,
  ids: string[],
  retentionDays: number,
  now = Date.now()
): Promise<RemoveResult> {
  if (retentionDays <= 0) {
    const r = await purgeFiles(env, ids);
    return { soft: 0, purged: r.purged, keys: r.keys };
  }
  const live = await rowsForDelete(env, ids, "live");
  if (!live.length) return { soft: 0, purged: 0, keys: [] };
  const foundIds = live.map((f) => f.id);
  for (const part of chunks(foundIds)) {
    // 时间戳占 ?1，所以 id 的占位符必须从 ?2 开始编号
    const ph = part.map((_, i) => `?${i + 2}`).join(", ");
    await env.db
      .prepare(`UPDATE files SET deleted_at = ?1 WHERE id IN (${ph}) AND deleted_at IS NULL`)
      .bind(now, ...part)
      .run();
  }
  return { soft: foundIds.length, purged: 0, keys: [] };
}

/** 恢复：清标记；原目录已经不存在时退回根目录（否则会冒出指向空目录的幽灵文件） */
export async function restoreFiles(env: Env, ids: string[]): Promise<{ restored: number; toRoot: number }> {
  const found = await rowsForDelete(env, ids, "trash");
  if (!found.length) return { restored: 0, toRoot: 0 };
  const foundIds = found.map((f) => f.id);
  const wanted = [...new Set(found.map((f) => f.folder_id).filter((x): x is string => !!x))];
  const existing = new Set<string>();
  for (const part of chunks(wanted)) {
    const { results } = await env.db
      .prepare(`SELECT id FROM folders WHERE id IN (${placeholders(part)})`)
      .bind(...part)
      .all<{ id: string }>();
    for (const r of results ?? []) existing.add(r.id);
  }
  const orphaned = found.filter((f) => f.folder_id && !existing.has(f.folder_id)).map((f) => f.id);

  for (const part of chunks(foundIds)) {
    await env.db.prepare(`UPDATE files SET deleted_at = NULL WHERE id IN (${placeholders(part)})`).bind(...part).run();
  }
  for (const part of chunks(orphaned)) {
    await env.db.prepare(`UPDATE files SET folder_id = NULL WHERE id IN (${placeholders(part)})`).bind(...part).run();
  }
  return { restored: foundIds.length, toRoot: orphaned.length };
}

/** 到期该彻底清除的回收站行（cron 用；LIMIT 控住单次 CPU 与子请求） */
export async function expiredTrashIds(env: Env, settings: Settings, now: number, limit: number): Promise<string[]> {
  if (settings.trashRetentionDays <= 0) return [];
  const cutoff = now - settings.trashRetentionDays * DAY_MS;
  const { results } = await env.db
    .prepare(`SELECT id FROM files WHERE deleted_at IS NOT NULL AND deleted_at < ?1 ORDER BY deleted_at LIMIT ?2`)
    .bind(cutoff, limit)
    .all<{ id: string }>();
  return (results ?? []).map((r) => r.id);
}

/** 删除存储对象（顺序删，失败静默 —— 由 cron 的孤儿对象报告兜底） */
export async function deleteObjects(env: Env, keys: string[]): Promise<void> {
  if (!keys.length) return;
  const st = await getStorageProvider(env);
  for (const key of keys) {
    try {
      await st.delete(key);
    } catch {
      /* 单个对象删不掉不该影响已完成的 DB 变更 */
    }
  }
}
