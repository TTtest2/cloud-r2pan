/**
 * 分片上传 —— 让单文件不再卡在"一次请求 100 MB"上
 *
 * Workers 的入站请求体上限是 100 MB（免费档与付费档都是），所以以前后台那句
 * "单文件最大 100 MB"其实是基础设施的天花板，不是产品参数。分片上传把它拆开：
 *
 *   POST /api/admin/upload/init     —— 开会话（拿 upload_id + 建议分片大小）
 *   PUT  /api/admin/upload/part     —— 逐片上传（X-Upload-Id / X-Part-Number 头）
 *   POST /api/admin/upload/complete —— 合并 + 用真实体积复核 + 落库
 *   DELETE /api/admin/upload        —— 客户端取消
 *
 * ⚠️ 三处不能马虎的地方：
 *   1. 分片的流仍然必须是"长度已知"的流 —— 直接把 req.body 交给存储层，
 *      不要包 pipeThrough 计数（会把整条通道打成 "must have a known length" 错误）
 *   2. 客户端报的 size/份数都可以撒谎，所以合并完一定 head() 取真实字节，
 *      超上限或超配额就删对象、不落库（和 limits.ts 同一个原则）
 *   3. 半途而废的会话要继续占着分片存储 —— 必须有 TTL，由 cron 中止回收
 */

import type { Env } from "./types";
import type { Settings } from "./settings";
import type { StoredPart } from "./storage";
import { randomId } from "./db";
import { getStorageProvider } from "./storage";
import { declaredSize, postUploadRejection, preUploadRejection, usedStorageBytes, type UploadRejection } from "./limits";

/** 建议分片大小：≥5 MiB（S3/R2 对非末片的最小值），远小于 100 MB 请求体上限 */
export const CHUNK_SIZE = 8 * 1024 * 1024;
/** 单片允许的上限（留出请求头余量） */
export const CHUNK_MAX = 96 * 1024 * 1024;
/** 最多 10000 片 —— S3/R2 的协议上限，也够 80 GB 一个文件 */
export const MAX_PARTS = 10_000;
/** 会话超过这么久没合并就中止（分片占存储） */
export const UPLOAD_TTL_MS = 24 * 3600_000;

export interface UploadSession {
  id: string;
  key: string;
  upload_id: string;
  name: string;
  mime: string;
  folder_id: string | null;
  size_declared: number | null;
  created_at: number;
}

export type InitResult =
  | { ok: true; session: UploadSession; chunk_size: number }
  | { ok: false; rejection: UploadRejection };

async function loadSession(env: Env, id: string): Promise<UploadSession | null> {
  return (
    (await env.db
      .prepare(
        `SELECT id, key, upload_id, name, mime, folder_id, size_declared, created_at
         FROM upload_sessions WHERE id = ?1`
      )
      .bind(id)
      .first<UploadSession>()) ?? null
  );
}

/** 开会话：能在落盘前判掉的体积现在就判掉 */
export async function initUpload(
  env: Env,
  settings: Settings,
  input: { name: string; mime: string; folder_id: string | null; size: number | null }
): Promise<InitResult> {
  const declared = input.size;
  if (declared !== null && declared > 0 && settings.maxUploadBytes > 0 && declared > settings.maxUploadBytes) {
    return { ok: false, rejection: { status: 413, code: "too_large", limitBytes: settings.maxUploadBytes } };
  }
  const neededParts = declared && declared > 0 ? Math.ceil(declared / CHUNK_SIZE) : 1;
  if (neededParts > MAX_PARTS) {
    // 单文件体积超过协议分片数上限 —— 按上限反推允许的字节数
    const allowed = MAX_PARTS * CHUNK_SIZE;
    return { ok: false, rejection: { status: 413, code: "too_large", limitBytes: Math.min(settings.maxUploadBytes || allowed, allowed) } };
  }
  const usedBytes = settings.storageQuotaBytes > 0 ? await usedStorageBytes(env) : 0;
  const pre = preUploadRejection(settings, usedBytes, declared);
  if (pre) return { ok: false, rejection: pre };

  const id = randomId(14);
  const key = `files/${id}`;
  const st = await getStorageProvider(env);
  const { uploadId } = await st.createMultipart(key, { contentType: input.mime });
  const now = Date.now();
  await env.db
    .prepare(
      `INSERT INTO upload_sessions(id, key, upload_id, name, mime, folder_id, size_declared, created_at)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)`
    )
    .bind(id, key, uploadId, input.name, input.mime, input.folder_id, declared, now)
    .run();
  return {
    ok: true,
    session: { id, key, upload_id: uploadId, name: input.name, mime: input.mime, folder_id: input.folder_id, size_declared: declared, created_at: now },
    chunk_size: CHUNK_SIZE,
  };
}

export type PartResult = { ok: true; etag: string } | { ok: false; status: number; code: string };

/** 上传一片：请求体原样交给存储层，不做任何包装 */
export async function uploadPart(env: Env, sessionId: string, partNumber: number, body: ReadableStream<Uint8Array>): Promise<PartResult> {
  const session = await loadSession(env, sessionId);
  if (!session) return { ok: false, status: 404, code: "upload_not_found" };
  if (Date.now() - session.created_at > UPLOAD_TTL_MS) return { ok: false, status: 410, code: "upload_expired" };
  if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > MAX_PARTS) {
    return { ok: false, status: 400, code: "bad_part_number" };
  }
  const st = await getStorageProvider(env);
  const part = await st.uploadPart(session.key, session.upload_id, partNumber, body);
  return { ok: true, etag: part.etag };
}

export type CompleteResult =
  | { ok: true; id: string; name: string; size: number }
  | { ok: false; status: number; code: string; limitBytes?: number };

/** 合并 → 用真实字节复核上限与配额 → 落库 */
export async function completeUpload(
  env: Env,
  settings: Settings,
  sessionId: string,
  parts: StoredPart[]
): Promise<CompleteResult> {
  const session = await loadSession(env, sessionId);
  if (!session) return { ok: false, status: 404, code: "upload_not_found" };
  if (!Array.isArray(parts) || !parts.length) return { ok: false, status: 400, code: "no_parts" };
  if (parts.length > MAX_PARTS) return { ok: false, status: 400, code: "too_many_parts" };
  const seen = new Set<number>();
  for (const p of parts) {
    const n = Number(p.partNumber);
    if (!Number.isInteger(n) || n < 1 || n > MAX_PARTS) return { ok: false, status: 400, code: "bad_part_number" };
    if (seen.has(n)) return { ok: false, status: 400, code: "duplicate_part" };
    seen.add(n);
    if (typeof p.etag !== "string" || !p.etag || p.etag.length > 256) return { ok: false, status: 400, code: "bad_etag" };
  }

  const st = await getStorageProvider(env);
  await st.completeMultipart(session.key, session.upload_id, parts);

  // 真实体积：客户端报什么都不算数
  const head = await st.head(session.key);
  const size = head?.size ?? 0;
  const usedBytes = await usedStorageBytes(env);
  const rejected = postUploadRejection(settings, usedBytes, size);
  await env.db.prepare("DELETE FROM upload_sessions WHERE id = ?1").bind(sessionId).run();
  if (rejected) {
    await st.delete(session.key).catch(() => {});
    return { ok: false, status: rejected.status, code: rejected.code, limitBytes: rejected.limitBytes };
  }

  await env.db
    .prepare("INSERT INTO files(id, key, name, size, mime, uploaded_at, folder_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)")
    .bind(session.id, session.key, session.name, size, session.mime, Date.now(), session.folder_id)
    .run();
  return { ok: true, id: session.id, name: session.name, size };
}

/** 客户端取消：中止分片并删会话 */
export async function abortUpload(env: Env, sessionId: string): Promise<boolean> {
  const session = await loadSession(env, sessionId);
  if (!session) return false;
  const st = await getStorageProvider(env);
  await st.abortMultipart(session.key, session.upload_id).catch(() => {});
  await env.db.prepare("DELETE FROM upload_sessions WHERE id = ?1").bind(sessionId).run();
  return true;
}

/** 超时未完成的会话（cron 用；分批处理，单次跑不完下一轮接着来） */
export async function staleUploadIds(env: Env, now: number, limit: number): Promise<UploadSession[]> {
  const { results } = await env.db
    .prepare(`SELECT id, key, upload_id, name, mime, folder_id, size_declared, created_at
              FROM upload_sessions WHERE created_at < ?1 ORDER BY created_at LIMIT ?2`)
    .bind(now - UPLOAD_TTL_MS, limit)
    .all<UploadSession>();
  return results ?? [];
}

/** 中止一批超时会话，返回成功条数 */
export async function abortStaleUploads(env: Env, sessions: UploadSession[]): Promise<number> {
  if (!sessions.length) return 0;
  const st = await getStorageProvider(env);
  const ids: string[] = [];
  for (const s of sessions) {
    try {
      await st.abortMultipart(s.key, s.upload_id);
      ids.push(s.id);
    } catch {
      /* 后端已经不认这个 uploadId：照样把会话行清掉，别让它反复被扫 */
      ids.push(s.id);
    }
  }
  const ph = ids.map((_, i) => `?${i + 1}`).join(", ");
  await env.db.prepare(`DELETE FROM upload_sessions WHERE id IN (${ph})`).bind(...ids).run();
  return ids.length;
}

/** 分片请求的体积预检（单片不得超过协议/配置允许的上限） */
export function partTooLarge(req: Request): boolean {
  const declared = declaredSize(req);
  return declared !== null && declared > CHUNK_MAX;
}
