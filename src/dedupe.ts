/**
 * 内容去重与秒传
 *
 * 同一个文件传两次以前会占两份存储。这里用两条互补的指纹：
 *
 *   sha256 —— 浏览器算好随上传带来。这是唯一能做到"一个字节都不传"的依据：
 *            /upload/check 命中就直接 /upload/claim，只多一行元数据。
 *            只有管理员上传通道会带这个头，所以"客户端报的哈希"在这里可信
 *            （这不是公开接口；WebDAV 与 S3 直连不会带，那些行 sha256 为 NULL）。
 *
 *   etag   —— 存储后端写完对象后的回执（单次上传是内容 MD5，分片上传是 "…-N"）。
 *            服务端零成本得到，所以任何通道写完对象后都能顺手去重：
 *            发现已有同指纹同体积的对象，就把刚写的那份删掉、行改指已有的 key。
 *
 * ⚠️ 去重之后**同一个 key 会被多行引用**，"能不能删对象"只能看剩余引用行数
 * （trash.ts 的 purgeFiles 负责数）。数错一次就会删掉别人还在用的字节。
 */

import type { Env } from "./types";
import type { Settings } from "./settings";
import { formatMb } from "./limits";

export interface DupHit {
  id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  sha256: string | null;
  etag: string | null;
}

/** 规范化客户端带来的 sha256（只接受 64 位十六进制，别信其它形状） */
export function normalizeSha(raw: string | null | undefined): string | null {
  const s = (raw ?? "").trim().toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : null;
}

/** 指纹必须带方案前缀 —— 不同方案的字符串绝不能互相命中 */
export function shaFp(hex: string): string {
  return "sha256:" + hex;
}
export function etagFp(etag: string): string {
  return "etag:" + etag.replace(/"/g, "");
}

/** 按 sha256 + 体积找已有的活文件（体积一起比，避免哈希被伪造时错位引用） */
export async function findBySha(env: Env, sha: string, size: number | null): Promise<DupHit | null> {
  const sql = size
    ? `SELECT id, key, name, size, mime, sha256, etag FROM files
       WHERE sha256 = ?1 AND size = ?2 AND deleted_at IS NULL ORDER BY uploaded_at LIMIT 1`
    : `SELECT id, key, name, size, mime, sha256, etag FROM files
       WHERE sha256 = ?1 AND deleted_at IS NULL ORDER BY uploaded_at LIMIT 1`;
  const stmt = size ? env.db.prepare(sql).bind(sha, size) : env.db.prepare(sql).bind(sha);
  return (await stmt.first<DupHit>()) ?? null;
}

/**
 * 写完成后的去重：已有同 etag 同体积的对象时，把刚写的那份删掉并改指已有 key。
 * 返回这一行最终该用的 key。
 */
export async function dedupeAfterWrite(
  env: Env,
  mine: { id: string; key: string; size: number },
  etag: string | null,
  onDeleteObject?: (key: string) => void
): Promise<{ key: string; deduped: boolean }> {
  if (!etag) return { key: mine.key, deduped: false };
  const hit = await env.db
    .prepare(
      `SELECT id, key, name, size, mime, sha256, etag FROM files
       WHERE etag = ?1 AND size = ?2 AND id != ?3 AND deleted_at IS NULL
       ORDER BY uploaded_at LIMIT 1`
    )
    .bind(etag, mine.size, mine.id)
    .first<DupHit>();
  if (!hit || hit.key === mine.key) return { key: mine.key, deduped: false };
  // 刚写的这份是多余的
  onDeleteObject?.(mine.key);
  await env.db.prepare("UPDATE files SET key = ?1 WHERE id = ?2").bind(hit.key, mine.id).run();
  return { key: hit.key, deduped: true };
}

export type ClaimResult =
  | { ok: true; id: string; name: string; size: number; key: string }
  | { ok: false; status: number; code: string; limitMb?: number };

/**
 * 秒传：不传字节，只新增一行指向已有对象。
 * 单文件上限照样要判（复用的对象本身可能超过现在的新上限），
 * 但**不占新的存储**，所以不判配额。
 */
export async function claimBySha(
  env: Env,
  settings: Settings,
  sha: string,
  name: string,
  folderId: string | null,
  randomId: (n: number) => string
): Promise<ClaimResult> {
  const hit = await findBySha(env, sha, null);
  if (!hit) return { ok: false, status: 404, code: "not_found" };
  if (settings.maxUploadBytes > 0 && hit.size > settings.maxUploadBytes) {
    return { ok: false, status: 413, code: "too_large", limitMb: formatMb(settings.maxUploadBytes) };
  }
  const id = randomId(14);
  await env.db
    .prepare(
      `INSERT INTO files(id, key, name, size, mime, uploaded_at, folder_id, sha256, etag)
       VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`
    )
    .bind(id, hit.key, name, hit.size, hit.mime, Date.now(), folderId, hit.sha256, hit.etag)
    .run();
  return { ok: true, id, name, size: hit.size, key: hit.key };
}

/** 某个 key 还剩多少行引用（含回收站 —— 对象是否还需要由"有没有人引用"决定） */
export async function refsPerKey(env: Env, keys: string[]): Promise<Map<string, number>> {
  const out = new Map<string, number>();
  const uniq = [...new Set(keys)];
  for (let i = 0; i < uniq.length; i += 50) {
    const part = uniq.slice(i, i + 50);
    const ph = part.map((_, j) => `?${j + 1}`).join(", ");
    const { results } = await env.db
      .prepare(`SELECT key, COUNT(*) AS c FROM files WHERE key IN (${ph}) GROUP BY key`)
      .bind(...part)
      .all<{ key: string; c: number }>();
    for (const r of results ?? []) out.set(r.key, Number(r.c) || 0);
  }
  return out;
}
