/**
 * 上传体积闸门 —— 单文件上限与总存储配额
 *
 * 前端那句"单文件最大 100 MB"以前只存在于文案里，服务端从来没校验过。
 * 现在两层判定：
 *   1. 落盘前用声明的 Content-Length 挡掉明显的超标请求（省一次写入）
 *   2. 写入完成后用存储层回报的真实 size 复核上限与配额，超标就把对象删掉、
 *      行不落库 —— 声明可以撒谎，真实字节数不能
 *
 * ⚠️ 不要用 pipeThrough 给 req.body 套一层字节计数：R2 只接受"长度已知"的流
 * （请求体本身或 FixedLengthStream），管道出来的是匿名流，会被直接拒绝并报
 * "Provided readable stream must have a known length"，于是所有上传全挂。
 * 传进存储层的必须是 req.body 本尊。
 */

import type { Env } from "./types";
import type { Settings } from "./settings";

export interface UploadRejection {
  status: number;
  code: "too_large" | "quota_exceeded";
  limitBytes: number;
}

/** 请求声明的体积（Content-Length）；缺失或非法返回 null（注意 Number(null) === 0） */
export function declaredSize(req: Request): number | null {
  const raw = req.headers.get("content-length");
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/**
 * 当前已用存储 —— 按对象 key 去重后统计。
 * 去重后同一个 key 会被多行引用，直接 SUM(size) 会把同一份字节算好几遍；
 * 回收站里的行照样占存储，所以不过滤 deleted_at。
 */
export async function usedStorageBytes(env: Env): Promise<number> {
  const row = await env.db
    .prepare("SELECT COALESCE(SUM(s), 0) AS bytes FROM (SELECT MIN(size) AS s FROM files GROUP BY key)")
    .first<{ bytes: number }>();
  return row?.bytes ?? 0;
}

/** 落盘之前能判多少判多少（没声明体积时就放行，交给落盘后的真实 size 复核） */
export function preUploadRejection(settings: Settings, usedBytes: number, declared: number | null): UploadRejection | null {
  if (settings.maxUploadBytes > 0 && declared !== null && declared > settings.maxUploadBytes) {
    return { status: 413, code: "too_large", limitBytes: settings.maxUploadBytes };
  }
  if (settings.storageQuotaBytes > 0 && usedBytes + (declared ?? 0) > settings.storageQuotaBytes) {
    return { status: 507, code: "quota_exceeded", limitBytes: settings.storageQuotaBytes };
  }
  return null;
}

/** 写入完成后用真实体积判上限与配额 —— 声明可以撒谎，落盘后的 size 不会 */
export function postUploadRejection(
  settings: Settings,
  usedBytes: number,
  actualBytes: number
): UploadRejection | null {
  if (settings.maxUploadBytes > 0 && actualBytes > settings.maxUploadBytes) {
    return { status: 413, code: "too_large", limitBytes: settings.maxUploadBytes };
  }
  if (settings.storageQuotaBytes > 0 && usedBytes + actualBytes > settings.storageQuotaBytes) {
    return { status: 507, code: "quota_exceeded", limitBytes: settings.storageQuotaBytes };
  }
  return null;
}

export function formatMb(bytes: number): number {
  return Math.round((bytes / 1024 ** 2) * 10) / 10;
}
