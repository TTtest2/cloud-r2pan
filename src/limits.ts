/**
 * 上传体积闸门 —— 单文件上限与总存储配额
 *
 * 前端一直写着"单文件最大 100 MB"，但那句话只存在于文案里：服务端从来没校验过，
 * 换一个不自量力的客户端（或干脆不带 Content-Length 的分块请求）就能无视它。
 * 这里补齐两道判据：
 *   1. 落盘前用声明体积挡掉明显的（快、省流量）
 *   2. 流式计数挡掉伪造声明的 —— 声明可以撒谎，实际字节数不行
 *   3. 配额用真实写入量事后判定，超了就回滚（删对象、不落库）
 */

import type { Env } from "./types";
import type { Settings } from "./settings";

/** cappedStream 超限抛出的错误标记，调用方靠它区分"体积超限"与"存储故障" */
export const OVER_LIMIT_MESSAGE = "upload_over_limit";

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

/** 当前已用存储（files 表的 size 合计） */
export async function usedStorageBytes(env: Env): Promise<number> {
  const row = await env.db
    .prepare("SELECT COALESCE(SUM(size), 0) AS bytes FROM files")
    .first<{ bytes: number }>();
  return row?.bytes ?? 0;
}

/** 落盘之前能判多少判多少（declared 为 null 时装不下就知道装不下，交给流计数） */
export function preUploadRejection(settings: Settings, usedBytes: number, declared: number | null): UploadRejection | null {
  if (settings.maxUploadBytes > 0 && declared !== null && declared > settings.maxUploadBytes) {
    return { status: 413, code: "too_large", limitBytes: settings.maxUploadBytes };
  }
  if (settings.storageQuotaBytes > 0 && usedBytes + (declared ?? 0) > settings.storageQuotaBytes) {
    return { status: 507, code: "quota_exceeded", limitBytes: settings.storageQuotaBytes };
  }
  return null;
}

/** 写入完成后用真实体积再判一次配额（声明缺失或撒谎时这是唯一准确的判据） */
export function postUploadRejection(settings: Settings, usedBytes: number, actualBytes: number): UploadRejection | null {
  if (settings.storageQuotaBytes > 0 && usedBytes + actualBytes > settings.storageQuotaBytes) {
    return { status: 507, code: "quota_exceeded", limitBytes: settings.storageQuotaBytes };
  }
  return null;
}

/**
 * 给请求体包一层字节计数，超过 maxBytes 就抛 OVER_LIMIT_MESSAGE。
 * 流被下游（R2 / S3）拉走时才会触发，所以不需要先把整个文件读进内存。
 */
export function cappedStream(source: ReadableStream<Uint8Array>, maxBytes: number): ReadableStream<Uint8Array> {
  let seen = 0;
  return source.pipeThrough(
    new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        seen += chunk.byteLength;
        if (seen > maxBytes) throw new Error(OVER_LIMIT_MESSAGE);
        controller.enqueue(chunk);
      },
    })
  );
}

/** 是"体积超限"导致的失败吗 */
export function isOverLimitError(err: unknown): boolean {
  return String((err as any)?.message ?? err).includes(OVER_LIMIT_MESSAGE);
}

export function formatMb(bytes: number): number {
  return Math.round((bytes / 1024 ** 2) * 10) / 10;
}
