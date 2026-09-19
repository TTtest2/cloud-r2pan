/**
 * 内联预览（?inline=1）—— 判断某个文件能否、以及如何以 inline 方式吐给浏览器
 *
 * 为什么要有白名单：这个 Worker 和分享页同源，任何被浏览器当成文档来解析的
 * 用户上传内容都是 XSS 面。所以只放行"浏览器只会把它当资源、不会执行"的类型，
 * 而且显式排除 text/html、image/svg+xml 这类可执行/可脚本载荷。
 */

/** MIME → 允许的预览类别（决定 CSP 里要不要开 media-src） */
const INLINE_ALLOWED_EXACT = new Set([
  "application/pdf",
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/avif",
  "image/bmp",
  "image/apng",
  "text/plain",
  "text/csv",
  "text/markdown",
  "image/tiff",
]);

/** 前缀匹配：audio/* 与常见视频容器 */
const INLINE_ALLOWED_PREFIXES = ["audio/", "video/mp4", "video/webm", "video/ogg", "video/quicktime"];

/** 显式黑名单优先于一切 —— SVG 能内嵌脚本，HTML/XHTML 自不必说 */
const ALWAYS_ATTACHMENT = [
  "text/html",
  "application/xhtml+xml",
  "image/svg+xml",
  "text/xml",
  "application/xml",
  "application/xhtml+xml",
  "text/javascript",
  "application/javascript",
  "application/ecmascript",
];

/** 规范化 MIME：丢掉 ;charset=... 之类参数并小写 */
function baseMime(mime: string | null | undefined): string {
  return (mime ?? "").split(";")[0].trim().toLowerCase();
}

/** 这个 MIME 能不能内联展示 */
export function canInline(mime: string | null | undefined): boolean {
  const m = baseMime(mime);
  if (!m || m === "application/octet-stream") return false;
  if (ALWAYS_ATTACHMENT.includes(m)) return false;
  if (INLINE_ALLOWED_EXACT.has(m)) return true;
  return INLINE_ALLOWED_PREFIXES.some((p) => m.startsWith(p));
}

/** 请求是否要求内联展示（?inline=1 / ?disposition=inline） */
export function wantsInline(req: Request): boolean {
  const sp = new URL(req.url).searchParams;
  return sp.get("inline") === "1" || sp.get("disposition") === "inline";
}

function rfc5987(name: string): string {
  return `filename*=UTF-8''${encodeURIComponent(name)}`;
}

/**
 * 决定 content-disposition 及配套响应头。
 * 返回 inline=true 时调用方必须同时用 inlineHeaders() 的 CSP —— 默认下载 CSP
 * 是 default-src 'none'，媒体/PDF 的分片续读会被自己挡掉。
 */
export function applyDisposition(
  headers: Headers,
  opts: { mime: string | null | undefined; name: string; inline: boolean }
): { inline: boolean } {
  const inline = opts.inline && canInline(opts.mime);
  headers.set(
    "content-disposition",
    `${inline ? "inline" : "attachment"}; ${rfc5987(opts.name)}`
  );
  return { inline };
}

/** 内联响应专用 CSP：只允许该资源自身及其同源分片请求，脚本一律禁止 */
export function inlineCsp(): string {
  return [
    "default-src 'none'",
    "img-src 'self' data:",
    "media-src 'self'",
    "style-src 'unsafe-inline'",
    "font-src 'self'",
    "frame-ancestors 'self'",
  ].join("; ");
}
