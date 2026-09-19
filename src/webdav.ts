/**
 * WebDAV 协议实现 —— 挂载点 /webdav/*
 *
 * 支持的方法：
 *   OPTIONS   —— 探测 DAV 能力
 *   PROPFIND  —— 列出目录 / 文件属性（Depth: 0/1/infinity）
 *   GET       —— 下载文件
 *   HEAD      —— 仅返回文件元数据
 *   PUT       —— 上传/覆盖文件
 *   DELETE    —— 删除文件或空目录（非空目录递归删除）
 *   MKCOL     —— 创建目录
 *   MOVE      —— 移动 / 重命名 文件或目录
 *   COPY      —— 复制文件（目录复制未实现，返回 501）
 *
 * 认证：HTTP Basic Auth，凭据在管理后台"设置 → WebDAV 挂载"里配置。
 *   口令以 PBKDF2-SHA256 存储；每个 IP 每分钟允许 8 次失败，超限后直接拒绝
 *   而不再做口令派生（省 CPU）；验证通过的凭据在本 isolate 缓存 60 秒，
 *   避免挂载后的每个请求都重跑一遍拉伸。
 * 存储：对象走 StorageProvider（R2 / S3），元数据走 D1 —— 文件行存 files（folder_id 指向目录），
 *      目录是 folders 的 parent_id 树；URL 里的路径由 src/folders.ts 现场解析，不是存储事实。
 */

import type { Env } from "./types";
import { getSettings, updateSettings } from "./settings";
import { sha256Hex, hashWebDAVPassword, verifyWebDAVPassword } from "./crypto";
import { clientIp, authThrottled, noteAuthFailure, clearAuthFailures } from "./auth";
import {
  declaredSize,
  formatMb,
  postUploadRejection,
  preUploadRejection,
  usedStorageBytes,
} from "./limits";
import { purgeFiles, removeFiles } from "./trash";
import { getStorageProvider as storage } from "./storage";
import { randomId } from "./db";
import {
  getFolderTree,
  resolveFolderPath,
  createFolder,
  relocateFolder,
  deleteFoldersStmt,
  invalidateFolderTree,
  joinPath,
  type FolderNode,
  type FolderRef,
} from "./folders";

/* ═══════════ 工具函数 ═══════════ */

/** 路径标准化：确保以 / 开头，不以 / 结尾（根目录除外） */
function normPath(p: string): string {
  p = decodeURIComponent(p);
  p = p.replace(/\\/g, "/").replace(/\/+/g, "/");
  if (!p.startsWith("/")) p = "/" + p;
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

/** 从 WebDAV URL 提取内部路径（去掉 /webdav 前缀） */
function extractInternalPath(urlPath: string): string {
  // /webdav         → /
  // /webdav/        → /
  // /webdav/foo.txt → /foo.txt
  // /webdav/dir/a.txt → /dir/a.txt
  const stripped = urlPath.replace(/^\/webdav/, "");
  return normPath(stripped || "/");
}

/** 从完整 URL 构建 WebDAV href（集合才带结尾斜杠，客户端会直接拿 href 去请求） */
function buildHref(baseUrl: string, internalPath: string, isCollection: boolean): string {
  const u = new URL(baseUrl);
  const encoded = internalPath
    .split("/")
    .filter(Boolean)
    .map(encodeURIComponent)
    .join("/");
  return `${u.origin}/webdav/${encoded}${encoded && isCollection ? "/" : ""}`;
}

/** RFC 1123 日期格式 */
function rfc1123(date: Date): string {
  return date.toUTCString().replace(/GMT$/, "GMT");
}

/** 将毫秒时间戳转 RFC 1123 */
function tsToRfc1123(ts: number): string {
  return rfc1123(new Date(ts));
}

/* ═══════════ Basic Auth 认证 ═══════════ */

/** 解析 Basic Auth 头 → {username, password} 或 null */
function parseBasicAuth(authHeader: string | null): { username: string; password: string } | null {
  if (!authHeader || !authHeader.startsWith("Basic ")) return null;
  try {
    const decoded = atob(authHeader.slice(6));
    const i = decoded.indexOf(":");
    if (i < 0) return null;
    return { username: decoded.slice(0, i), password: decoded.slice(i + 1) };
  } catch {
    return null;
  }
}

/** 验证 WebDAV Basic Auth */
const WEBDAV_FAIL_LIMIT = 8;          // 每个 IP 每分钟允许的失败次数
const CRED_CACHE_TTL_MS = 60_000;
/** 凭据 → 过期时间戳。口令派生是 PBKDF2 五万轮，而挂载后每个请求都要认证。 */
const credCache = new Map<string, number>();

async function checkWebDAVAuth(req: Request, env: Env): Promise<boolean> {
  const settings = await getSettings(env);
  if (!settings.webdavEnabled) return false;
  const stored = settings.webdavPasswordHash;
  if (!stored) return false;

  const auth = parseBasicAuth(req.headers.get("authorization"));
  // 没带凭据是正常挑战流程，不能计成失败
  if (!auth) return false;

  // 键里带上存储哈希的尾部指纹：管理员换口令后指纹变化，旧缓存自动失效
  const cacheKey = (await sha256Hex(auth.username + ":" + auth.password)) + "|" + stored.slice(-16);
  const cachedUntil = credCache.get(cacheKey);
  if (cachedUntil && cachedUntil > Date.now()) return true; // 已验证过，不必再派生

  const ip = clientIp(req);
  if (authThrottled(ip, "webdav", WEBDAV_FAIL_LIMIT)) return false; // 超限后连派生都不做

  if (auth.username !== settings.webdavUsername) {
    noteAuthFailure(ip, "webdav");
    return false;
  }

  const { ok, needUpgrade } = await verifyWebDAVPassword(stored, auth.password);
  if (!ok) {
    noteAuthFailure(ip, "webdav");
    return false;
  }
  clearAuthFailures(ip, "webdav");
  credCache.set(cacheKey, Date.now() + CRED_CACHE_TTL_MS);

  // 老格式（单轮 sha256，可离线爆破）或迭代数偏低时，顺手就地升级
  if (needUpgrade) {
    const upgraded = await hashWebDAVPassword(auth.password);
    await updateSettings(env, { webdav_password_hash: upgraded }).catch(() => {});
  }
  return true;
}

/* ═══════════ 目录模型（folders + files.folder_id） ═══════════ */

interface DBFile {
  id: string;
  key: string;
  name: string;
  size: number;
  mime: string;
  folder_id: string | null;
  uploaded_at: number;
}

const FILE_COLUMNS = "id, key, name, size, mime, folder_id, uploaded_at";

/** 一个 WebDAV 路径的解析结果。root 与 missing 必须区分，否则写错路径就能列出整站 */
type Loc =
  | { kind: "root" }
  | { kind: "dir"; node: FolderNode }
  | { kind: "file"; file: DBFile; parentId: FolderRef; path: string }
  | { kind: "missing" };

/** 拆成"父路径 + 名称"，父路径永远是 /xxx 形式（根是 "/"） */
function splitPath(path: string): { parentPath: string; name: string } {
  const last = path.lastIndexOf("/");
  return {
    parentPath: last <= 0 ? "/" : path.slice(0, last),
    name: path.slice(last + 1),
  };
}

/** 同一目录下的同名文件（partial unique index 管目录，文件靠这个查询判重） */
async function findFileByName(env: Env, parentId: FolderRef, name: string): Promise<DBFile | null> {
  const stmt = parentId === null
    ? env.db.prepare(`SELECT ${FILE_COLUMNS} FROM files WHERE deleted_at IS NULL AND folder_id IS NULL AND name = ?1`).bind(name)
    : env.db.prepare(`SELECT ${FILE_COLUMNS} FROM files WHERE deleted_at IS NULL AND folder_id = ?1 AND name = ?2`).bind(parentId, name);
  return await stmt.first<DBFile>();
}

async function locate(env: Env, path: string): Promise<Loc> {
  const tree = await getFolderTree(env);
  const dirId = tree.resolve(path);
  if (dirId === null) return { kind: "root" };
  const dirNode = dirId === undefined ? undefined : tree.get(dirId);
  if (dirNode) return { kind: "dir", node: dirNode }; // 目录优先：同名文件行属于脏数据

  const { parentPath, name } = splitPath(path);
  if (!name) return { kind: "missing" };
  const parentId = tree.resolve(parentPath);
  if (parentId === undefined) return { kind: "missing" };
  const file = await findFileByName(env, parentId, name);
  return file ? { kind: "file", file, parentId, path } : { kind: "missing" };
}

/** 取若干目录（含根）里的文件；一次查询，避免 Depth: infinity 时按目录往返 */
async function filesInFolders(env: Env, ids: FolderRef[]): Promise<DBFile[]> {
  if (!ids.length) return [];
  const conds: string[] = [];
  const binds: unknown[] = [];
  for (const id of ids) {
    if (id === null) conds.push("folder_id IS NULL");
    else {
      binds.push(id);
      conds.push(`folder_id = ?${binds.length}`);
    }
  }
  const { results } = await env.db
    .prepare(`SELECT ${FILE_COLUMNS} FROM files WHERE deleted_at IS NULL AND (${conds.join(" OR ")}) ORDER BY name`)
    .bind(...binds)
    .all<DBFile>();
  return results ?? [];
}

/* ═══════════ PROPFIND XML 生成 ═══════════ */

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** 为单个文件生成 propstat XML（resourcetype 必须为空，否则客户端会当成目录） */
function filePropstat(file: DBFile, href: string): string {
  const displayName = escapeXml(file.name);
  const mime = escapeXml(file.mime || "application/octet-stream");
  const lastModified = tsToRfc1123(file.uploaded_at);
  const creationDate = new Date(file.uploaded_at).toISOString();
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype/>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontentlength>${file.size}</getcontentlength>
        <getcontenttype>${mime}</getcontenttype>
        <getetag>"${file.id}"</getetag>
        <getlastmodified>${lastModified}</getlastmodified>
        <creationdate>${creationDate}</creationdate>
        <displayname>${displayName}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 目录自身的 propstat（根目录没有对应行，创建时间缺省为当前） */
function dirPropstat(path: string, baseUrl: string, createdAt?: number): string {
  const href = buildHref(baseUrl, path, true);
  const displayName = path === "/" ? "/" : path.split("/").filter(Boolean).pop() || "";
  const stamp = createdAt ?? Date.now();
  return `
  <response>
    <href>${escapeXml(href)}</href>
    <propstat>
      <prop>
        <resourcetype><collection/></resourcetype>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
    <propstat>
      <prop>
        <getcontenttype>httpd/unix-directory</getcontenttype>
        <getlastmodified>${tsToRfc1123(stamp)}</getlastmodified>
        <creationdate>${new Date(stamp).toISOString()}</creationdate>
        <displayname>${escapeXml(displayName)}</displayname>
      </prop>
      <status>HTTP/1.1 200 OK</status>
    </propstat>
  </response>`;
}

/** 生成 multistatus XML 响应 */
function multistatusXML(responses: string[]): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">${responses.join("")}
</D:multistatus>`;
}

/* ═══════════ WebDAV 主入口 ═══════════ */

export async function handleWebDAV(
  req: Request,
  env: Env,
  _ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(req.url);
  const method = req.method.toUpperCase();
  const internalPath = extractInternalPath(url.pathname);

  // 1. OPTIONS —— 不强制认证（让客户端先探测能力）
  if (method === "OPTIONS") {
    return new Response("", {
      status: 200,
      headers: {
        "Allow": "OPTIONS, PROPFIND, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY",
        "DAV": "1, 2, 3",
        "Accept-Ranges": "bytes",
        "Cache-Control": "no-store",
      },
    });
  }

  // 2. 认证
  if (!(await checkWebDAVAuth(req, env))) {
    return new Response("Unauthorized", {
      status: 401,
      headers: {
        "WWW-Authenticate": `Basic realm="cloud-r2pan WebDAV"`,
        "Content-Type": "text/plain",
      },
    });
  }

  // 3. 检查根路径限制（settings.webdav_root_path）
  const settings = await getSettings(env);
  if (settings.webdavRootPath && settings.webdavRootPath !== "/") {
    const root = settings.webdavRootPath.replace(/\/+$/, "") || "/";
    if (!internalPath.startsWith(root)) {
      return new Response("Forbidden", { status: 403 });
    }
  }

  // 4. 分发到各方法处理
  switch (method) {
    case "PROPFIND":
      return handlePropfind(req, env, url, internalPath);
    case "GET":
      return handleWebDavGet(req, env, internalPath, false);
    case "HEAD":
      return handleWebDavGet(req, env, internalPath, true);
    case "PUT":
      return handleWebDavPut(req, env, internalPath);
    case "DELETE":
      return handleWebDavDelete(env, internalPath);
    case "MKCOL":
      return handleWebDavMkcol(env, internalPath);
    case "MOVE":
      return handleWebDavMove(req, env, url, internalPath);
    case "COPY":
      return handleWebDavCopy(req, env, url, internalPath);
    default:
      return new Response("Method Not Allowed", { status: 405 });
  }
}

/* ═══════════ PROPFIND ═══════════ */

async function handlePropfind(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const depth = req.headers.get("depth") || "1"; // 0 / 1 / infinity
  const baseUrl = url.origin;
  const xmlHeaders = { "Content-Type": "application/xml; charset=utf-8" };

  const loc = await locate(env, internalPath);
  if (loc.kind === "missing") return new Response("Not Found", { status: 404 });

  if (loc.kind === "file") {
    const body = multistatusXML([filePropstat(loc.file, buildHref(baseUrl, loc.path, false))]);
    return new Response(body, { status: 207, headers: xmlHeaders });
  }

  const folderId: FolderRef = loc.kind === "root" ? null : loc.node.id;
  const selfCreated = loc.kind === "dir" ? loc.node.created_at : undefined;

  // Depth: 0 —— 只返回目录自身
  if (depth === "0") {
    const body = multistatusXML([dirPropstat(internalPath, baseUrl, selfCreated)]);
    return new Response(body, { status: 207, headers: xmlHeaders });
  }

  const tree = await getFolderTree(env);
  const responses: string[] = [dirPropstat(internalPath, baseUrl, selfCreated)];

  if (depth === "infinity") {
    // 子树 id 全在内存里算，再一次性把涉及目录的文件捞回来
    const ids: FolderRef[] = [];
    if (folderId === null) {
      ids.push(null);
      for (const root of tree.roots()) ids.push(...tree.subtreeIds(root.id));
    } else {
      ids.push(...tree.subtreeIds(folderId));
    }
    const pathByFolder = new Map<FolderRef, string>();
    for (const id of ids) {
      if (id === null) continue;
      const p = id === folderId ? internalPath : tree.pathOf(id);
      if (p) pathByFolder.set(id, p);
    }
    for (const id of ids) {
      if (id === null || id === folderId) continue; // 根与自身已报过
      const p = pathByFolder.get(id);
      if (p) responses.push(dirPropstat(p, baseUrl, tree.get(id)?.created_at));
    }
    for (const f of await filesInFolders(env, ids)) {
      const parentPath = f.folder_id === null ? "/" : pathByFolder.get(f.folder_id) ?? internalPath;
      responses.push(filePropstat(f, buildHref(baseUrl, joinPath(parentPath, f.name), false)));
    }
  } else {
    // Depth: 1 —— 直接子目录（内存树）+ 直接子文件（一条按 folder_id 的精确查询）
    for (const d of tree.childrenOf(folderId)) {
      responses.push(dirPropstat(joinPath(internalPath, d.name), baseUrl, d.created_at));
    }
    for (const f of await filesInFolders(env, [folderId])) {
      responses.push(filePropstat(f, buildHref(baseUrl, joinPath(internalPath, f.name), false)));
    }
  }

  return new Response(multistatusXML(responses), { status: 207, headers: xmlHeaders });
}

/* ═══════════ GET / HEAD ═══════════ */

async function handleWebDavGet(
  req: Request,
  env: Env,
  internalPath: string,
  headOnly: boolean
): Promise<Response> {
  const loc = await locate(env, internalPath);
  if (loc.kind === "missing") return new Response("Not Found", { status: 404 });
  if (loc.kind !== "file") return new Response("Not a file", { status: 409 });
  const file = loc.file;

  const st = await storage(env);
  const obj = await st.head(file.key);
  if (!obj) {
    return new Response("Not Found", { status: 404 });
  }

  const headers = new Headers();
  headers.set("Content-Type", obj.contentType);
  headers.set("Content-Length", String(obj.size));
  headers.set("ETag", `"${file.id}"`);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Last-Modified", tsToRfc1123(file.uploaded_at));
  headers.set("Cache-Control", "no-store");

  if (headOnly) {
    return new Response("", { status: 200, headers });
  }

  // 支持 Range 请求
  const rangeHeader = req.headers.get("range");
  if (rangeHeader) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader.trim());
    if (m) {
      let offset = m[1] === "" ? null : Number(m[1]);
      let end = m[2] === "" ? null : Number(m[2]);
      if (offset === null && end !== null) {
        // 后缀范围 bytes=-N
        offset = obj.size - end;
        end = obj.size - 1;
      } else if (offset !== null) {
        if (end === null) end = obj.size - 1;
        if (end >= obj.size) end = obj.size - 1;
        if (offset > end) {
          return new Response("Range Not Satisfiable", { status: 416, headers: { "Content-Range": `bytes */${obj.size}` } });
        }
      }
      if (offset !== null && end !== null) {
        const len = end - offset + 1;
        headers.set("Content-Range", `bytes ${offset}-${end}/${obj.size}`);
        headers.set("Content-Length", String(len));
        const ranged = await st.get(file.key, { offset, length: len });
        if (!ranged) return new Response("Not Found", { status: 404 });
        return new Response(ranged.body, { status: 206, headers });
      }
    }
  }

  const fullObj = await st.get(file.key);
  if (!fullObj) return new Response("Not Found", { status: 404 });
  return new Response(fullObj.body, { status: 200, headers });
}

/* ═══════════ PUT ═══════════ */

async function handleWebDavPut(
  req: Request,
  env: Env,
  internalPath: string
): Promise<Response> {
  const { parentPath, name } = splitPath(internalPath);
  if (!name) {
    return new Response("No file name", { status: 400 });
  }

  // 父目录必须存在（WebDAV 不自动创建中间目录）
  const parentId = await resolveFolderPath(env, parentPath);
  if (parentId === undefined) {
    return new Response("Conflict: parent directory does not exist", { status: 409 });
  }

  // 目标已存在：集合不能被文件覆盖；同名文件则是覆盖上传
  const target = await locate(env, internalPath);
  if (target.kind === "dir" || target.kind === "root") {
    return new Response("Method Not Allowed: collection exists here", { status: 405 });
  }
  const existing = target.kind === "file" ? target.file : null;

  const mime = req.headers.get("content-type") || "application/octet-stream";
  const st = await storage(env);

  const limits = await getSettings(env);
  const declared = declaredSize(req);
  const usedBytes = limits.storageQuotaBytes > 0 ? await usedStorageBytes(env) : 0;
  const rejected = preUploadRejection(limits, usedBytes, declared);
  if (rejected) {
    return new Response(rejected.code === "too_large"
      ? `Payload Too Large: per-file limit is ${formatMb(rejected.limitBytes)} MB`
      : `Insufficient Storage: quota is ${formatMb(rejected.limitBytes)} MB`, { status: rejected.status });
  }

  // 生成文件记录
  const id = randomId(14);
  const key = `files/${id}`;
  const now = Date.now();

  let size = 0;
  // req.body 必须原样交给存储层：R2 只接受长度已知的流，pipeThrough 包装会被直接拒绝
  try {
    const res = await st.put(key, req.body as any, {
      contentType: mime,
      contentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
      contentLength: declared ?? undefined,
    });
    size = res.size;
  } catch (err: any) {
    await st.delete(key).catch(() => {});
    return new Response(`Storage error: ${err?.message || err}`, { status: 502 });
  }

  const over = postUploadRejection(limits, usedBytes, size);
  if (over) {
    await st.delete(key).catch(() => {});
    return new Response(over.code === "too_large"
      ? `Payload Too Large: per-file limit is ${formatMb(over.limitBytes)} MB`
      : `Insufficient Storage: quota is ${formatMb(over.limitBytes)} MB`, { status: over.status });
  }

  try {
    await env.db.prepare(
      "INSERT INTO files(id, key, name, size, mime, uploaded_at, folder_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(id, key, name, size, mime, now, parentId).run();
  } catch (err: any) {
    // D1 失败 —— 清理 storage
    await st.delete(key).catch(() => {});
    return new Response(`DB error: ${err?.message || err}`, { status: 502 });
  }
  // 覆盖上传：新行写成功了才退掉旧行。走 purgeFiles 而不是直接删对象 ——
  // 内容去重之后同一个 key 可能还被别的文件引用着，数错一次就是删掉别人的数据。
  if (existing) {
    const purged = await purgeFiles(env, [existing.id]).catch(() => ({ keys: [] as string[] }));
    for (const k of purged.keys) await st.delete(k).catch(() => {});
  }

  return new Response(null, {
    status: existing ? 204 : 201,
    headers: { "ETag": `"${id}"` },
  });
}

/* ═══════════ DELETE ═══════════ */

async function handleWebDavDelete(env: Env, internalPath: string): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Cannot delete root", { status: 403 });
  }

  const loc = await locate(env, internalPath);
  if (loc.kind === "missing") return new Response("Not Found", { status: 404 });

  const st = await storage(env);
  const s = await getSettings(env);
  /** 走回收站：返回真正需要从存储拿掉的 key（软删除时为空） */
  const trash = async (ids: string[]) => {
    const r = await removeFiles(env, ids, s.trashRetentionDays);
    for (const key of r.keys) await st.delete(key).catch(() => {});
    return r;
  };

  if (loc.kind === "file") {
    await trash([loc.file.id]);
    return new Response(null, { status: 204 });
  }

  // 目录：连整棵子树一起删（沿用原有语义 —— 非空目录递归删除）
  if (loc.kind !== "dir") return new Response("Cannot delete root", { status: 403 });
  const tree = await getFolderTree(env);
  const ids = tree.subtreeIds(loc.node.id);
  const files = await filesInFolders(env, ids);
  await trash(files.map((f) => f.id));
  await env.db.batch(deleteFoldersStmt(env, ids));
  invalidateFolderTree();
  return new Response(null, { status: 204 });
}

/* ═══════════ MKCOL ═══════════ */

async function handleWebDavMkcol(env: Env, internalPath: string): Promise<Response> {
  if (internalPath === "/") {
    return new Response("Root exists", { status: 200 });
  }

  const { parentPath, name } = splitPath(internalPath);
  if (!name) return new Response("Bad request", { status: 400 });

  // 父目录必须存在
  const parentId = await resolveFolderPath(env, parentPath);
  if (parentId === undefined) {
    return new Response("Conflict: parent does not exist", { status: 409 });
  }

  const target = await locate(env, internalPath);
  if (target.kind === "file") {
    return new Response("Method Not Allowed: file exists here", { status: 405 });
  }
  // 同名集合已存在 —— 沿用宽松的 201：部分客户端每次挂载都会对已有目录再 MKCOL 一次
  if (target.kind === "dir") {
    return new Response("", { status: 201 });
  }

  if (!(await createFolder(env, parentId, name))) {
    return new Response("Conflict: could not create collection", { status: 409 });
  }
  return new Response("", { status: 201 });
}

/* ═══════════ MOVE ═══════════ */

async function handleWebDavMove(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  // 从 Destination URL 提取目标路径
  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  const src = await locate(env, internalPath);
  if (src.kind === "missing") return new Response("Not Found", { status: 404 });

  const { parentPath: destParentPath, name: destName } = splitPath(destPath);
  if (!destName) return new Response("Bad request", { status: 400 });

  const destParentId = await resolveFolderPath(env, destParentPath);
  if (destParentId === undefined) return new Response("Conflict", { status: 409 });

  if (src.kind === "root") return new Response("Forbidden: cannot move root", { status: 403 });

  if (src.kind === "dir") {
    // 目录不能移进自己的子树，也不能移到自己身上。必须在"删除已存在目标"之前拦下：
    // 否则目标是源的子孙时，会先把要保数据的那一份删掉。
    const srcPath = (await getFolderTree(env)).pathOf(src.node.id) ?? internalPath;
    if (destPath === srcPath || destPath.startsWith(srcPath + "/")) {
      return new Response("Forbidden: cannot move a collection into itself", { status: 403 });
    }
  }

  const dest = await locate(env, destPath);
  const destExists = dest.kind === "file" || dest.kind === "dir";
  if (destExists && !overwrite) {
    return new Response("Precondition Failed: destination exists", { status: 412 });
  }
  if (destExists) {
    const removed = await handleWebDavDelete(env, destPath);
    if (removed.status !== 204) return removed;
  }

  if (src.kind === "file") {
    await env.db
      .prepare("UPDATE files SET folder_id = ?1, name = ?2 WHERE id = ?3")
      .bind(destParentId, destName, src.file.id)
      .run();
  } else {
    const moved = await relocateFolder(env, src.node.id, { parentId: destParentId, name: destName });
    if (!moved.ok) {
      const status = moved.error === "cycle" ? 403 : moved.error === "not_found" ? 404 : 409;
      return new Response(`Conflict: ${moved.error}`, { status });
    }
  }

  return new Response(null, { status: destExists ? 204 : 201 });
}

/* ═══════════ COPY ═══════════ */

async function handleWebDavCopy(
  req: Request,
  env: Env,
  url: URL,
  internalPath: string
): Promise<Response> {
  const destHeader = req.headers.get("destination");
  if (!destHeader) {
    return new Response("Missing Destination header", { status: 400 });
  }

  let destPath: string;
  try {
    const destUrl = new URL(destHeader);
    destPath = extractInternalPath(destUrl.pathname);
  } catch {
    return new Response("Invalid Destination", { status: 400 });
  }

  const overwrite = (req.headers.get("overwrite") || "T").toUpperCase() === "T";

  const src = await locate(env, internalPath);
  if (src.kind === "missing") return new Response("Not Found", { status: 404 });
  if (src.kind !== "file") return new Response("Only file copy supported", { status: 501 });
  const srcFile = src.file;

  const { parentPath: destParentPath, name: destName } = splitPath(destPath);
  if (!destName) return new Response("Bad request", { status: 400 });

  const destParentId = await resolveFolderPath(env, destParentPath);
  if (destParentId === undefined) return new Response("Conflict", { status: 409 });

  const dest = await locate(env, destPath);
  if (dest.kind !== "missing" && !overwrite) {
    return new Response("Precondition Failed", { status: 412 });
  }
  if (dest.kind === "file" || dest.kind === "dir") {
    const removed = await handleWebDavDelete(env, destPath);
    if (removed.status !== 204) return removed;
  }

  const st = await storage(env);
  const srcObj = await st.get(srcFile.key);
  if (!srcObj) return new Response("Source not found", { status: 404 });

  const newId = randomId(14);
  const newKey = `files/${newId}`;

  try {
    await st.put(newKey, srcObj.body, { contentType: srcFile.mime, contentLength: srcObj.size });
  } catch (err: any) {
    return new Response(`Storage error: ${err?.message || err}`, { status: 502 });
  }

  try {
    await env.db.prepare(
      "INSERT INTO files(id, key, name, size, mime, uploaded_at, folder_id) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    ).bind(newId, newKey, destName, srcFile.size, srcFile.mime, Date.now(), destParentId).run();
  } catch (err: any) {
    await st.delete(newKey).catch(() => {});
    return new Response(`DB error: ${err?.message || err}`, { status: 502 });
  }

  return new Response("", { status: 201 });
}
