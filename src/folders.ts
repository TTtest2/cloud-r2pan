/**
 * 目录树解析 —— 统一目录模型（Phase 2）
 *
 * folders 表是一棵 parent_id 树（parent_id IS NULL = 顶层），files.folder_id 指向目录。
 * 这一层只负责"路径 ↔ 目录 id"的解析：
 *   - 一次 SELECT 全量目录（几十到几百行）在内存里建树，避免每层一次 D1 往返，
 *     也彻底不再对 files 做 LIKE 前缀匹配（那种写法的 off-by-one 与通配符坑我们已经踩过）
 *   - 读缓存带 TTL，任何写操作后主动失效
 *   - 写操作（建/改名/移动/删）在 Phase 3 随 WebDAV 切换一起落地
 */

import type { Env } from "./types";
import { randomId } from "./db";

/** 目录 id；null = 根目录（不属于任何 folder） */
export type FolderRef = string | null;

export interface FolderNode {
  id: string;
  name: string;
  parent_id: string | null;
  created_at: number;
}

/** 路径段数与单段长度上限 —— 防御超长路径 */
const MAX_DEPTH = 64;
const MAX_SEGMENT_LEN = 255;

const TREE_TTL_MS = 5_000;

export class FolderTree {
  private byId = new Map<string, FolderNode>();
  /** key = 父目录 id（根用空串）+ NUL 分隔 + 名称（大小写敏感，与 WebDAV 一致） */
  private childByKey = new Map<string, FolderNode>();
  private kidsByParent = new Map<FolderRef, FolderNode[]>();

  constructor(rows: FolderNode[]) {
    for (const r of rows) {
      this.byId.set(r.id, r);
      this.childByKey.set(siblingKey(r.parent_id, r.name), r);
      const list = this.kidsByParent.get(r.parent_id);
      if (list) list.push(r);
      else this.kidsByParent.set(r.parent_id, [r]);
    }
  }

  get(id: string): FolderNode | undefined {
    return this.byId.get(id);
  }

  /** 顶层目录列表 */
  roots(): FolderNode[] {
    return this.kidsByParent.get(null) ?? [];
  }

  childrenOf(parent: FolderRef): FolderNode[] {
    return (parent === null ? this.roots() : this.kidsByParent.get(parent) ?? []).slice();
  }

  child(parent: FolderRef, name: string): FolderNode | undefined {
    return this.childByKey.get(siblingKey(parent, name));
  }

  /**
   * 绝对路径 → 目录 id。"/" 得到 null（根）；任何一段不存在时返回 undefined，
   * 与"指向根"区分开，调用方才能判断 404 而不是当成根目录列全部。
   */
  resolve(path: string): FolderRef | undefined {
    const segments = pathSegments(path);
    if (!segments) return undefined;
    let parent: FolderRef = null;
    for (const seg of segments) {
      const next = this.child(parent, seg);
      if (!next) return undefined;
      parent = next.id;
    }
    return parent;
  }

  /** 目录 id → 绝对路径；根是 "/"；数据里有环时返回 null 而不是死循环 */
  pathOf(id: FolderRef): string | null {
    if (id === null) return "/";
    const seen = new Set<string>();
    const names: string[] = [];
    let cur = this.byId.get(id);
    while (cur) {
      if (seen.has(cur.id)) return null; // 环
      seen.add(cur.id);
      names.push(cur.name);
      if (cur.parent_id === null) break;
      cur = this.byId.get(cur.parent_id);
    }
    if (!cur || cur.parent_id !== null) return null; // 悬空 id（父链断裂）
    return "/" + names.reverse().join("/");
  }

  /** maybeAncestor 是否在 id 的上游（含自身）—— 拒绝"把目录移进自己的子树" */
  isAncestorOf(maybeAncestor: string, id: FolderRef): boolean {
    let cur = id === null ? undefined : this.byId.get(id);
    while (cur) {
      if (cur.id === maybeAncestor) return true;
      cur = cur.parent_id === null ? undefined : this.byId.get(cur.parent_id);
    }
    return false;
  }

  /** 以 rootId 为根的子树 id（含自身）；脏数据成环时靠 seen 收敛 */
  subtreeIds(rootId: string): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    const stack = [rootId];
    while (stack.length) {
      const id = stack.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push(id);
      for (const kid of this.kidsByParent.get(id) ?? []) stack.push(kid.id);
    }
    return out;
  }
}

function siblingKey(parent: FolderRef, name: string): string {
  return `${parent ?? ""}\u0000${name}`;
}

/* ═══════════ 读取与缓存 ═══════════ */

let _tree: FolderTree | null = null;
let _treeLoadedAt = 0;

export function invalidateFolderTree(): void {
  _tree = null;
  _treeLoadedAt = 0;
}

/** 全量目录建树；默认走 5 秒缓存，写操作后用 fresh 读取立即看到自己的改动 */
export async function getFolderTree(env: Env, opts: { fresh?: boolean } = {}): Promise<FolderTree> {
  const now = Date.now();
  if (!opts.fresh && _tree && now - _treeLoadedAt < TREE_TTL_MS) return _tree;
  const { results } = await env.db
    .prepare("SELECT id, name, parent_id, created_at FROM folders")
    .all<FolderNode>();
  _tree = new FolderTree(results ?? []);
  _treeLoadedAt = now;
  return _tree;
}

/** 绝对路径 → 目录 id（null = 根，undefined = 不存在） */
export async function resolveFolderPath(env: Env, path: string): Promise<FolderRef | undefined> {
  const tree = await getFolderTree(env);
  return tree.resolve(path);
}

/** 把 WebDAV 风格的路径拆成段（去空段、拒绝 . 与 ..） */
export function pathSegments(path: string): string[] | null {
  const segments = path.split("/").filter(Boolean);
  if (segments.length > MAX_DEPTH) return null;
  if (segments.some((s) => s === "." || s === ".." || s.length > MAX_SEGMENT_LEN)) return null;
  return segments;
}

/** 父路径 + 名称 → 展示用完整路径（href 与提示文案用，不参与查询） */
export function joinPath(parentPath: string, name: string): string {
  return parentPath === "/" ? "/" + name : parentPath + "/" + name;
}

/* ═══════════ 写操作 ═══════════ */

/** 新建目录；同层已有同名时返回 null（由 partial unique index 兜底） */
export async function createFolder(env: Env, parentId: FolderRef, name: string): Promise<FolderNode | null> {
  if (!name || name === "." || name === ".." || name.length > MAX_SEGMENT_LEN) return null;
  const node: FolderNode = { id: randomId(14), name, parent_id: parentId, created_at: Date.now() };
  try {
    await env.db
      .prepare("INSERT INTO folders(id, name, parent_id, created_at) VALUES(?1, ?2, ?3, ?4)")
      .bind(node.id, node.name, node.parent_id, node.created_at)
      .run();
  } catch {
    return null; // 同层重名
  }
  invalidateFolderTree();
  return node;
}

export type RelocateResult = { ok: true } | { ok: false; error: "not_found" | "parent_missing" | "exists" | "cycle" };

/** 目录改名和/或换父目录 —— 新模型下只改一行，不需要重写子树 */
export async function relocateFolder(
  env: Env,
  id: string,
  target: { parentId: FolderRef; name?: string }
): Promise<RelocateResult> {
  const tree = await getFolderTree(env, { fresh: true });
  const node = tree.get(id);
  if (!node) return { ok: false, error: "not_found" };
  if (target.parentId !== null && !tree.get(target.parentId)) return { ok: false, error: "parent_missing" };
  if (target.parentId !== null && tree.isAncestorOf(id, target.parentId)) return { ok: false, error: "cycle" };
  const name = target.name ?? node.name;
  if (!name || name === "." || name === ".." || name.length > MAX_SEGMENT_LEN) return { ok: false, error: "exists" };
  if (tree.child(target.parentId, name)) return { ok: false, error: "exists" };

  try {
    await env.db.prepare("UPDATE folders SET name = ?1, parent_id = ?2 WHERE id = ?3").bind(name, target.parentId, id).run();
  } catch {
    return { ok: false, error: "exists" }; // 并发下另一个请求先占了同名
  }
  invalidateFolderTree();
  return { ok: true };
}

/** 删除目录行本身（子文件与子目录由调用方先清完，放在同一个 batch 里） */
export function deleteFoldersStmt(env: Env, ids: string[]) {
  return ids.map((id) => env.db.prepare("DELETE FROM folders WHERE id = ?1").bind(id));
}
