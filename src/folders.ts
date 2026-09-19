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

/** 目录 id；null = 根目录（不属于任何 folder） */
export type FolderRef = string | null;

interface FolderRow {
  id: string;
  name: string;
  parent_id: string | null;
}

/** 路径段数上限 —— 防御超长路径与环 */
const MAX_DEPTH = 64;

const TREE_TTL_MS = 5_000;

export class FolderTree {
  private byId = new Map<string, FolderRow>();
  /** key = 父目录 id（根用空串）+ NUL 分隔 + 名称（大小写敏感，与 WebDAV 一致） */
  private childByKey = new Map<string, FolderRow>();
  private kidsByParent = new Map<FolderRef, FolderRow[]>();

  constructor(rows: FolderRow[]) {
    for (const r of rows) {
      this.byId.set(r.id, r);
      this.childByKey.set(siblingKey(r.parent_id, r.name), r);
      const list = this.kidsByParent.get(r.parent_id);
      if (list) list.push(r);
      else this.kidsByParent.set(r.parent_id, [r]);
    }
  }

  get(id: string): FolderRow | undefined {
    return this.byId.get(id);
  }

  /** 顶层目录列表 */
  roots(): FolderRow[] {
    return this.kidsByParent.get(null) ?? [];
  }

  childrenOf(parent: FolderRef): FolderRow[] {
    return (parent === null ? this.roots() : this.kidsByParent.get(parent) ?? []).slice();
  }

  child(parent: FolderRef, name: string): FolderRow | undefined {
    return this.childByKey.get(siblingKey(parent, name));
  }

  /**
   * 绝对路径 → 目录 id。"/" 得到 null（根）；任何一段不存在时返回 undefined，
   * 与"指向根"区分开，调用方才能判断 404 而不是当成根目录列全部。
   */
  resolve(path: string): FolderRef | undefined {
    const segments = path.split("/").filter(Boolean);
    if (segments.length > MAX_DEPTH) return undefined;
    let parent: FolderRef = null;
    for (const seg of segments) {
      if (seg === "." || seg === "..") return undefined; // 不接受相对段，避免路径歧义
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
    .prepare("SELECT id, name, parent_id FROM folders")
    .all<FolderRow>();
  _tree = new FolderTree(results ?? []);
  _treeLoadedAt = now;
  return _tree;
}

/** 把 WebDAV 风格的路径拆成段（去空段、拒绝 . 与 ..） */
export function pathSegments(path: string): string[] | null {
  const segments = path.split("/").filter(Boolean);
  if (segments.length > MAX_DEPTH) return null;
  if (segments.some((s) => s === "." || s === ".." || s.length > 255)) return null;
  return segments;
}

/** 父路径 + 名称 → 展示用完整路径（仅用于旧列回填与提示文案，不参与查询） */
export function joinPath(parentPath: string, name: string): string {
  return parentPath === "/" ? "/" + name : parentPath + "/" + name;
}
