/**
 * 旧目录模型迁移测试 —— directories + files.path 搬进 folders 树。
 * 核心断言是"迁移前后每一句话都能在原位置找到"：把旧模型里的全部路径收集起来，
 * 迁移后再用新树反解一遍，两个集合必须完全相等。另测幂等、撞名不覆盖、跨层同名。
 *
 * 运行：
 *   npx esbuild test/folder-migration.ts --bundle --platform=node --format=esm --outfile=.dev/folder-migration.mjs
 *   node .dev/folder-migration.mjs
 */
import { migrateLegacyFolders } from "../src/db";
import { FolderTree, type FolderNode } from "../src/folders";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

interface FileRow { id: string; name: string; size: number; mime: string; path: string; folder_id: string | null }

/** 只实现迁移会用到的那几条 SQL 的迷你库 */
class MiniDb {
  folders: FolderNode[] = [];
  files: FileRow[] = [];
  directories: { path: string }[] = [];
  inserts = 0;

  private match(sql: string, binds: unknown[]): any {
    const norm = sql.replace(/\s+/g, " ").trim();

    if (/^SELECT 1 FROM directories LIMIT 1/.test(norm)) {
      return { first: this.directories.length ? { "1": 1 } : null };
    }
    if (/^SELECT 1 FROM files WHERE folder_id IS NULL AND path IS NOT NULL AND path != '\/' LIMIT 1/.test(norm)) {
      return { first: this.pendingFiles().length ? { "1": 1 } : null };
    }
    if (/^SELECT path FROM directories ORDER BY length\(path\)/.test(norm)) {
      return { all: [...this.directories].sort((a, b) => a.path.length - b.path.length) };
    }
    if (/^SELECT id, name, path FROM files WHERE folder_id IS NULL/.test(norm)) {
      return { all: this.pendingFiles() };
    }
    if (/^SELECT id FROM folders WHERE parent_id IS NULL AND name = \?1/.test(norm)) {
      const hit = this.folders.find((f) => f.parent_id === null && f.name === binds[0]);
      return { first: hit ? { id: hit.id } : null };
    }
    if (/^SELECT id FROM folders WHERE parent_id = \?1 AND name = \?2/.test(norm)) {
      const hit = this.folders.find((f) => f.parent_id === binds[0] && f.name === binds[1]);
      return { first: hit ? { id: hit.id } : null };
    }
    if (/^INSERT INTO folders\(/.test(norm)) {
      const [id, name, parent_id, created_at] = binds as any[];
      if (this.folders.some((f) => f.parent_id === parent_id && f.name === name)) {
        throw new Error("UNIQUE constraint failed");
      }
      this.folders.push({ id, name, parent_id, created_at });
      this.inserts++;
      return { run: { meta: { changes: 1 } } };
    }
    if (/^SELECT 1 FROM files WHERE folder_id IS NULL AND name = \?1 AND id != \?2 LIMIT 1/.test(norm)) {
      const hit = this.files.some((f) => f.folder_id === null && f.name === binds[0] && f.id !== binds[1]);
      return { first: hit ? { "1": 1 } : null };
    }
    if (/^SELECT 1 FROM files WHERE folder_id = \?1 AND name = \?2 AND id != \?3 LIMIT 1/.test(norm)) {
      const hit = this.files.some((f) => f.folder_id === binds[0] && f.name === binds[1] && f.id !== binds[2]);
      return { first: hit ? { "1": 1 } : null };
    }
    if (/^UPDATE files SET path = '\/' WHERE id = \?1/.test(norm)) {
      const f = this.files.find((x) => x.id === binds[0]);
      if (f) f.path = "/";
      return { run: { meta: { changes: f ? 1 : 0 } } };
    }
    if (/^UPDATE files SET folder_id = \?1, name = \?2 WHERE id = \?3/.test(norm)) {
      const f = this.files.find((x) => x.id === binds[2]);
      if (f) {
        f.folder_id = binds[0] as string;
        f.name = binds[1] as string;
      }
      return { run: { meta: { changes: f ? 1 : 0 } } };
    }
    if (/^DELETE FROM directories WHERE path = \?1/.test(norm)) {
      this.directories = this.directories.filter((d) => d.path !== binds[0]);
      return { run: { meta: { changes: 1 } } };
    }
    throw new Error("迷你库未覆盖的 SQL: " + norm);
  }

  private pendingFiles() {
    return this.files.filter((f) => f.folder_id === null && f.path !== "/" && f.path !== "");
  }

  prepare(sql: string) {
    let binds: unknown[] = [];
    const self = this;
    const stmt: any = {
      bind(...vals: unknown[]) {
        binds = vals;
        return stmt;
      },
      async first() {
        return self.match(sql, binds).first ?? null;
      },
      async all() {
        return { results: self.match(sql, binds).all ?? [] };
      },
      async run() {
        return self.match(sql, binds).run ?? { meta: { changes: 0 } };
      },
    };
    return stmt;
  }
}

function seedLegacyDb() {
  const db = new MiniDb();
  db.directories = [{ path: "/docs" }, { path: "/docs/2024" }, { path: "/photos/2024" }, { path: "/empty" }];
  // 注意：/photos/2024 只在文件路径里出现过，directories 表里并没有它 —— 迁移要能补出中间层
  db.files = [
    file("t1", "readme.md", "/readme.md"),
    file("d1", "a.txt", "/docs/a.txt"),
    file("d2", "b.txt", "/docs/2024/b.txt"),
    file("p1", "c.jpg", "/photos/2024/c.jpg"),
    file("p2", "deep.bin", "/photos/2024/raw/deep.bin"),
    // 管理员从后台上传的：path 停在默认 '/'，不属于任何 WebDAV 目录，必须原样不动
    { id: "adm1", name: "admin.txt", size: 1, mime: "text/plain", path: "/", folder_id: "af1" },
  ];
  db.folders = [{ id: "af1", name: "admin上传", parent_id: null, created_at: 1 }];
  return db;

  function file(id: string, name: string, path: string): FileRow {
    return { id, name, size: 10, mime: "text/plain", path, folder_id: null };
  }
}

/** 旧模型里"能看到的全部路径"：directories（含祖先）+ 每个未归属文件的完整路径 */
function legacySet(db: MiniDb): string[] {
  const s = new Set<string>(["/"]);
  for (const d of db.directories) addDirChain(s, d.path);
  for (const f of db.files) {
    if (f.folder_id !== null) continue; // 后台上传的走另一棵树，不参与
    // 旧模型里 path 就是文件的完整路径
    addDirChain(s, dirname(f.path));
    s.add(f.path);
  }
  return [...s].sort();
}

/** 新模型里同样的集合：新树每个目录 + 每个文件的解析路径（去掉后台那棵子树） */
function newSet(db: MiniDb): string[] {
  const tree = new FolderTree(db.folders);
  const s = new Set<string>(["/"]);
  for (const node of db.folders) {
    const p = tree.pathOf(node.id);
    if (!p) continue;
    addDirChain(s, p);
    s.add(p + "/");
  }
  for (const f of db.files) {
    const parent = f.folder_id === null ? "/" : tree.pathOf(f.folder_id);
    if (parent === null) continue;
    addDirChain(s, parent);
    s.add(join(parent, f.name));
  }
  return [...s].filter((p) => !p.startsWith("/admin上传")).sort();
}

function dirname(p: string): string {
  const i = p.lastIndexOf("/");
  return i <= 0 ? "/" : p.slice(0, i);
}

/** 把 /a/b/c 这条链上的每一层（不含自身文件名）都加进集合 */
function addDirChain(s: Set<string>, path: string): void {
  let cur = path;
  while (cur && cur !== "/") {
    s.add(cur + "/");
    const i = cur.lastIndexOf("/");
    cur = i <= 0 ? "/" : cur.slice(0, i);
  }
  s.add("/");
}

function join(dir: string, name: string) {
  return dir === "/" ? "/" + name : dir + "/" + name;
}

async function main() {
  console.log("\n[1] 迁移前后目录树完全一致");
  {
    const db = seedLegacyDb();
    const before = legacySet(db);
    const res = await migrateLegacyFolders({ db } as any);
    const after = newSet(db);
    check("路径集合完全相等", JSON.stringify(before) === JSON.stringify(after),
      JSON.stringify({ before, after }));
    check("隐含中间目录被补出（photos 与 raw）",
      db.folders.some((f) => f.name === "photos" && f.parent_id === null) &&
        db.folders.some((f) => f.name === "raw"),
      JSON.stringify(db.folders.map((f) => f.name)));
    check("跨层同名各归各（两个 2024）", db.folders.filter((f) => f.name === "2024").length === 2);
    check("directories 表已清空", db.directories.length === 0);
    check("根下文件的 path 归位成 '/'", db.files.find((f) => f.id === "t1")!.path === "/");
    check("后台上传的文件没被动", db.files.find((f) => f.id === "adm1")!.folder_id === "af1");
    check("返回统计合理", res.files === 5 && res.folders === 6, JSON.stringify(res));
    const deep = db.files.find((f) => f.id === "p2")!;
    check("深层文件挂到 raw 下", db.folders.find((f) => f.id === deep.folder_id)?.name === "raw", String(deep.folder_id));

    console.log("\n[2] 幂等：再跑一次什么都不做");
    const again = await migrateLegacyFolders({ db } as any);
    check("第二次没有活", again.folders === 0 && again.files === 0, JSON.stringify(again));
    check("路径集合不变", JSON.stringify(newSet(db)) === JSON.stringify(after));
  }

  console.log("\n[3] 目标目录里已有同名文件：改名，绝不覆盖");
  {
    const d = new MiniDb();
    d.folders = [{ id: "docsid", name: "docs", parent_id: null, created_at: 1 }];
    d.files = [
      { id: "existing", name: "notes.txt", size: 1, mime: "text/plain", path: "/", folder_id: "docsid" },
      { id: "move", name: "notes.txt", size: 1, mime: "text/plain", path: "/docs/notes.txt", folder_id: null },
    ];
    const r = await migrateLegacyFolders({ db: d } as any);
    const moved = d.files.find((f) => f.id === "move")!;
    check("原文件还在", d.files.some((f) => f.id === "existing" && f.name === "notes.txt"));
    check("搬来的换了个名字", moved.name === "notes (migrated).txt", moved.name);
    check("搬来的挂进了 docs", moved.folder_id === "docsid", String(moved.folder_id));
    check("同目录下不重名",
      new Set(d.files.filter((f) => f.folder_id === "docsid").map((f) => f.name)).size === 2);
    check("没有为已存在的目录重复建行", r.folders === 0 && d.inserts === 0, JSON.stringify(r));
  }

  console.log("\n[4] 空库直接返回");
  {
    const empty = new MiniDb();
    const r = await migrateLegacyFolders({ db: empty } as any);
    check("零写入", r.folders === 0 && r.files === 0 && empty.inserts === 0, JSON.stringify(r));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
