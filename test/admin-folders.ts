/**
 * 管理页文件夹接口测试（统一目录模型 Phase 5）
 * 覆盖：列表带完整路径并按路径排序、跨层同名可共存、创建走"同层唯一"、
 * 未知父目录 404、删除只允许空目录（非空 409 并回报数量）。
 * 顺带把 ensureSchema 的冷启动预检查走通，确认它对已迁移库是零写入。
 *
 * 运行：
 *   npx esbuild test/admin-folders.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/admin-folders.mjs
 *   node .dev/admin-folders.mjs
 */
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import { invalidateFolderTree } from "../src/folders";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

interface FRow { id: string; name: string; parent_id: string | null; created_at: number }
interface FileRow { id: string; folder_id: string | null; size: number }

const NEW_TABLE_SQL =
  "CREATE TABLE \"folders\"(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)";
const MIGRATED_COUNT = "999"; // 让 runMigrations 认为所有迁移都跑过了

class FakeDb {
  folders: FRow[] = [];
  files: FileRow[] = [];
  writes = 0;
  coldStartQueries: string[] = [];

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    let binds: unknown[] = [];
    const self = this;
    const stmt: any = {
      bind(...vals: unknown[]) {
        binds = vals;
        return stmt;
      },
      async first() {
        return self.dispatch(norm, binds, "first");
      },
      async all() {
        return { results: self.dispatch(norm, binds, "all") ?? [] };
      },
      async run() {
        self.writes++;
        return self.dispatch(norm, binds, "run") ?? { success: true, meta: { changes: 1 } };
      },
    };
    return stmt;
  }

  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }

  private dispatch(sql: string, binds: unknown[], mode: string): any {
    /* ── ensureSchema 的冷启动路径 ── */
    if (/sqlite_master WHERE type='table' AND name='settings'/.test(sql)) {
      return { name: "settings" };
    }
    if (/sqlite_master WHERE type = 'table' AND name = 'folders'/.test(sql)) {
      return { sql: NEW_TABLE_SQL }; // 已是新形状 → migrateFolderTree 不动表
    }
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) {
      return { value: MIGRATED_COUNT };
    }
    if (/^SELECT 1 FROM directories LIMIT 1/.test(sql) || /FROM files WHERE folder_id IS NULL AND path IS NOT NULL/.test(sql)) {
      this.coldStartQueries.push(sql);
      return null; // 旧模型已无残留 → migrateLegacyFolders 直接返回
    }
    if (/^CREATE TABLE|^ALTER TABLE|^DROP TABLE|^CREATE INDEX|^CREATE UNIQUE INDEX/.test(sql)) {
      throw new Error("冷启动不该再跑 DDL: " + sql);
    }

    /* ── 业务查询 ── */
    if (/^SELECT key, value FROM settings/.test(sql)) {
      return mode === "all" ? [{ key: "admin_ips", value: "" }] : null;
    }
    if (/^SELECT id, name, parent_id, created_at FROM folders/.test(sql)) {
      return mode === "all" ? this.folders.map((f) => ({ ...f })) : null;
    }
    if (/^SELECT fo\.id, fo\.name, fo\.parent_id/.test(sql)) {
      if (mode !== "all") return null;
      return this.folders.map((f) => ({
        id: f.id,
        name: f.name,
        parent_id: f.parent_id,
        created_at: f.created_at,
        file_count: this.files.filter((x) => x.folder_id === f.id).length,
        total_size: this.files.filter((x) => x.folder_id === f.id).reduce((a, b) => a + b.size, 0),
        subfolder_count: this.folders.filter((x) => x.parent_id === f.id).length,
      }));
    }
    if (/^SELECT id FROM folders WHERE id = \?1/.test(sql)) {
      return this.folders.find((f) => f.id === binds[0]) ?? null;
    }
    if (/^SELECT \(SELECT COUNT\(\*\) FROM files WHERE folder_id = \?1\) AS files/.test(sql)) {
      if (mode !== "first") return null;
      return {
        files: this.files.filter((x) => x.folder_id === binds[0]).length,
        subfolders: this.folders.filter((x) => x.parent_id === binds[0]).length,
      };
    }
    if (/^INSERT INTO folders\(/.test(sql)) {
      const [id, name, parent_id, created_at] = binds as any[];
      if (this.folders.some((f) => f.parent_id === parent_id && f.name === name)) {
        throw new Error("UNIQUE constraint failed");
      }
      this.folders.push({ id, name, parent_id, created_at });
      return { success: true, meta: { changes: 1 } };
    }
    if (/^DELETE FROM folders WHERE id = \?1/.test(sql)) {
      this.folders = this.folders.filter((f) => f.id !== binds[0]);
      return { success: true, meta: { changes: 1 } };
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }
}

async function call(db: FakeDb, path: string, init: { method?: string; body?: unknown } = {}) {
  const env: any = { db, admin: "sekret" };
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    method: init.method ?? "GET",
    headers: { cookie, "cf-connecting-ip": "203.0.113.1", ...(init.body ? { "content-type": "application/json" } : {}) },
    body: init.body ? JSON.stringify(init.body) : undefined,
  });
  const res = await handleAdminApi(req, env, { waitUntil() {}, props: {} } as any, new URL(req.url).pathname);
  return { status: res.status, body: await res.json().catch(() => null) };
}

function seedDb() {
  invalidateSettingsCache();
  invalidateFolderTree();
  const db = new FakeDb();
  db.folders = [
    { id: "docs", name: "docs", parent_id: null, created_at: 1 },
    { id: "docs-2024", name: "2024", parent_id: "docs", created_at: 2 },
    { id: "photos", name: "photos", parent_id: null, created_at: 3 },
    { id: "photos-2024", name: "2024", parent_id: "photos", created_at: 4 },
    { id: "empty", name: "empty", parent_id: null, created_at: 5 },
  ];
  db.files = [
    { id: "f1", folder_id: "docs", size: 10 },
    { id: "f2", folder_id: "docs-2024", size: 20 },
    { id: "f3", folder_id: "photos-2024", size: 30 },
  ];
  return db;
}

async function main() {
  console.log("\n[1] 列表：完整路径 + 按路径排序");
  {
    const db = seedDb();
    const r = await call(db, "/api/admin/folders");
    check("200", r.status === 200, String(r.status));
    const list: any[] = r.body?.folders ?? [];
    check("五个目录都在（含子层）", list.length === 5, JSON.stringify(list.map((x) => x.path)));
    check("子目录给出完整路径", list.find((x) => x.id === "docs-2024")?.path === "/docs/2024");
    check("跨层同名各自可辨", new Set(list.map((x) => x.path)).size === 5);
    check("按路径排序", JSON.stringify(list.map((x) => x.path)) ===
      JSON.stringify(["/docs", "/docs/2024", "/empty", "/photos", "/photos/2024"]), JSON.stringify(list.map((x) => x.path)));
    check("带文件数与体积", list.find((x) => x.id === "docs")?.file_count === 1 && list.find((x) => x.id === "docs")?.total_size === 10);
    check("带子目录数", list.find((x) => x.id === "docs")?.subfolder_count === 1);
    check("冷启动没跑 DDL、没写库", db.writes === 0, String(db.writes));
  }

  console.log("\n[2] 创建：同层唯一、跨层可同名");
  {
    const db = seedDb();
    const top = await call(db, "/api/admin/folders", { method: "POST", body: { name: "music" } });
    check("顶层新建 201", top.status === 201 && top.body?.parent_id === null, JSON.stringify(top.body));
    const dup = await call(db, "/api/admin/folders", { method: "POST", body: { name: "docs" } });
    check("同层重名 409", dup.status === 409, String(dup.status));
    const child = await call(db, "/api/admin/folders", { method: "POST", body: { name: "docs", parent_id: "photos" } });
    check("不同层同名允许（photos/docs）", child.status === 201 && child.body?.parent_id === "photos", String(child.status));
    const badParent = await call(db, "/api/admin/folders", { method: "POST", body: { name: "x", parent_id: "ghost" } });
    check("未知父目录 404", badParent.status === 404, String(badParent.status));
    const blank = await call(db, "/api/admin/folders", { method: "POST", body: { name: "   " } });
    check("空名 400", blank.status === 400, String(blank.status));

    const after = await call(db, "/api/admin/folders");
    const paths = (after.body?.folders ?? []).map((x: any) => x.path);
    check("新目录立刻出现在列表且路径正确", paths.includes("/photos/docs") && paths.includes("/music"), JSON.stringify(paths));
  }

  console.log("\n[3] 删除：只允许空目录");
  {
    const db = seedDb();
    const nonEmpty = await call(db, "/api/admin/folders/docs", { method: "DELETE" });
    check("有文件的目录 409", nonEmpty.status === 409, String(nonEmpty.status));
    check("回报文件数", nonEmpty.body?.files === 1 && nonEmpty.body?.subfolders === 1, JSON.stringify(nonEmpty.body));
    check("目录没被删", db.folders.some((f) => f.id === "docs"));
    check("没有把子文件丢回根", db.files.every((f) => f.folder_id !== null), JSON.stringify(db.files));

    const hasChild = await call(db, "/api/admin/folders/photos", { method: "DELETE" });
    check("只有子目录也算非空", hasChild.status === 409 && hasChild.body?.subfolders === 1, JSON.stringify(hasChild.body));

    const ok = await call(db, "/api/admin/folders/empty", { method: "DELETE" });
    check("空目录删除 200", ok.status === 200 && !db.folders.some((f) => f.id === "empty"), String(ok.status));
    const gone = await call(db, "/api/admin/folders/empty", { method: "DELETE" });
    check("删掉的目录再删 404", gone.status === 404, String(gone.status));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
