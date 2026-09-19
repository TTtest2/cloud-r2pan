/**
 * files.key 去唯一约束迁移测试
 *
 * 内容去重要求"多个 files 行指向同一个对象 key"，而原始建表语句是
 * `key TEXT NOT NULL UNIQUE` —— 真 D1 会在重指那一步直接 SQLITE_CONSTRAINT。
 * 这条迁移重建表，风险在于"搬数据"，所以断言集中在：
 *   1. 已经是新形状时一个字节都不动（幂等，绝不在每次冷启动时反复重建）
 *   2. 重建时列是从 PRAGMA 现读的：新列一个都不能漏
 *   3. 复制用的是列名显式的 INSERT ... SELECT，不是 SELECT *（列序变了也不受影响）
 *   4. id 仍是主键、NOT NULL 与默认值保留，UNIQUE 消失
 *   5. 索引补回来（含两条 partial index）
 *
 * 运行：
 *   npx esbuild test/files-key-migration.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/files-key-migration.mjs
 *   node .dev/files-key-migration.mjs
 */
import { migrateFilesKeyShareable } from "../src/db";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const LEGACY_DDL =
  "CREATE TABLE files (id TEXT PRIMARY KEY, key TEXT NOT NULL UNIQUE, name TEXT NOT NULL, size INTEGER NOT NULL, " +
  "mime TEXT NOT NULL DEFAULT 'application/octet-stream', uploaded_at INTEGER NOT NULL, path TEXT NOT NULL DEFAULT '/', " +
  "folder_id TEXT, deleted_at INTEGER, sha256 TEXT, etag TEXT)";
const NEW_DDL = LEGACY_DDL.replace(" NOT NULL UNIQUE", " NOT NULL");

/** 旧表的列（PRAGMA table_info 的形状） */
const LEGACY_COLS = [
  { name: "id", type: "TEXT", notnull: 0, dflt_value: null, pk: 1 },
  { name: "key", type: "TEXT", notnull: 1, dflt_value: null, pk: 0 },
  { name: "name", type: "TEXT", notnull: 1, dflt_value: null, pk: 0 },
  { name: "size", type: "INTEGER", notnull: 1, dflt_value: null, pk: 0 },
  { name: "mime", type: "TEXT", notnull: 1, dflt_value: "'application/octet-stream'", pk: 0 },
  { name: "uploaded_at", type: "INTEGER", notnull: 1, dflt_value: null, pk: 0 },
  { name: "path", type: "TEXT", notnull: 1, dflt_value: "'/'", pk: 0 },
  { name: "folder_id", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
  { name: "deleted_at", type: "INTEGER", notnull: 0, dflt_value: null, pk: 0 },
  { name: "sha256", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
  { name: "etag", type: "TEXT", notnull: 0, dflt_value: null, pk: 0 },
];

class Db {
  ddl: string;
  cols: any[];
  statements: string[] = [];

  constructor(ddl: string, cols: any[]) {
    this.ddl = ddl;
    this.cols = cols;
  }

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    const self = this;
    const stmt: any = {
      bind() { return stmt; },
      async first() {
        self.statements.push(norm);
        if (/sqlite_master/.test(norm)) return { sql: self.ddl };
        return null;
      },
      async all() {
        self.statements.push(norm);
        if (/PRAGMA table_info\(files\)/.test(norm)) return { results: self.cols.map((c) => ({ ...c })) };
        return { results: [] };
      },
      async run() {
        self.statements.push(norm);
        return { success: true, meta: { changes: 0 } };
      },
    };
    return stmt;
  }
  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }
}

function env(db: Db) {
  return { db } as any;
}

async function main() {
  console.log("\n[1] 已经是新形状 → 完全不动表");
  {
    const db = new Db(NEW_DDL, LEGACY_COLS);
    await migrateFilesKeyShareable(env(db));
    const ddlish = db.statements.filter((s) => /^(CREATE TABLE|DROP TABLE|ALTER TABLE|INSERT INTO)/.test(s));
    check("没有重建动作", ddlish.length === 0, JSON.stringify(ddlish));
    check("只做了 sqlite_master 探测", db.statements.length === 1, JSON.stringify(db.statements));
  }

  console.log("\n2] 旧表 → 重建为可共享 key 的表");
  {
    const db = new Db(LEGACY_DDL, LEGACY_COLS);
    await migrateFilesKeyShareable(env(db));
    const created = db.statements.find((s) => /^CREATE TABLE files_v2/.test(s)) ?? "";
    check("新表没有 UNIQUE", !!created && !/\bUNIQUE\b/i.test(created), created);
    check("id 仍是主键", /"id" TEXT PRIMARY KEY/.test(created), created);
    check("key 保留 NOT NULL", /"key" TEXT NOT NULL/.test(created));
    check("默认值原样带上（mime 与 path）", created.includes("DEFAULT 'application/octet-stream'") && created.includes("DEFAULT '/'"), created);
    for (const c of LEGACY_COLS) check(`列 ${c.name} 进了新表`, created.includes(`"${c.name}"`));
    const copy = db.statements.find((s) => /^INSERT INTO files_v2/.test(s)) ?? "";
    check("搬运显式列出列名（不依赖列序）", /SELECT "id", "key", "name", "size", "mime", "uploaded_at", "path", "folder_id", "deleted_at", "sha256", "etag" FROM files/.test(copy), copy);
    check("不写死 SELECT *", !/SELECT \* FROM/.test(copy));
    check("先建新再删旧最后改名",
      db.statements.findIndex((s) => /^CREATE TABLE files_v2/.test(s)) <
        db.statements.findIndex((s) => /^DROP TABLE files$/.test(s)) &&
      db.statements.findIndex((s) => /^DROP TABLE files$/.test(s)) <
        db.statements.findIndex((s) => /RENAME TO files/.test(s)));
    for (const idx of ["idx_files_path", "idx_files_folder", "idx_files_deleted", "idx_files_sha", "idx_files_etag"]) {
      check(`索引 ${idx} 补回来了`, db.statements.some((s) => s.includes(idx)));
    }
    check("partial index 条件保留", db.statements.some((s) => /idx_files_sha ON files\(sha256\) WHERE sha256 IS NOT NULL/.test(s)));
    check("没有任何一条语句会丢数据（无 DELETE FROM files）", !db.statements.some((s) => /^DELETE FROM files/.test(s)), JSON.stringify(db.statements));
  }

  console.log("\n[3] 表还不存在（新库）→ 不动");
  {
    const db = new Db("", []);
    await migrateFilesKeyShareable(env(db));
    check("只探测一次，不建表", db.statements.length === 1, JSON.stringify(db.statements));
  }
  {
    const db = new Db(LEGACY_DDL, []); // 有 UNIQUE 但读不到列 → 保守放弃，绝不建空表
    await migrateFilesKeyShareable(env(db));
    check("读不到列信息时不重建", !db.statements.some((s) => /^CREATE TABLE files_v2/.test(s)), JSON.stringify(db.statements));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
