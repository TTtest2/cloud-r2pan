/**
 * folders 表升级迁移测试 —— 这段迁移会 DROP + RENAME 真表，必须把触发条件钉死：
 *   1. 旧表（name 上有表级 UNIQUE）→ 重建，且整个过程在一个 batch 事务里
 *   2. 新表（无 UNIQUE）→ 什么都不做
 *   3. 表还不存在（新部署）→ 什么都不做，交给建表语句
 *   4. 读不到 sqlite_master → 不动表
 *
 * 运行：
 *   npx esbuild test/folder-tree-migration.ts --bundle --platform=node --format=esm --outfile=.dev/folder-tree-migration.mjs
 *   node .dev/folder-tree-migration.mjs
 */
import { migrateFolderTree } from "../src/db";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const LEGACY_SQL =
  "CREATE TABLE folders(id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL)";
const NEW_SQL =
  "CREATE TABLE \"folders\"(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)";

function fakeEnv(opts: { tableSql: string | null; masterThrows?: boolean }) {
  const batches: string[][] = [];
  const standalone: string[] = [];
  const db: any = {
    prepare(sql: string) {
      const norm = sql.replace(/\s+/g, " ").trim();
      const stmt: any = {
        bind() {
          return stmt;
        },
        async first() {
          if (opts.masterThrows) throw new Error("no sqlite_master access");
          return opts.tableSql === null ? null : { sql: opts.tableSql };
        },
        async all() {
          return { results: [] };
        },
        async run() {
          standalone.push(norm);
          return { success: true, meta: {} };
        },
      };
      return stmt;
    },
    async batch(stmts: any[]) {
      const sqls: string[] = [];
      for (const s of stmts) {
        // 记录 batch 内容但不走 stmt.run()（那样会混进 standalone）
        sqls.push(String(s.__sql ?? ""));
      }
      batches.push(sqls);
      return [];
    },
  };
  // prepare 额外带上 __sql，方便 batch 里读原文
  const origPrepare = db.prepare;
  db.prepare = (sql: string) => {
    const s = origPrepare.call(db, sql);
    s.__sql = sql.replace(/\s+/g, " ").trim();
    return s;
  };
  return { env: { db } as any, batches, standalone };
}

async function main() {
  console.log("\n[1] 旧表需要重建");
  {
    const h = fakeEnv({ tableSql: LEGACY_SQL });
    await migrateFolderTree(h.env);
    check("没有逐条执行 DDL（必须走事务）", h.standalone.length === 0, h.standalone.join(" | "));
    check("恰好一个 batch", h.batches.length === 1, String(h.batches.length));
    const steps = h.batches[0] ?? [];
    check("batch 含建表/搬数据/删旧表/改名 4 步", steps.length === 4, steps.join(" | "));
    check("先建 v2 表", /CREATE TABLE folders_v2/.test(steps[0] ?? ""), steps[0]);
    check("搬数据时 parent_id 显式置 NULL", /SELECT id, name, NULL, created_at FROM folders/.test(steps[1] ?? ""), steps[1]);
    check("DROP 的是旧表而不是新表", /^DROP TABLE folders$/.test(steps[2] ?? ""), steps[2]);
    check("改名回 folders", /ALTER TABLE folders_v2 RENAME TO folders/.test(steps[3] ?? ""), steps[3]);
    check("新表定义里没有表级 UNIQUE", !/UNIQUE/.test(steps[0] ?? ""), steps[0]);
  }

  console.log("\n[2] 已是新形状 → 不动");
  {
    const h = fakeEnv({ tableSql: NEW_SQL });
    await migrateFolderTree(h.env);
    check("没有 batch", h.batches.length === 0);
    check("没有 DDL", h.standalone.length === 0);
  }

  console.log("\n[3] 表还不存在 → 不动（新部署走建表语句）");
  {
    const h = fakeEnv({ tableSql: null });
    await migrateFolderTree(h.env);
    check("没有 batch", h.batches.length === 0);
  }

  console.log("\n[4] 读不到 sqlite_master → 保守跳过");
  {
    const h = fakeEnv({ tableSql: LEGACY_SQL, masterThrows: true });
    await migrateFolderTree(h.env);
    check("没有 batch", h.batches.length === 0);
    check("没有 DDL", h.standalone.length === 0);
  }

  console.log("\n[5] 同层唯一索引的语义（记录设计意图）");
  {
    // 顶层：name 唯一（partial index WHERE parent_id IS NULL）
    // 子层：(parent_id, name) 唯一 —— /a/b 与 /c/b 可共存，/a/b 重复则冲突
    check("旧约束会拒绝跨层同名", /name TEXT NOT NULL UNIQUE/.test(LEGACY_SQL));
    check("新约束允许跨层同名", !/UNIQUE/.test(NEW_SQL));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
