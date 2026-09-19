/**
 * 后台文件列表接口测试（分页 + 搜索 + 排序 + 去掉逐行子查询）
 *
 * 重点是"形状"而不是数据：这个端点以前无条件返回全表，且每行两趟相关子查询，
 * 文件一多就把 D1 的行读配额烧光。所以断言集中在 ——
 *   1. 一定带 LIMIT/OFFSET，且绑定顺序与 ? 出现顺序一致
 *   2. 逐行子查询换成了单次聚合 JOIN
 *   3. 搜索词里的 LIKE 通配符被转义
 *   4. sort 参数走白名单，注入串进不了 SQL 文本
 *
 * 运行：
 *   npx esbuild test/admin-files-list.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/admin-files-list.mjs
 *   node .dev/admin-files-list.mjs
 */
import { handleAdminApi } from "../src/admin";
import { createSession } from "../src/auth";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const NEW_TABLE_SQL =
  "CREATE TABLE \"folders\"(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created_at INTEGER NOT NULL)";

class FakeDb {
  total = 137;
  rows: any[] = [];
  /** 所有 SELECT 的 {sql, binds}，按调用顺序 */
  selects: { sql: string; binds: unknown[] }[] = [];

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
        return self.dispatch(norm, binds);
      },
      async all() {
        return { results: self.dispatch(norm, binds, true) ?? [] };
      },
      async run() {
        return { success: true, meta: { changes: 0 } };
      },
    };
    return stmt;
  }

  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  }

  private dispatch(sql: string, binds: unknown[], all = false): any {
    /* ensureSchema 冷启动路径 —— 已迁移库应当零写入 */
    if (/sqlite_master WHERE type='table' AND name='settings'/.test(sql)) return { name: "settings" };
    if (/sqlite_master WHERE type = 'table' AND name = 'folders'/.test(sql)) return { sql: NEW_TABLE_SQL };
    if (/SELECT value FROM settings WHERE key = 'migration_version'/.test(sql)) return { value: "999" };
    if (/^SELECT 1 FROM directories LIMIT 1/.test(sql) || /FROM files WHERE folder_id IS NULL AND path IS NOT NULL/.test(sql)) return null;
    if (/^CREATE TABLE|^ALTER TABLE|^DROP TABLE|^CREATE INDEX/.test(sql)) throw new Error("冷启动不该再跑 DDL: " + sql);
    if (/^SELECT key, value FROM settings/.test(sql)) return all ? [{ key: "admin_ips", value: "" }] : null;

    if (/^SELECT COUNT\(\*\) AS c FROM files f/.test(sql)) {
      this.selects.push({ sql, binds: [...binds] });
      return { c: this.total };
    }
    if (/^SELECT f\.id, f\.name, f\.size, f\.mime, f\.uploaded_at, f\.folder_id/.test(sql)) {
      this.selects.push({ sql, binds: [...binds] });
      return all ? this.rows : null;
    }
    throw new Error("未覆盖的 SQL: " + sql);
  }
}

async function call(db: FakeDb, path: string) {
  const env: any = { db, admin: "sekret" };
  const cookie = (await createSession(env)).split(";")[0];
  const req = new Request("https://pan.test" + path, {
    headers: { cookie, "cf-connecting-ip": "203.0.113.1" },
  });
  const res = await handleAdminApi(req, env, { waitUntil() {}, props: {} } as any, new URL(req.url).pathname);
  const body = await res.json().catch(() => null);
  const page = db.selects.find((s) => /LEFT JOIN/.test(s.sql))!;
  const count = db.selects.find((s) => /COUNT\(\*\) AS c FROM files/.test(s.sql))!;
  return { status: res.status, body, pageSql: page?.sql ?? "", pageBinds: page?.binds ?? [], countSql: count?.sql ?? "", countBinds: count?.binds ?? [] };
}

async function main() {
  invalidateSettingsCache();

  console.log("\n[1] 默认请求也必须分页");
  {
    const db = new FakeDb();
    const r = await call(db, "/api/admin/files");
    check("200", r.status === 200, String(r.status));
    check("带 total 与 page/size", r.body?.total === 137 && r.body?.page === 1 && r.body?.size === 50, JSON.stringify({ t: r.body?.total, p: r.body?.page, s: r.body?.size }));
    check("SQL 里有 LIMIT/OFFSET", /LIMIT \? OFFSET \?/.test(r.pageSql), r.pageSql);
    check("默认每页 50 且 offset 0", r.pageBinds.slice(-2).join(",") === "50,0", JSON.stringify(r.pageBinds));
    check("没有 WHERE 时不绑目录", r.pageBinds.length === 2, JSON.stringify(r.pageBinds));
  }

  console.log("\n[2] 逐行子查询换成一次聚合 JOIN");
  {
    const db = new FakeDb();
    const r = await call(db, "/api/admin/files");
    check("不再对每个文件跑 SELECT COUNT(*) FROM shares", !/\(SELECT COUNT\(\*\) FROM shares/.test(r.pageSql), r.pageSql);
    check("分享数来自 GROUP BY file_id 的派生表", /GROUP BY file_id/.test(r.pageSql) && /LEFT JOIN/.test(r.pageSql), r.pageSql);
    check("结果列名保持不变（前端不用改字段）", /AS share_count/.test(r.pageSql) && /AS download_count/.test(r.pageSql));
  }

  console.log("\n[3] 搜索词按 LIKE 通配符转义");
  {
    const db = new FakeDb();
    const r = await call(db, "/api/admin/files?q=%25a_b");
    check("LIKE 声明了 ESCAPE", /LIKE \? ESCAPE/.test(r.pageSql), r.pageSql);
    check("% 与 _ 被转义后绑定", r.pageBinds[0] === "%\\%a\\_b%", JSON.stringify(r.pageBinds));
    check("计数查询用同一份绑定", r.countBinds.join(",") === r.pageBinds.slice(0, 1).join(","), JSON.stringify(r.countBinds));
    const bare = await call(new FakeDb(), "/api/admin/files?q=");
    check("空搜索不加 LIKE、不多绑参", !/LIKE/.test(bare.pageSql) && bare.pageBinds.length === 2, JSON.stringify(bare.pageBinds));
  }

  console.log("\n[4] sort 走白名单，注入进不了 SQL");
  {
    const evil = encodeURIComponent("uploaded_at; DROP TABLE files--");
    const r = await call(new FakeDb(), "/api/admin/files?sort=" + evil + "&dir=" + encodeURIComponent("asc; DELETE FROM files"));
    check("ORDER BY 里只有白名单列", /ORDER BY f\.uploaded_at DESC, f\.id DESC/.test(r.pageSql), r.pageSql);
    check("注入串没有出现在 SQL 文本里", !/DROP TABLE|DELETE FROM files/.test(r.pageSql), r.pageSql);
    const byName = await call(new FakeDb(), "/api/admin/files?sort=name&dir=asc");
    check("按名称升序", /ORDER BY f\.name COLLATE NOCASE ASC/.test(byName.pageSql), byName.pageSql);
    const bySize = await call(new FakeDb(), "/api/admin/files?sort=size");
    check("按体积排序（默认降序）", /ORDER BY f\.size DESC/.test(bySize.pageSql), bySize.pageSql);
  }

  console.log("\n[5] 目录筛选与翻页");
  {
    const db = new FakeDb();
    const inFolder = await call(db, "/api/admin/files?folder=F7&page=3&size=100");
    check("限定目录时先绑目录再绑分页", inFolder.pageBinds.join(",") === "F7,100,200", JSON.stringify(inFolder.pageBinds));
    check("目录条件 AND 在活动过滤之后", /WHERE f\.deleted_at IS NULL AND f\.folder_id = \?/.test(inFolder.pageSql), inFolder.pageSql);
    check("size 上限 200", (await call(new FakeDb(), "/api/admin/files?size=99999")).body?.size === 200);
    check("page 下限 1", (await call(new FakeDb(), "/api/admin/files?page=-5")).body?.page === 1);
    const root = await call(new FakeDb(), "/api/admin/files?folder=root");
    check("root 只查根目录且不绑定", /AND f\.folder_id IS NULL/.test(root.pageSql) && root.pageBinds.length === 2, JSON.stringify(root.pageBinds));
    check("默认列表排除回收站", /f\.deleted_at IS NULL/.test(root.pageSql), root.pageSql);
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
