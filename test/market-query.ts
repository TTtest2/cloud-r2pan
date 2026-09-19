/**
 * 市场查询测试 —— 覆盖从路由里搬出来的 SQL 拼装：
 *   1. 绑定顺序必须与 SQL 中 ? 的出现顺序一致（搬动代码时最容易错位）
 *   2. LIKE 通配符转义：搜 "%" 不能变成"列出全部"
 *   3. sort 只走白名单，用户输入不进 ORDER BY
 *   4. page / size 夹在合法区间
 * 另覆盖限流器按 scope 分桶。
 *
 * 运行：
 *   npx esbuild test/market-query.ts --bundle --platform=node --format=esm --outfile=.dev/market-query.mjs
 *   node .dev/market-query.mjs
 */
import { parseMarketParams, queryMarket, type MarketListing } from "../src/market";
import { rateLimit } from "../src/auth";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

interface Captured {
  sql: string;
  binds: unknown[];
}

const ROW = {
  share_id: "abc",
  created_at: 1,
  download_count: 2,
  market_views: 3,
  market_title: null,
  market_desc: null,
  file_name: "a.bin",
  file_size: 10,
  file_mime: "application/octet-stream",
};

function fakeDb(captured: Captured[], count: number, rows: unknown[]) {
  const db: any = {
    prepare(sql: string) {
      const norm = sql.replace(/\s+/g, " ").trim();
      let binds: unknown[] = [];
      const stmt: any = {
        bind(...vals: unknown[]) {
          binds = vals;
          return stmt;
        },
        async first() {
          captured.push({ sql: norm, binds });
          return { c: count };
        },
        async all() {
          captured.push({ sql: norm, binds });
          return { results: rows };
        },
      };
      return stmt;
    },
  };
  return { db } as any;
}

/** SQL 里 ? 的个数 */
function placeholders(sql: string): number {
  return (sql.match(/\?/g) ?? []).length;
}

interface RunResult {
  out: MarketListing;
  count: Captured;
  list: Captured;
}

/** 走真实入口：query string → 参数解析 → 查询 */
async function run(qs: string, opts: { count?: number; rows?: unknown[] } = {}): Promise<RunResult> {
  const caps: Captured[] = [];
  const env = fakeDb(caps, opts.count ?? 0, opts.rows ?? []);
  const params = parseMarketParams(new URLSearchParams(qs));
  const out = await queryMarket(env, params);
  return { out, count: caps[0], list: caps[1] };
}

async function main() {
  console.log("\n[1] 参数解析");
  {
    const p = parseMarketParams(new URLSearchParams("page=3&size=999&sort=newest&q=hi"));
    check("size 上限夹到 50", p.perPage === 50, String(p.perPage));
    check("page 保留", p.page === 3, String(p.page));
    check("q 透传", p.q === "hi", String(p.q));
    check("合法 sort 生效", p.sort === "newest", p.sort);

    const bad = parseMarketParams(new URLSearchParams("page=-5&size=1&sort=;DROP"));
    check("page 下限 1", bad.page === 1, String(bad.page));
    check("size 下限 6", bad.perPage === 6, String(bad.perPage));
    check("未知 sort 回落 hot", bad.sort === "hot", bad.sort);

    const empty = parseMarketParams(new URLSearchParams("q="));
    check("空 q 视作不搜索", empty.q === null, String(empty.q));
    check("默认 size 12", empty.perPage === 12, String(empty.perPage));
  }

  console.log("\n[2] 绑定顺序与数量");
  {
    const { count, list } = await run("q=photo&page=3&size=6", { count: 7 });
    check("count 绑定数 == 占位符数", count.binds.length === placeholders(count.sql), `${count.binds.length}/${placeholders(count.sql)}`);
    check("list 绑定数 == 占位符数", list.binds.length === placeholders(list.sql), `${list.binds.length}/${placeholders(list.sql)}`);
    check("首个绑定是时间戳", typeof count.binds[0] === "number");
    check("搜索值重复三次", count.binds.length === 4 && count.binds.slice(1).every((v) => v === "%photo%"), JSON.stringify(count.binds));
    check("分页排在末尾：LIMIT=6, OFFSET=(3-1)*6", list.binds[4] === 6 && list.binds[5] === 12, JSON.stringify(list.binds));

    const plain = await run("");
    check("无搜索词时只有时间戳 + 分页", plain.list.binds.length === 3, JSON.stringify(plain.list.binds));
    check("无搜索词时 SQL 不含 LIKE", !/LIKE/.test(plain.list.sql));
    check("无搜索词时占位符数仍对齐", plain.list.binds.length === placeholders(plain.list.sql));
  }

  console.log("\n[3] LIKE 通配符转义");
  {
    const { count } = await run("q=%25"); // q = "%"
    check("单独的 % 被转义", String(count.binds[1]) === "%\\%%", String(count.binds[1]));
    check("声明了 ESCAPE", /ESCAPE/.test(count.sql), count.sql);

    const mixed = await run("q=100%25_a");
    check("% 与 _ 都转义、反斜杠自身也转义", String(mixed.count.binds[1]) === "%100\\%\\_a%", String(mixed.count.binds[1]));
  }

  console.log("\n[4] ORDER BY 只走白名单");
  {
    const { list } = await run("sort=views%3B%20DROP%20TABLE");
    const orderBy = /ORDER BY (.+?) LIMIT/.exec(list.sql)?.[1] ?? "";
    check("非法 sort 落到 hot 表达式", orderBy.startsWith("(s.market_views + s.download_count * 3)"), orderBy);
    check("SQL 里没有 DROP", !/DROP/i.test(list.sql), list.sql);
  }

  console.log("\n[5] 返回结构");
  {
    const { out } = await run("", { count: 7, rows: [ROW] });
    check("total 来自 count 查询", out.total === 7, String(out.total));
    check("heat = 浏览 + 下载*3", out.items[0].heat === 9, String(out.items[0].heat));
    check("url 指向分享页", out.items[0].url === "/s/abc", out.items[0].url);
  }

  console.log("\n[6] 限流按 scope 分桶");
  {
    const ip = "198.51.100.20";
    const eight = Array.from({ length: 8 }, () => rateLimit(ip, "admin-login", 8));
    check("admin-login 前 8 次放行", eight.every(Boolean));
    check("第 9 次拒绝", rateLimit(ip, "admin-login", 8) === false);
    check("换 scope 不受影响", rateLimit(ip, "share-verify:T1", 10) === true);

    const ip2 = "198.51.100.21";
    const tenA = Array.from({ length: 10 }, () => rateLimit(ip2, "share-verify:A", 10));
    check("同 IP 同一 token 满 10 次后拒绝", tenA.every(Boolean) && rateLimit(ip2, "share-verify:A", 10) === false);
    check("另一个 token 仍可用", rateLimit(ip2, "share-verify:B", 10) === true);
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
