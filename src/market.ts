/**
 * 下载市场查询 —— /api/market 的 SQL 与分页参数
 *
 * 从 index.ts 的路由里搬出来：这里的绑定顺序必须与 SQL 中 ? 的出现顺序严格一致，
 * 放在路由里没法单测，挪错一位就是一次静默的查询结果错位。
 */

import type { Env } from "./types";

export type MarketSort = "hot" | "newest" | "downloads" | "views";

export interface MarketParams {
  page: number;
  perPage: number;
  q: string | null;
  sort: MarketSort;
}

export interface MarketItem {
  share_id: string;
  created_at: number;
  download_count: number;
  market_views: number;
  market_title: string | null;
  market_desc: string | null;
  file_name: string;
  file_size: number;
  file_mime: string;
  heat: number;
  url: string;
}

export interface MarketListing {
  ok: true;
  total: number;
  page: number;
  size: number;
  sort: MarketSort;
  items: MarketItem[];
}

/** ORDER BY 的列表达式白名单 —— 绝不把用户输入拼进 SQL */
const SORT_SQL: Record<MarketSort, string> = {
  hot: "(s.market_views + s.download_count * 3) DESC",
  newest: "s.created_at DESC",
  downloads: "s.download_count DESC",
  views: "s.market_views DESC",
};

const DEFAULT_PER_PAGE = 12;
const MAX_PER_PAGE = 50;
const MIN_PER_PAGE = 6;

export function parseMarketParams(sp: URLSearchParams): MarketParams {
  const rawSort = sp.get("sort");
  const sort = (Object.keys(SORT_SQL) as MarketSort[]).includes(rawSort as MarketSort)
    ? (rawSort as MarketSort)
    : "hot";
  return {
    page: Math.max(1, Number(sp.get("page")) || 1),
    perPage: Math.min(MAX_PER_PAGE, Math.max(MIN_PER_PAGE, Number(sp.get("size")) || DEFAULT_PER_PAGE)),
    q: sp.get("q")?.trim() || null,
    sort,
  };
}

/**
 * SQLite 的 LIKE 里 % 和 _ 是通配符：不转义的话，搜索框输入一个 "%"
 * 就能列出所有分享。转义符同时要通过 ESCAPE '\' 声明，否则反斜杠按字面匹配。
 */
export function escapeLike(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

export async function queryMarket(env: Env, params: MarketParams, now = Date.now()): Promise<MarketListing> {
  // 只返回有效分享：上架、未撤销、没过期、没达上限、有密码的隐藏
  // ⚠️ SQLite + D1 只支持纯 ? 占位符，不支持 ?N1 / ?Q1 这类扩展语法
  const activeFilter = ` AND s.is_market = 1 AND s.revoked = 0
    AND (s.expires_at IS NULL OR s.expires_at > ?)
    AND (s.max_downloads IS NULL OR s.download_count < s.max_downloads)
    AND s.password_hash IS NULL`;

  const qLike = params.q ? `%${escapeLike(params.q)}%` : null;
  const qFilter = qLike
    ? ` AND (f.name LIKE ? ESCAPE '\\' OR COALESCE(s.market_title,'') LIKE ? ESCAPE '\\' OR COALESCE(s.market_desc,'') LIKE ? ESCAPE '\\')`
    : "";

  // 绑定顺序 = SQL 里 ? 的出现顺序：activeFilter 的 1 个，然后 qFilter 的 3 个（同一个值复用）
  const searchBinds = qLike ? [qLike, qLike, qLike] : [];
  const countStmt = env.db
    .prepare(
      `SELECT COUNT(*) AS c FROM shares s JOIN files f ON f.id = s.file_id WHERE 1=1 ${activeFilter} ${qFilter}`
    )
    .bind(now, ...searchBinds);
  const listStmt = env.db
    .prepare(
      `SELECT s.id AS share_id, s.created_at, s.download_count, s.market_views, s.market_title, s.market_desc,
              f.name AS file_name, f.size AS file_size, f.mime AS file_mime
       FROM shares s JOIN files f ON f.id = s.file_id
       WHERE 1=1 ${activeFilter} ${qFilter}
       ORDER BY ${SORT_SQL[params.sort]}
       LIMIT ? OFFSET ?`
    )
    .bind(now, ...searchBinds, params.perPage, (params.page - 1) * params.perPage);

  const countRow = await countStmt.first<{ c: number }>();
  const { results } = await listStmt.all<Omit<MarketItem, "heat" | "url">>();

  return {
    ok: true,
    total: countRow?.c ?? 0,
    page: params.page,
    size: params.perPage,
    sort: params.sort,
    items: (results ?? []).map((r) => ({
      ...r,
      // 前端算热度就够了，这里也给一个数值方便
      heat: (r.market_views || 0) + (r.download_count || 0) * 3,
      url: `/s/${r.share_id}`,
    })),
  };
}
