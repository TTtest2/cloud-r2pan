/**
 * WebDAV 目录列举测试 —— 用内存版 D1 跑真实 PROPFIND，校验：
 *   1. Depth:1 只返回直接子项，嵌套目录不会被摊平进父目录
 *   2. 文件的 href 不带结尾斜杠、resourcetype 为空（否则客户端把文件当目录，挂载后点不开）
 *   3. 按文件完整路径 PROPFIND 能识别为文件而不是 404 / 空目录
 *   4. href 里的非法字符做百分号编码
 *
 * 运行：
 *   npx esbuild test/webdav-listing.ts --bundle --platform=node --format=esm --outfile=.dev/webdav-listing.mjs
 *   node .dev/webdav-listing.mjs
 */
import { handleWebDAV } from "../src/webdav";
import { sha256Hex } from "../src/crypto";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

/* ═══════════ 内存 D1（只实现 PROPFIND 会用到的几条 SQL） ═══════════ */

interface Row {
  id?: string;
  key?: string;
  name?: string;
  size?: number;
  mime?: string;
  path?: string;
  uploaded_at?: number;
  value?: string;
}

/** SQLite 的 LIKE 对 ASCII 大小写不敏感，且 % / _ 是通配符 */
function sqlLike(value: string, pattern: string): boolean {
  const re = new RegExp(
    "^" +
      pattern
        .split("")
        .map((c) =>
          c === "%" ? ".*" : c === "_" ? "." : /[\\^$.|?*+()[\]{}]/.test(c) ? "\\" + c : c
        )
        .join("") +
      "$",
    "i"
  );
  return re.test(value);
}

class FakeD1 {
  files: Row[];
  directories: Row[];
  settings: Row[];
  readonly queries: string[] = [];

  constructor(files: Row[], directories: string[], settings: Row[]) {
    this.files = files;
    this.directories = directories.map((p) => ({ path: p }));
    this.settings = settings;
  }

  prepare(sql: string) {
    const norm = sql.replace(/\s+/g, " ").trim();
    let binds: unknown[] = [];
    const query = () => this.run(norm, binds);
    const stmt = {
      bind: (...vals: unknown[]) => {
        binds = vals;
        return stmt;
      },
      first: async () => (await query())[0] ?? null,
      all: async () => {
        const rows = await query();
        return { results: rows, success: true, meta: {} };
      },
      run: async () => ({ success: true, meta: {} }),
    };
    return stmt;
  }

  async batch(stmts: any[]) {
    for (const s of stmts) await s.all?.() ?? s.first?.() ?? s.run?.();
    return [];
  }

  private async run(sql: string, binds: unknown[]): Promise<Row[]> {
    this.queries.push(sql);
    if (sql.includes("FROM settings")) return this.settings;

    if (sql.includes("FROM directories")) {
      const eq = /WHERE path = \?1/.test(sql);
      const like = /WHERE path LIKE \?1/.test(sql);
      const ne = /AND path != \?2/.test(sql);
      return this.directories.filter((d) => {
        const p = String(d.path);
        if (eq) return p === binds[0];
        if (like) {
          if (!sqlLike(p, String(binds[0]))) return false;
          return ne ? p !== binds[1] : true;
        }
        return true;
      });
    }

    if (sql.includes("FROM files")) {
      const eq = /WHERE path = \?1/.test(sql);
      const like = /WHERE path LIKE \?1/.test(sql);
      const limited = /LIMIT 1/.test(sql);
      const rows = this.files.filter((f) => {
        const p = String(f.path);
        if (eq) return p === binds[0];
        if (like) return sqlLike(p, String(binds[0]));
        return true;
      });
      return limited ? rows.slice(0, 1) : rows;
    }

    throw new Error("FakeD1 未覆盖的 SQL: " + sql);
  }
}

/* ═══════════ 请求助手 ═══════════ */

const PASSWORD = "correct horse";

function makeDb(): FakeD1 {
  const t = 1_700_000_000_000;
  return new FakeD1(
    [
      { id: "f1", key: "files/f1", name: "notes.txt", size: 11, mime: "text/plain", path: "/notes.txt", uploaded_at: t },
      { id: "f2", key: "files/f2", name: "a.txt", size: 5, mime: "text/plain", path: "/dir/a.txt", uploaded_at: t },
      { id: "f3", key: "files/f3", name: "b.txt", size: 7, mime: "text/plain", path: "/dir/b.txt", uploaded_at: t },
      { id: "f4", key: "files/f4", name: "deep.bin", size: 9, mime: "application/octet-stream", path: "/dir/sub/deep.bin", uploaded_at: t },
      { id: "f5", key: "files/f5", name: "my report#1.txt", size: 3, mime: "text/plain", path: "/dir/my report#1.txt", uploaded_at: t },
    ],
    ["/dir", "/dir/sub", "/empty"],
    [
      { key: "webdav_enabled", value: "1" },
      { key: "webdav_username", value: "webdav" },
      { key: "webdav_root_path", value: "/" },
    ]
  );
}

async function request(db: FakeD1, method: string, path: string, depth?: string): Promise<Response> {
  const headers = new Headers({
    authorization: "Basic " + btoa(`webdav:${PASSWORD}`),
    host: "pan.example.com",
  });
  if (depth) headers.set("depth", depth);
  const req = new Request("https://pan.example.com/webdav" + path, { method, headers });
  return await handleWebDAV(req, { db } as any, { waitUntil() {}, passThroughErrorOnCatch() {}, props: {} } as any);
}

interface Res {
  href: string;
  isCollection: boolean;
  raw: string;
}

/** 把 multistatus 拆成 href → 是否集合 */
function parseResponses(body: string): Res[] {
  return [...body.matchAll(/<response>([\s\S]*?)<\/response>/g)].map(([, r]) => {
    const href = /<href>([^<]*)<\/href>/.exec(r)?.[1] ?? "";
    return { href, isCollection: /<collection\s*\/>/.test(r), raw: r };
  });
}

function byHref(list: Res[], href: string): Res | undefined {
  return list.find((r) => r.href === href);
}

/* ═══════════ 用例 ═══════════ */

async function main() {
  const db = makeDb();
  db.settings.push({
    key: "webdav_password_hash",
    value: `s1:${await sha256Hex("s1:" + PASSWORD)}`,
  });
  const { invalidateSettingsCache } = await import("../src/settings");
  invalidateSettingsCache();

  const BASE = "https://pan.example.com/webdav";

  console.log("\n[1] Basic Auth");
  {
    const noAuth = await handleWebDAV(
      new Request("https://pan.example.com/webdav/", { method: "PROPFIND", headers: { depth: "1" } }),
      { db } as any,
      { waitUntil() {}, props: {} } as any
    );
    check("缺凭据 → 401 + WWW-Authenticate", noAuth.status === 401 && !!noAuth.headers.get("www-authenticate"), String(noAuth.status));
    const wrongPw = await handleWebDAV(
      new Request("https://pan.example.com/webdav/", {
        method: "PROPFIND",
        headers: { depth: "1", authorization: "Basic " + btoa("webdev:wrong") },
      }),
      { db } as any,
      { waitUntil() {}, props: {} } as any
    );
    check("错误密码 → 401", wrongPw.status === 401, String(wrongPw.status));
  }

  console.log("\n[2] PROPFIND Depth:1 /dir —— 只返回直接子项");
  {
    const res = await request(db, "PROPFIND", "/dir", "1");
    check("状态 207", res.status === 207, String(res.status));
    const list = parseResponses(await res.text());
    const hrefs = list.map((r) => r.href);
    check("列出 5 项（自身 + 2 文件 + 1 编码名文件 + 1 子目录）", list.length === 5, hrefs.join(" "));

    const self = byHref(list, `${BASE}/dir/`);
    check("目录自身 href 带结尾斜杠", !!self && self.isCollection);

    const a = byHref(list, `${BASE}/dir/a.txt`);
    check("直接子文件 a.txt 在列表里", !!a, hrefs.join(" "));
    check("文件 href 不带结尾斜杠", !!a && a.href.endsWith("/dir/a.txt"));
    check("文件 resourcetype 为空（不是 collection）", !!a && !a.isCollection);
    check("文件带 getcontentlength", !!a && /<getcontentlength>5<\/getcontentlength>/.test(a.raw));

    check("子目录 sub 作为集合出现", byHref(list, `${BASE}/dir/sub/`)?.isCollection === true);
    check("Depth:1 不返回孙辈 deep.bin", !hrefs.some((h) => h.includes("deep.bin")), hrefs.join(" "));
    check("不返回兄弟目录 /empty 的内容", !hrefs.some((h) => h.includes("/empty")), hrefs.join(" "));

    const spaced = byHref(list, `${BASE}/dir/my%20report%231.txt`);
    check("文件名做百分号编码（空格 / #）", !!spaced && !spaced.isCollection, hrefs.join(" "));
  }

  console.log("\n[3] PROPFIND Depth:1 根目录");
  {
    const res = await request(db, "PROPFIND", "/", "1");
    const list = parseResponses(await res.text());
    const hrefs = list.map((r) => r.href);
    check("根 href 为 /webdav/", hrefs.includes(`${BASE}/`), hrefs.join(" "));
    check("根目录下的文件可见", hrefs.includes(`${BASE}/notes.txt`), hrefs.join(" "));
    check("notes.txt 不是集合", byHref(list, `${BASE}/notes.txt`)?.isCollection === false);
    check("子目录 dir 可见且为集合", byHref(list, `${BASE}/dir/`)?.isCollection === true);
    check("不递归到 dir 内的 a.txt", !hrefs.includes(`${BASE}/dir/a.txt`), hrefs.join(" "));
  }

  console.log("\n[4] PROPFIND Depth:infinity /dir");
  {
    const res = await request(db, "PROPFIND", "/dir", "infinity");
    const list = parseResponses(await res.text());
    const hrefs = list.map((r) => r.href);
    check("孙辈 deep.bin 出现在 infinity", hrefs.includes(`${BASE}/dir/sub/deep.bin`), hrefs.join(" "));
    check("deep.bin 不是集合", byHref(list, `${BASE}/dir/sub/deep.bin`)?.isCollection === false);
    check("sub 只作为集合出现一次", hrefs.filter((h) => h === `${BASE}/dir/sub/`).length === 1, hrefs.join(" "));
  }

  console.log("\n[5] 按文件路径 PROPFIND / Depth:0");
  {
    const asFile = await request(db, "PROPFIND", "/dir/a.txt", "1");
    check("文件路径返回 207 而不是 404", asFile.status === 207, String(asFile.status));
    const list = parseResponses(await asFile.text());
    check("只有一条响应", list.length === 1, String(list.length));
    check("文件自身不被当成目录", list[0] && !list[0].isCollection, list[0]?.raw.slice(0, 120));
    check("displayname 正确", /<displayname>a\.txt<\/displayname>/.test(list[0]?.raw ?? ""));

    const rootFile = await request(db, "PROPFIND", "/notes.txt", "0");
    const rootList = parseResponses(await rootFile.text());
    check("同名文件不会被误判为空目录", rootFile.status === 207 && rootList[0]?.isCollection === false, String(rootFile.status));
    check("href 无结尾斜杠", rootList[0]?.href === `${BASE}/notes.txt`, rootList[0]?.href);

    const depth0 = await request(db, "PROPFIND", "/dir", "0");
    const d0 = parseResponses(await depth0.text());
    check("Depth:0 只返回目录自身", d0.length === 1 && d0[0].isCollection, String(d0.length));

    const missing = await request(db, "PROPFIND", "/dir/nope", "1");
    check("不存在的路径 → 404", missing.status === 404, String(missing.status));

    const emptyDir = await request(db, "PROPFIND", "/empty", "1");
    const e = parseResponses(await emptyDir.text());
    check("显式空目录可列举", emptyDir.status === 207 && e.length === 1 && e[0].isCollection, String(emptyDir.status));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
