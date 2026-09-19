/**
 * WebDAV 协议测试 —— 跑在内存目录模型（folders 树 + files.folder_id）上，覆盖：
 *   1. PROPFIND 的三种 Depth，以及"文件 href 不带结尾斜杠、resourcetype 为空"
 *   2. 管理页建的顶层文件夹与上传的文件在挂载盘里可见（两棵树合一的核心诉求）
 *   3. PUT / MKCOL / DELETE / MOVE / COPY 的真实读写与状态码
 *   4. 删文件要连带清掉 shares / direct_links / download_logs
 *   5. 目录改名/移动只改一行 parent_id，子项路径自动跟着走
 *   6. 把目录移进自己的子树必须拒绝，而且不能在拒绝前删掉目标
 *
 * 运行：
 *   npx esbuild test/webdav-listing.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/webdav-listing.mjs
 *   node .dev/webdav-listing.mjs
 */
import { handleWebDAV } from "../src/webdav";
import { hashWebDAVPassword } from "../src/crypto";
import { invalidateSettingsCache } from "../src/settings";
import { invalidateFolderTree } from "../src/folders";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

/* ═══════════ 内存存储 ═══════════ */

/** 所有用例共用同一个桶：storage.ts 的 provider 缓存绑的是第一次见到的 r2 对象 */
const bucket = new Map<string, { data: Uint8Array; contentType: string }>();

interface FolderRow { id: string; name: string; parent_id: string | null; created_at: number }
interface FileRow { id: string; key: string; name: string; size: number; mime: string; folder_id: string | null; uploaded_at: number }

class Store {
  folders: FolderRow[] = [];
  files: FileRow[] = [];
  deletedFileIds: string[] = [];
  cascadeTables: string[] = [];
  readonly queries: string[] = [];

  /** 同一文件内共用一个 store 实例；seed 时清空内容但保持引用（缓存里的 provider 绑着它） */
  reset() {
    this.folders = [];
    this.files = [];
    this.deletedFileIds = [];
    this.cascadeTables = [];
    this.queries.length = 0;
    bucket.clear();
  }

  addFolder(id: string, name: string, parentId: string | null, createdAt = 1_700_000_000_000) {
    this.folders.push({ id, name, parent_id: parentId, created_at: createdAt });
    return this.folders[this.folders.length - 1];
  }

  addFile(id: string, name: string, folderId: string | null, size = 10, mime = "text/plain") {
    this.files.push({ id, key: `files/${id}`, name, size, mime, folder_id: folderId, uploaded_at: 1_700_000_000_000 });
  }

  fileByName(name: string, folderId: string | null) {
    return this.files.find((f) => f.name === name && f.folder_id === folderId) ?? null;
  }

  run(sql: string, binds: unknown[]): any {
    const norm = sql.replace(/\s+/g, " ").trim();
    this.queries.push(norm);

    if (/^SELECT key, value FROM settings/.test(norm)) {
      return { results: SETTINGS_ROWS };
    }

    if (/FROM folders/.test(norm) && /^SELECT id, name, parent_id, created_at/.test(norm)) {
      return { results: this.folders.map((f) => ({ ...f })) };
    }

    if (/FROM files/.test(norm) && /^SELECT/.test(norm)) {
      const cols = /WHERE folder_id IS NULL AND name = \?1/.test(norm);
      const byParent = /WHERE folder_id = \?1 AND name = \?2/.test(norm);
      if (cols) {
        const name = String(binds[0]);
        return { results: this.files.filter((f) => f.folder_id === null && f.name === name).slice(0, 1) };
      }
      if (byParent) {
        const parentId = String(binds[0]);
        const name = String(binds[1]);
        return { results: this.files.filter((f) => f.folder_id === parentId && f.name === name).slice(0, 1) };
      }
      // 按目录集合取文件：folder_id IS NULL / folder_id = ?N 的 OR 组合
      const wanted: (string | null)[] = [];
      for (const m of norm.matchAll(/folder_id (IS NULL|= \?(\d+))/g)) {
        wanted.push(m[1] === "IS NULL" ? null : binds[Number(m[2]) - 1] as string);
      }
      const hit = wanted.length
        ? this.files.filter((f) => wanted.some((id) => (id === null ? f.folder_id === null : f.folder_id === id)))
        : [];
      return { results: hit.sort((a, b) => (a.name < b.name ? -1 : 1)).map((f) => ({ ...f })) };
    }

    if (/^INSERT INTO files\(/.test(norm)) {
      const [id, key, name, size, mime, uploaded_at, folder_id] = binds as any[];
      this.files.push({ id, key, name, size, mime, folder_id, uploaded_at });
      return { meta: { changes: 1 } };
    }

    if (/^UPDATE files SET folder_id = \?1, name = \?2 WHERE id = \?3/.test(norm)) {
      const [folder_id, name, id] = binds as any[];
      const f = this.files.find((x) => x.id === id);
      if (f) {
        f.folder_id = folder_id;
        f.name = name;
      }
      return { meta: { changes: f ? 1 : 0 } };
    }

    const cascadeMatch = /^DELETE FROM (shares|direct_links|download_logs) WHERE file_id/.exec(norm);
    if (cascadeMatch) {
      this.cascadeTables.push(cascadeMatch[1]);
      return { meta: { changes: 1 } };
    }

    if (/^DELETE FROM files WHERE id = \?1/.test(norm)) {
      const id = String(binds[0]);
      this.files = this.files.filter((f) => f.id !== id);
      this.deletedFileIds.push(id);
      return { meta: { changes: 1 } };
    }

    if (/^INSERT INTO folders\(/.test(norm)) {
      const [id, name, parent_id, created_at] = binds as any[];
      if (this.folders.some((f) => f.parent_id === parent_id && f.name === name)) {
        throw new Error("UNIQUE constraint failed: folders.parent_id, folders.name");
      }
      this.folders.push({ id, name, parent_id, created_at });
      return { meta: { changes: 1 } };
    }

    if (/^UPDATE folders SET name = \?1, parent_id = \?2 WHERE id = \?3/.test(norm)) {
      const [name, parent_id, id] = binds as any[];
      const f = this.folders.find((x) => x.id === id);
      if (!f) return { meta: { changes: 0 } };
      if (this.folders.some((x) => x.parent_id === parent_id && x.name === name && x.id !== id)) {
        throw new Error("UNIQUE constraint failed");
      }
      f.name = name;
      f.parent_id = parent_id;
      return { meta: { changes: 1 } };
    }

    if (/^DELETE FROM folders WHERE id = \?1/.test(norm)) {
      const id = String(binds[0]);
      this.folders = this.folders.filter((f) => f.id !== id);
      return { meta: { changes: 1 } };
    }

    throw new Error("内存库未覆盖的 SQL: " + norm);
  }
}

const PASSWORD = "correct horse";
let SETTINGS_ROWS: { key: string; value: string }[] = [];

const store = new Store();

function makeEnv() {
  const db: any = {
    prepare(sql: string) {
      const self = {
        _binds: [] as unknown[],
        bind(...vals: unknown[]) {
          self._binds = vals;
          return self;
        },
        async first() {
          const r = store.run(sql, self._binds);
          return r.results?.[0] ?? null;
        },
        async all() {
          return { results: store.run(sql, self._binds).results ?? [], success: true, meta: {} };
        },
        async run() {
          return { success: true, meta: store.run(sql, self._binds).meta ?? {} };
        },
      };
      return self;
    },
    async batch(stmts: any[]) {
      for (const s of stmts) await s.run();
      return [];
    },
  };

  const r2: any = {
    async put(key: string, body: any, opts: any) {
      let bytes: Uint8Array;
      if (body instanceof Uint8Array) bytes = body;
      else if (body && typeof body.getReader === "function") {
        bytes = new Uint8Array(await new Response(body).arrayBuffer());
      } else if (body instanceof ArrayBuffer) bytes = new Uint8Array(body);
      else bytes = new Uint8Array(0);
      bucket.set(key, { data: bytes, contentType: opts?.httpMetadata?.contentType ?? "application/octet-stream" });
      return { size: bytes.byteLength, httpEtag: "etag-" + key };
    },
    async get(key: string) {
      const o = bucket.get(key);
      if (!o) return null;
      return { body: o.data, size: o.data.byteLength, httpEtag: "etag-" + key, httpMetadata: { contentType: o.contentType } };
    },
    async head(key: string) {
      const o = bucket.get(key);
      if (!o) return null;
      return { size: o.data.byteLength, httpMetadata: { contentType: o.contentType } };
    },
    async delete(key: string) {
      bucket.delete(key);
    },
  };
  return { env: { db, r2, admin: "k" } as any, ctx: { waitUntil() {}, props: {} } as any, bucket };
}

async function request(
  method: string,
  path: string,
  opts: { depth?: string; destination?: string; overwrite?: string; body?: Uint8Array; contentType?: string } = {}
) {
  const { env, ctx } = makeEnv();
  const headers: Record<string, string> = {
    authorization: "Basic " + btoa(`webdav:${PASSWORD}`),
  };
  if (opts.depth) headers.depth = opts.depth;
  if (opts.destination) headers.destination = opts.destination;
  if (opts.overwrite) headers.overwrite = opts.overwrite;
  if (opts.contentType) headers["content-type"] = opts.contentType;
  const req = new Request("https://pan.example.com/webdav" + path, {
    method,
    headers,
    body: opts.body as any,
  });
  return await handleWebDAV(req, env, ctx);
}

/* ═══════════ multistatus 解析 ═══════════ */

interface Res {
  href: string;
  isCollection: boolean;
  raw: string;
}

function parseResponses(body: string): Res[] {
  return [...body.matchAll(/<response>([\s\S]*?)<\/response>/g)].map(([, r]) => ({
    href: /<href>([^<]*)<\/href>/.exec(r)?.[1] ?? "",
    isCollection: /<collection\s*\/>/.test(r),
    raw: r,
  }));
}

function byHref(list: Res[], href: string): Res | undefined {
  return list.find((r) => r.href === href);
}

const BASE = "https://pan.example.com/webdav";

/** 每个用例重建样本树：
 *  /notes.txt(根文件)  /dir/{a.txt, b.txt, sub/deep.bin, "my report#1.txt"}  /empty
 */
function seed() {
  store.reset();
  invalidateFolderTree();
  const dir = store.addFolder("dir", "dir", null);
  store.addFolder("sub", "sub", dir.id);
  store.addFolder("empty", "empty", null);
  store.addFile("f1", "notes.txt", null, 11);
  store.addFile("f2", "a.txt", dir.id, 5);
  store.addFile("f3", "b.txt", dir.id, 7);
  store.addFile("f4", "deep.bin", "sub", 9, "application/octet-stream");
  store.addFile("f5", "my report#1.txt", dir.id, 3);
  return { dir, sub: store.folders.find((f) => f.id === "sub")! };
}

async function propfind(path: string, depth: string) {
  const res = await request("PROPFIND", path, { depth });
  const list = parseResponses(await res.text());
  return { res, list, hrefs: list.map((r) => r.href) };
}

/* ═══════════ 用例 ═══════════ */

async function main() {
  SETTINGS_ROWS = [
    { key: "webdav_enabled", value: "1" },
    { key: "webdav_username", value: "webdav" },
    { key: "webdav_root_path", value: "/" },
    { key: "webdav_password_hash", value: await hashWebDAVPassword(PASSWORD) },
  ];
  invalidateSettingsCache();

  console.log("\n[1] Basic Auth");
  {
    seed();
    const noAuth = await handleWebDAV(
      new Request("https://pan.example.com/webdav/", { method: "PROPFIND", headers: { depth: "1" } }),
      makeEnv().env,
      makeEnv().ctx
    );
    check("缺凭据 → 401 + WWW-Authenticate", noAuth.status === 401 && !!noAuth.headers.get("www-authenticate"), String(noAuth.status));
    const wrongPw = await request("PROPFIND", "/", { depth: "1" });
    check("正确密码 → 207", wrongPw.status === 207, String(wrongPw.status));
  }

  console.log("\n[2] PROPFIND Depth:1 /dir");
  {
    seed();
    const { res, list, hrefs } = await propfind("/dir", "1");
    check("状态 207", res.status === 207, String(res.status));
    check("列出 5 项（自身 + 2 文件 + 1 编码名文件 + 1 子目录）", list.length === 5, hrefs.join(" "));
    check("目录自身 href 带结尾斜杠", byHref(list, `${BASE}/dir/`)?.isCollection === true);
    const a = byHref(list, `${BASE}/dir/a.txt`);
    check("直接子文件在列表里", !!a, hrefs.join(" "));
    check("文件 href 不带结尾斜杠", !!a && a.href.endsWith("/dir/a.txt"));
    check("文件 resourcetype 为空", !!a && !a.isCollection);
    check("文件带 getcontentlength", !!a && /<getcontentlength>5<\/getcontentlength>/.test(a.raw));
    check("子目录 sub 是集合", byHref(list, `${BASE}/dir/sub/`)?.isCollection === true);
    check("Depth:1 不返回孙辈", !hrefs.some((h) => h.includes("deep.bin")), hrefs.join(" "));
    check("不返回兄弟目录内容", !hrefs.some((h) => h.includes("/empty")), hrefs.join(" "));
    check("文件名做百分号编码", !!byHref(list, `${BASE}/dir/my%20report%231.txt`), hrefs.join(" "));
    check("同层按名称排序", hrefs.filter((h) => h.startsWith(`${BASE}/dir/`) && !h.endsWith("/")).length === 3);
  }

  console.log("\n[3] PROPFIND Depth:1 根目录（管理页的目录也要看得见）");
  {
    seed();
    const { list, hrefs } = await propfind("/", "1");
    check("根 href 为 /webdav/（不是双斜杠）", hrefs[0] === `${BASE}/`, hrefs.join(" "));
    check("根目录下的文件可见", hrefs.includes(`${BASE}/notes.txt`), hrefs.join(" "));
    check("notes.txt 不是集合", byHref(list, `${BASE}/notes.txt`)?.isCollection === false);
    check("顶层目录 dir 可见且为集合", byHref(list, `${BASE}/dir/`)?.isCollection === true);
    check("显式空目录可列举", byHref(list, `${BASE}/empty/`)?.isCollection === true);
    check("不递归到 dir 内部", !hrefs.includes(`${BASE}/dir/a.txt`), hrefs.join(" "));
  }

  console.log("\n[4] PROPFIND Depth:infinity");
  {
    seed();
    const { list, hrefs } = await propfind("/dir", "infinity");
    check("孙辈 deep.bin 出现且路径正确", hrefs.includes(`${BASE}/dir/sub/deep.bin`), hrefs.join(" "));
    check("deep.bin 不是集合", byHref(list, `${BASE}/dir/sub/deep.bin`)?.isCollection === false);
    check("sub 只报一次", hrefs.filter((h) => h === `${BASE}/dir/sub/`).length === 1);
    const all = await propfind("/", "infinity");
    check("根 infinity 覆盖全树（自身 + 3 目录 + 5 文件）", all.hrefs.length === 9, all.hrefs.join(" "));
    check("根 infinity 不重复报根自身", all.hrefs.filter((h) => h === `${BASE}/`).length === 1);
  }

  console.log("\n[5] 文件 / 不存在 / Depth:0");
  {
    seed();
    const asFile = await propfind("/dir/a.txt", "1");
    check("文件路径返回 207", asFile.res.status === 207, String(asFile.res.status));
    check("只有一条响应", asFile.list.length === 1, String(asFile.list.length));
    check("文件不被当成目录", asFile.list[0]?.isCollection === false);
    check("displayname 正确", /<displayname>a\.txt<\/displayname>/.test(asFile.list[0]?.raw ?? ""));

    const rootFile = await propfind("/notes.txt", "0");
    check("根下的文件不被误判为空目录", rootFile.res.status === 207 && rootFile.list[0]?.isCollection === false);

    const d0 = await propfind("/dir", "0");
    check("Depth:0 只返回目录自身", d0.list.length === 1 && d0.list[0].isCollection, String(d0.list.length));
    check("目录 creationdate 来自 folders.created_at", /<creationdate>2023-11-14/.test(d0.list[0].raw), d0.list[0].raw);

    const missing = await propfind("/dir/nope", "1");
    check("不存在的路径 → 404", missing.res.status === 404, String(missing.res.status));
    const deepMissing = await propfind("/nope/deeper", "1");
    check("父级不存在也 404", deepMissing.res.status === 404, String(deepMissing.res.status));
  }

  console.log("\n[6] GET / HEAD");
  {
    seed();
    const put = await request("PUT", "/dir/get-me.txt", { body: new TextEncoder().encode("hello"), contentType: "text/plain" });
    check("PUT 成功 → 201", put.status === 201, String(put.status));
    const got = await request("GET", "/dir/get-me.txt");
    check("GET 取回内容", got.status === 200 && (await got.text()) === "hello");
    check("GET 带 Content-Length", got.headers.get("content-length") === "5", String(got.headers.get("content-length")));
    const head = await request("HEAD", "/dir");
    check("HEAD 目录 → 409", head.status === 409, String(head.status));
    const miss = await request("GET", "/dir/nothing.txt");
    check("GET 不存在 → 404", miss.status === 404, String(miss.status));
  }

  console.log("\n[7] PUT 归属与判重");
  {
    seed();
    await request("PUT", "/dir/new.txt", { body: new TextEncoder().encode("x"), contentType: "text/plain" });
    check("文件挂到 dir 的 id 下", store.fileByName("new.txt", "dir") !== null);
    check("不再写 files.path", !store.queries.some((q) => /path/.test(q) && /^INSERT INTO files/.test(q)), store.queries.filter((q) => /^INSERT INTO files/.test(q)).join(" | "));

    const orphan = await request("PUT", "/missing/x.txt", { body: new TextEncoder().encode("x") });
    check("父目录不存在 → 409", orphan.status === 409, String(orphan.status));

    const ontoDir = await request("PUT", "/dir", { body: new TextEncoder().encode("x") });
    check("覆盖到集合上 → 405", ontoDir.status === 405, String(ontoDir.status));

    const first = store.files.length;
    const reupload = await request("PUT", "/dir/a.txt", { body: new TextEncoder().encode("yyyy") });
    check("同名覆盖 → 204", reupload.status === 204, String(reupload.status));
    check("覆盖后文件数不变", store.files.length === first, `${first} → ${store.files.length}`);
    check("覆盖时清掉旧文件的直链", store.cascadeTables.includes("direct_links"), store.cascadeTables.join(","));
    const rootPut = await request("PUT", "/top.txt", { body: new TextEncoder().encode("z") });
    check("根下上传 → 201 且 folder_id 为空", rootPut.status === 201 && store.fileByName("top.txt", null) !== null);

    // 体积闸门：与管理端共用同一套上限判定
    const filesBefore = store.files.length;
    SETTINGS_ROWS = SETTINGS_ROWS.filter((r) => r.key !== "max_upload_mb").concat({ key: "max_upload_mb", value: "1" });
    invalidateSettingsCache();
    const tooBig = await request("PUT", "/dir/huge.bin", { body: new Uint8Array(2 * 1024 * 1024) });
    check("超过单文件上限 → 413", tooBig.status === 413, String(tooBig.status));
    check("超限时不落库", store.files.length === filesBefore, String(store.files.length));
    const okSmall = await request("PUT", "/dir/ok.bin", { body: new Uint8Array(2048) });
    check("上限内照常通过", okSmall.status === 201, String(okSmall.status));
    SETTINGS_ROWS = SETTINGS_ROWS.filter((r) => r.key !== "max_upload_mb");
    invalidateSettingsCache();
  }

  console.log("\n[8] MKCOL");
  {
    seed();
    const mk = await request("MKCOL", "/dir/newdir/");
    check("建子目录 → 201", mk.status === 201, String(mk.status));
    check("新目录 parent_id 指向 dir", store.folders.some((f) => f.name === "newdir" && f.parent_id === "dir"));
    const dup = await request("MKCOL", "/dir/newdir");
    check("重复 MKCOL 沿用宽松的 201", dup.status === 201, String(dup.status));
    const nested = await request("MKCOL", "/a/b/c");
    check("父级不存在 → 409", nested.status === 409, String(nested.status));
    const ontoFile = await request("MKCOL", "/notes.txt");
    check("目标同名文件 → 405", ontoFile.status === 405, String(ontoFile.status));
    const inList = await propfind("/dir", "1");
    check("MKCOL 后新目录立即可列举（缓存即时失效）", inList.hrefs.includes(`${BASE}/dir/newdir/`), inList.hrefs.join(" "));
  }

  console.log("\n[9] DELETE 与级联");
  {
    seed();
    const del = await request("DELETE", "/dir/a.txt");
    check("删文件 → 204", del.status === 204, String(del.status));
    check("文件行已消失", store.fileByName("a.txt", "dir") === null);
    check("级联删了 shares/direct_links/download_logs",
      ["shares", "direct_links", "download_logs"].every((t) => store.cascadeTables.includes(t)),
      store.cascadeTables.join(","));
    const delMissing = await request("DELETE", "/dir/a.txt");
    check("再删一次 → 404", delMissing.status === 404, String(delMissing.status));
    const delRoot = await request("DELETE", "/");
    check("删根 → 403", delRoot.status === 403, String(delRoot.status));

    const before = store.files.length;
    const delDir = await request("DELETE", "/dir");
    check("递归删目录 → 204", delDir.status === 204, String(delDir.status));
    check("子树里的文件全删（" + before + " 个）", store.files.filter((f) => f.folder_id !== null).length === 0, JSON.stringify(store.files.map((f) => [f.name, f.folder_id])));
    check("dir 与 sub 目录行都没了", !store.folders.some((f) => f.id === "dir" || f.id === "sub"));
    check("根下的文件不受影响", store.fileByName("notes.txt", null) !== null);
    const after = await propfind("/", "1");
    check("删完根列表只剩 notes.txt 与 empty", after.list.length === 3, after.hrefs.join(" "));
  }

  console.log("\n[10] MOVE / 重命名");
  {
    seed();
    const mv = await request("MOVE", "/dir/a.txt", { destination: "https://pan.example.com/webdav/dir/renamed.txt" });
    check("同目录改名 → 201", mv.status === 201, String(mv.status));
    check("改名后归属不变", store.fileByName("renamed.txt", "dir") !== null);

    const cross = await request("MOVE", "/notes.txt", { destination: "https://pan.example.com/webdav/dir/moved.txt" });
    check("跨目录移动 → 201", cross.status === 201, String(cross.status));
    check("文件挂进 dir", store.fileByName("moved.txt", "dir") !== null && store.fileByName("moved.txt", null) === null);

    const renameDir = await request("MOVE", "/dir", { destination: "https://pan.example.com/webdav/dir2" });
    check("目录改名 → 201", renameDir.status === 201, String(renameDir.status));
    const listed = await propfind("/dir2/sub", "1");
    check("子目录路径自动跟上（只改了一行 parent_id）", listed.res.status === 207, String(listed.res.status));
    const oldGone = await propfind("/dir", "1");
    check("旧路径不再存在 → 404", oldGone.res.status === 404, String(oldGone.res.status));
    check("目录移动没有重写任何 files.path", !store.queries.some((q) => /^UPDATE files SET path/.test(q)));

    const intoItself = await request("MOVE", "/dir2", { destination: "https://pan.example.com/webdav/dir2/sub/dir2" });
    check("移进自己的子树 → 403", intoItself.status === 403, String(intoItself.status));
    check("拒绝时子树数据完好", store.folders.some((f) => f.id === "sub") && store.files.some((f) => f.folder_id === "sub"));
    const ontoItself = await request("MOVE", "/empty", { destination: "https://pan.example.com/webdav/empty" });
    check("原地 MOVE → 403", ontoItself.status === 403, String(ontoItself.status));

    const noOverwrite = await request("MOVE", "/dir2/b.txt", {
      destination: "https://pan.example.com/webdav/dir2/renamed.txt",
      overwrite: "F",
    });
    check("目标已存在且 Overwrite:F → 412", noOverwrite.status === 412, String(noOverwrite.status));
    const withOverwrite = await request("MOVE", "/dir2/b.txt", { destination: "https://pan.example.com/webdav/dir2/renamed.txt" });
    check("覆盖式移动 → 204", withOverwrite.status === 204, String(withOverwrite.status));
    check("被覆盖的旧文件已删除", store.files.filter((f) => f.name === "renamed.txt").length === 1);
  }

  console.log("\n[11] COPY");
  {
    seed();
    await request("PUT", "/dir/a.txt", { body: new TextEncoder().encode("payload"), contentType: "text/plain" });
    const cp = await request("COPY", "/dir/a.txt", { destination: "https://pan.example.com/webdav/dir/copy.txt" });
    check("复制文件 → 201", cp.status === 201, String(cp.status));
    const copy = store.fileByName("copy.txt", "dir");
    check("副本是独立的一行", !!copy && copy!.id !== "f2");
    check("副本有自己的存储对象", !!copy && copy!.key !== "files/f2");
    const copied = await request("GET", "/dir/copy.txt");
    check("副本内容可读回", copied.status === 200 && (await copied.text()) === "payload", String(copied.status));
    const cpDir = await request("COPY", "/dir", { destination: "https://pan.example.com/webdav/dircopy" });
    check("目录复制未实现 → 501", cpDir.status === 501, String(cpDir.status));
    const cpMissing = await request("COPY", "/nope.txt", { destination: "https://pan.example.com/webdav/x.txt" });
    check("源不存在 → 404", cpMissing.status === 404, String(cpMissing.status));
    const cpBadParent = await request("COPY", "/dir/a.txt", { destination: "https://pan.example.com/webdav/nope/x.txt" });
    check("目标父目录不存在 → 409", cpBadParent.status === 409, String(cpBadParent.status));
  }

  console.log("\n[12] 跨层同名（旧 path 模型做不到）");
  {
    seed();
    const top = store.addFolder("root-2024", "2024", null);
    const inner = store.addFolder("dir-2024", "2024", "dir");
    store.addFile("t1", "x.txt", top.id);
    store.addFile("t2", "x.txt", inner.id);
    const a = await propfind("/2024", "1");
    const b = await propfind("/dir/2024", "1");
    check("顶层 /2024 可列举", a.res.status === 207 && a.hrefs.includes(`${BASE}/2024/x.txt`), a.hrefs.join(" "));
    check("子层 /dir/2024 各自独立", b.res.status === 207 && b.hrefs.includes(`${BASE}/dir/2024/x.txt`), b.hrefs.join(" "));
    check("两个 x.txt 互不干扰", store.files.filter((f) => f.name === "x.txt").length === 2);
    await request("MKCOL", "/2024");
    check("同层同名目录不会多出第二行", store.folders.filter((f) => f.name === "2024" && f.parent_id === null).length === 1, String(store.folders.length));
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
