/**
 * 目录树解析测试 —— 统一目录模型的第 2 阶段：路径 ↔ id 的解析规则。
 * 重点钉住几个容易出事故的分界：
 *   - "根目录" 与 "路径不存在" 必须能区分（后者若当成根，PROPFIND 会列出整个网盘）
 *   - 同层不重名、跨层可重名
 *   - 数据里有环 / 父链断裂时不能死循环
 *   - 缓存与失效
 *
 * 运行：
 *   npx esbuild test/folder-tree.ts --bundle --platform=node --format=esm --outfile=.dev/folder-tree.mjs
 *   node .dev/folder-tree.mjs
 */
import { FolderTree, getFolderTree, invalidateFolderTree, joinPath, pathSegments } from "../src/folders";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

type Row = { id: string; name: string; parent_id: string | null };

/**
 * 树形样本：
 *   docs            (id: docs)
 *     2024          (id: docs-2024)
 *     备份          (id: docs-bak)
 *   photos          (id: photos)
 *     2024          (id: photos-2024)   ← 与 docs/2024 跨层同名，必须共存
 *   顶层 "备份"     (id: root-bak)      ← 与 docs/备份 跨层同名
 */
const ROWS: Row[] = [
  { id: "docs", name: "docs", parent_id: null },
  { id: "photos", name: "photos", parent_id: null },
  { id: "root-bak", name: "备份", parent_id: null },
  { id: "docs-2024", name: "2024", parent_id: "docs" },
  { id: "docs-bak", name: "备份", parent_id: "docs" },
  { id: "photos-2024", name: "2024", parent_id: "photos" },
];

const tree = new FolderTree(ROWS);

function fakeEnv(rows: Row[]) {
  let queries = 0;
  const db: any = {
    prepare() {
      return {
        bind() {
          return this;
        },
        async all() {
          queries++;
          return { results: rows };
        },
        async first() {
          queries++;
          return null;
        },
        async run() {
          queries++;
          return { success: true, meta: {} };
        },
      };
    },
  };
  return { env: { db } as any, queries: () => queries };
}

async function main() {
  console.log("\n[1] resolve：路径 → id");
  {
    check("/docs/2024 → docs-2024", tree.resolve("/docs/2024") === "docs-2024", String(tree.resolve("/docs/2024")));
    check("/photos/2024 → photos-2024（跨层同名各归各）", tree.resolve("/photos/2024") === "photos-2024");
    check("/备份 → root-bak", tree.resolve("/备份") === "root-bak");
    check("/docs/备份 → docs-bak", tree.resolve("/docs/备份") === "docs-bak");
    check("结尾斜杠不影响解析", tree.resolve("/docs/2024/") === "docs-2024");
    check("重复斜杠不影响解析", tree.resolve("//docs//2024//") === "docs-2024");
    check("大小写敏感", tree.resolve("/DOCS") === undefined, String(tree.resolve("/DOCS")));
  }

  console.log("\n[2] 根与不存在必须可区分");
  {
    check("/ → null（根）", tree.resolve("/") === null, String(tree.resolve("/")));
    check("空串 → null（根）", tree.resolve("") === null);
    check("不存在的单层 → undefined", tree.resolve("/nope") === undefined);
    check("父存在子不存在 → undefined", tree.resolve("/docs/nope") === undefined);
    check("把 undefined 当根就会泄露整站", tree.resolve("/docs/nope") !== null);
    check("点段被拒绝", tree.resolve("/docs/../photos") === undefined);
    check("当前目录段被拒绝", tree.resolve("/./photos") === undefined);
    check("超深路径被拒绝", tree.resolve("/" + Array.from({ length: 70 }, (_, i) => "x" + i).join("/")) === undefined);
  }

  console.log("\n[3] pathOf：id → 路径");
  {
    check("根 → /", tree.pathOf(null) === "/", String(tree.pathOf(null)));
    check("两层", tree.pathOf("docs-2024") === "/docs/2024", String(tree.pathOf("docs-2024")));
    check("三层同名不同支", tree.pathOf("photos-2024") === "/photos/2024");
    check("中文段", tree.pathOf("docs-bak") === "/docs/备份", String(tree.pathOf("docs-bak")));
    check("未知 id → null", tree.pathOf("ghost") === null);

    const cyclic = new FolderTree([
      { id: "a", name: "a", parent_id: "b" },
      { id: "b", name: "b", parent_id: "a" },
    ]);
    check("数据有环时不死循环", cyclic.pathOf("a") === null, String(cyclic.pathOf("a")));

    const dangling = new FolderTree([{ id: "c", name: "c", parent_id: "missing" }]);
    check("父链断裂 → null", dangling.pathOf("c") === null, String(dangling.pathOf("c")));
  }

  console.log("\n[4] 子项查询");
  {
    check("顶层三项", tree.roots().length === 3, String(tree.roots().length));
    check("docs 下两个子目录", tree.childrenOf("docs").map((r) => r.name).sort().join(",") === "2024,备份");
    check("叶子无子项", tree.childrenOf("photos-2024").length === 0);
    check("未知父 id 视为无子项", tree.childrenOf("ghost").length === 0);
    check("child 精确命中", tree.child("docs", "2024")?.id === "docs-2024");
    check("child 不误命中别的层", tree.child(null, "2024") === undefined);
    const kids = tree.childrenOf("docs");
    kids.pop();
    check("childrenOf 返回副本，改不坏内部状态", tree.childrenOf("docs").length === 2);
  }

  console.log("\n[5] 路径工具");
  {
    check("pathSegments 去空段", pathSegments("/a/b/")?.join("|") === "a|b");
    check("pathSegments 拒绝点段", pathSegments("/a/../b") === null);
    check("pathSegments 拒绝超长段", pathSegments("/" + "z".repeat(300)) === null);
    check("joinPath 根", joinPath("/", "a") === "/a");
    check("joinPath 子层", joinPath("/docs", "a") === "/docs/a");
  }

  console.log("\n[6] 缓存与失效");
  {
    invalidateFolderTree();
    const h = fakeEnv(ROWS);
    const t1 = await getFolderTree(h.env);
    const t2 = await getFolderTree(h.env);
    check("第二次读命中缓存", t1 === t2 && h.queries() === 1, String(h.queries()));
    const t3 = await getFolderTree(h.env, { fresh: true });
    check("fresh 强制重读", t3 !== t1 && h.queries() === 2, String(h.queries()));
    invalidateFolderTree();
    await getFolderTree(h.env);
    check("invalidate 后重读", h.queries() === 3, String(h.queries()));

    const h2 = fakeEnv([]);
    invalidateFolderTree();
    const empty = await getFolderTree(h2.env);
    check("空表可用", empty.resolve("/") === null && empty.resolve("/x") === undefined);
    invalidateFolderTree();
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
