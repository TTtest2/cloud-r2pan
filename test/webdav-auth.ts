/**
 * WebDAV 认证加固测试 —— PBKDF2 口令拉伸、失败限流、老哈希自动升级。
 *
 * 运行：
 *   npx esbuild test/webdav-auth.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/webdav-auth.mjs
 *   node .dev/webdav-auth.mjs
 */
import { handleWebDAV } from "../src/webdav";
import { hashWebDAVPassword, pbkdf2Hex, sha256Hex, verifyWebDAVPassword } from "../src/crypto";
import { invalidateSettingsCache } from "../src/settings";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

const PW = "mount-me-please";

/* ═══════════ 假 D1（设置 + 空目录树 + 记录写回） ═══════════ */

let settingsRows: { key: string; value: string }[] = [];
const upserts: { key: string; value: string }[] = [];

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
        if (/SELECT 1 FROM directories LIMIT 1/.test(norm)) return null;
        return null;
      },
      async all() {
        if (/^SELECT key, value FROM settings/.test(norm)) return { results: settingsRows };
        if (/FROM folders/.test(norm)) return { results: [] };
        if (/FROM files/.test(norm)) return { results: [] };
        throw new Error("未覆盖的 SQL: " + norm);
      },
      async run() {
        const m = /^INSERT INTO settings\(key, value\)/.test(norm);
        if (m) upserts.push({ key: String(binds[0]), value: String(binds[1]) });
        return { success: true, meta: {} };
      },
    };
    return stmt;
  },
  async batch(stmts: any[]) {
    for (const s of stmts) await s.run();
    return [];
  },
};

function setStored(hash: string | null) {
  settingsRows = [
    { key: "webdav_enabled", value: "1" },
    { key: "webdav_username", value: "webdav" },
    { key: "webdav_root_path", value: "/" },
  ];
  if (hash) settingsRows.push({ key: "webdav_password_hash", value: hash });
  upserts.length = 0;
  invalidateSettingsCache();
}

async function authReq(user: string, pass: string, ip: string): Promise<number> {
  const req = new Request("https://pan.test/webdav/", {
    method: "PROPFIND",
    headers: {
      depth: "0",
      authorization: "Basic " + btoa(`${user}:${pass}`),
      "cf-connecting-ip": ip,
    },
  });
  return (await handleWebDAV(req, { db } as any, { waitUntil() {}, props: {} } as any)).status;
}

async function anonymousReq(ip: string): Promise<number> {
  const req = new Request("https://pan.test/webdav/", {
    method: "PROPFIND",
    headers: { depth: "0", "cf-connecting-ip": ip },
  });
  return (await handleWebDAV(req, { db } as any, { waitUntil() {}, props: {} } as any)).status;
}

async function main() {
  console.log("\n[1] 哈希格式与校验");
  {
    const stored = await hashWebDAVPassword(PW);
    check("新格式 pbkdf2$迭代数$盐$哈希", /^pbkdf2\$50000\$[0-9a-f]{32}\$[0-9a-f]{64}$/.test(stored), stored.slice(0, 40));
    check("正确口令通过", (await verifyWebDAVPassword(stored, PW)).ok === true);
    check("错误口令被拒", (await verifyWebDAVPassword(stored, "nope")).ok === false);
    check("新格式无需升级", (await verifyWebDAVPassword(stored, PW)).needUpgrade === false);
    check("同一盐值派生可复现", (await pbkdf2Hex(PW, "0011aabb", 1000)) === (await pbkdf2Hex(PW, "0011aabb", 1000)));

    const legacySalt = "s1";
    const legacy = `${legacySalt}:${await sha256Hex(legacySalt + ":" + PW)}`;
    const lv = await verifyWebDAVPassword(legacy, PW);
    check("老格式仍能登录", lv.ok === true);
    check("老格式标记需要升级", lv.needUpgrade === true);
    check("老格式错口令仍被拒", (await verifyWebDAVPassword(legacy, "bad")).ok === false);

    const weak = await hashWebDAVPassword(PW);
    const downgraded = weak.replace("$50000$", "$1000$");
    check("迭代数偏低的仍可用但要求升级", (await verifyWebDAVPassword(downgraded, PW)).needUpgrade === true);

    const overCap = "pbkdf2$200000$abcd$ef01";
    const broken = await verifyWebDAVPassword(overCap, PW);
    check("迭代数超上限的存储直接判失败并要求重设", broken.ok === false && broken.needUpgrade === true);
    const junk = await verifyWebDAVPassword("pbkdf2$50000$zz$yy", PW);
    check("非十六进制的存储不派生", junk.ok === false && junk.needUpgrade === true);
    check("空存储一律拒", (await verifyWebDAVPassword("", PW)).ok === false);
  }

  console.log("\n[2] 失败限流（超限后不再做昂贵派生）");
  {
    setStored(await hashWebDAVPassword(PW));
    const ip = "198.51.100.77";
    let firstOk = 0;
    for (let i = 0; i < 8; i++) firstOk = await authReq("webdav", "wrong-" + i, ip);
    check("8 次错误口令都是 401", firstOk === 401);
    const blocked = await authReq("webdav", PW, ip);
    check("第 9 次即使口令正确也被拒（省掉派生）", blocked === 401, String(blocked));

    const ip2 = "198.51.100.78";
    check("换 IP 不受影响", (await authReq("webdav", PW, ip2)) === 207, String(await authReq("webdav", PW, ip2)));

    const ip3 = "198.51.100.79";
    for (let i = 0; i < 5; i++) await authReq("webdav", "nope", ip3);
    check("成功登录会清零失败计数", (await authReq("webdav", PW, ip3)) === 207);
    for (let i = 0; i < 5; i++) await authReq("webdav", "nope", ip3);
    check("清零后再错 5 次仍可登录（累计未超阈）", (await authReq("webdav", PW, ip3)) === 207);

    const ip4 = "198.51.100.80";
    for (let i = 0; i < 12; i++) await anonymousReq(ip4);
    check("不带凭据的请求不计失败", (await authReq("webdav", PW, ip4)) === 207);
    // 换一组没用过的凭据：缓存是按凭据（含存储哈希指纹）索引的，
    // 用已验证过的口令会被缓存短路，测不到限流。
    const PW2 = "second-mount-pass";
    setStored(await hashWebDAVPassword(PW2));
    const ip5 = "198.51.100.81";
    for (let i = 0; i < 9; i++) await authReq("baduser", PW2, ip5);
    check("用户名错误也算失败尝试", (await authReq("webdav", PW2, ip5)) === 401);
    check("锁定窗口内持续被拒", (await authReq("webdav", PW2, ip5)) === 401);
  }

  console.log("\n[3] 登录时自动升级老哈希");
  {
    const legacy = `s1:${await sha256Hex("s1:" + PW)}`;
    setStored(legacy);
    const status = await authReq("webdav", PW, "198.51.100.88");
    check("老哈希仍能登录", status === 207, String(status));
    const wrote = upserts.find((u) => u.key === "webdav_password_hash");
    check("写回新格式哈希", !!wrote && wrote.value.startsWith("pbkdf2$50000$"), wrote?.value.slice(0, 30));
    check("写回的哈希校验旧口令有效", wrote ? (await verifyWebDAVPassword(wrote.value, PW)).ok === true : false);
    check("不写明文", !JSON.stringify(upserts).includes(PW), JSON.stringify(upserts).slice(0, 120));

    setStored(null);
    check("未设口令时一律 401", (await authReq("webdav", PW, "198.51.100.89")) === 401);
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
