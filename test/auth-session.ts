/**
 * 管理会话测试 —— 密钥没配时必须是"未登录"（401），不能抛异常变成 500：
 * 自动构建把 admin 密钥弄丢时，500 会把"该配密钥"伪装成"服务器坏了"。
 *
 * 运行：
 *   npx esbuild test/auth-session.ts --bundle --platform=node --format=esm --loader:.html=text --outfile=.dev/auth-session.mjs
 *   node .dev/auth-session.mjs
 */
import { createSession, verifySession } from "../src/auth";

let failures = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) console.log(`  \x1b[32m✓\x1b[0m ${name}`);
  else {
    failures++;
    console.log(`  \x1b[31m✗\x1b[0m ${name}${detail ? " — " + detail : ""}`);
  }
}

function reqWithCookie(cookie: string): Request {
  return new Request("https://pan.test/api/admin/settings", { headers: { cookie } });
}

async function main() {
  console.log("\n[1] 正常签发与校验");
  {
    const env: any = { admin: "s3cret-key" };
    const cookie = (await createSession(env)).split(";")[0];
    check("签发出来是 cd_admin=<exp>.<sig>", /^cd_admin=\d+\.[A-Za-z0-9_-]+$/.test(cookie), cookie);
    check("自己的 Cookie 通过", (await verifySession(reqWithCookie(cookie), env)) === true);
    check("没有 Cookie 不通过", (await verifySession(reqWithCookie(""), env)) === false);
    check("签名被改过不通过", (await verifySession(reqWithCookie(cookie.slice(0, -3) + "xxx"), env)) === false);
    check("换一个密钥后不通过", (await verifySession(reqWithCookie(cookie), { admin: "other" } as any)) === false);
    check("别的 Cookie 不顶替", (await verifySession(reqWithCookie("cd_adminx=1.2"), env)) === false);
  }

  console.log("\n[2] 密钥缺失：回未登录而不是抛异常");
  {
    const env: any = {}; // 没配 admin secret 的部署
    const cookie = "cd_admin=9999999999999.abcdefgh";
    let threw = false;
    let ok = true;
    try {
      ok = await verifySession(reqWithCookie(cookie), env);
    } catch {
      threw = true;
    }
    check("不抛异常", threw === false);
    check("判定为未登录", ok === false, String(ok));
    const signed = await createSession({ admin: "k" } as any);
    check("有密钥时仍能自证", (await verifySession(reqWithCookie(signed.split(";")[0]), { admin: "k" } as any)) === true);
  }

  console.log(`\n${failures === 0 ? "\x1b[32m全部通过\x1b[0m" : `\x1b[31m${failures} 项失败\x1b[0m`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
