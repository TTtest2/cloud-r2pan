# cloud-r2pan

一个 iOS 26 液态玻璃风格的网盘分享系统，跑在 **Cloudflare Workers + R2 + D1** 上。
功能：上传与文件夹、分享链接（有效期 / 次数上限 / 访问密码）、独立直链、下载市场、
激活码配额、月度流量限额、单 IP 重复下载拦截与自动封禁、下载日志与全球分布、
登录审计 + 2FA、Turnstile 人机验证、OAuth 登录下载、WebDAV 挂载、中英双语。

**零运行时依赖**：生产代码只用 Worker 原生 API（`crypto.subtle`、`ReadableStream`、
`Request/Response`），开发依赖只有 `typescript` / `wrangler` / `@cloudflare/workers-types` / `esbuild`。

英文概览见 [README.en.md](README.en.md)；部署手册见 [DEPLOY.md](DEPLOY.md) 与
[DEPLOY-S3.md](DEPLOY-S3.md)（用任意 S3 兼容存储替代 R2）。

---

## 目录结构

```
src/
  index.ts          路由分发、公开端点的限流
  admin.ts          管理后台全部 REST API（登录 / 2FA / 文件 / 文件夹 / 分享 / 直链 /
                    激活码 / 封禁 / 日志 / 市场 / 设置 / OAuth Provider）
  public.ts         访客侧：分享信息、密码校验、下载闸门、直链下载
  market.ts         下载市场查询（分页 / 搜索 / 排序）
  webdav.ts         WebDAV 协议（PROPFIND/GET/HEAD/PUT/DELETE/MKCOL/MOVE/COPY）
  folders.ts        统一目录模型：路径 ↔ folders 树的解析、缓存与写操作
  storage.ts        存储抽象层：R2 或任意 S3 兼容后端（自带 SigV4 签名）
  codes.ts          激活码：批次、状态、流量配额扣减
  oauth.ts          OAuth2 授权码流程原语（多 Provider）
  oauth_handlers.ts OAuth 路由处理
  db.ts             D1 建表 + 版本化迁移 + 目录模型迁移
  settings.ts       站点配置（5 秒内存缓存）与流量统计
  auth.ts           会话签发校验、IP 识别、限流与登录失败计数
  crypto.ts         HMAC / AES-GCM / TOTP / PBKDF2 / 恢复码
  limits.ts         上传体积闸门（单文件上限 + 总配额）
  pages.ts          页面与错误页渲染、统一安全响应头
  i18n.ts / ua.ts   语言判定、User-Agent 解析
public/
  admin.html        管理后台 SPA（单文件）
  share.html        分享页
  market.html       下载市场首页
```

---

## 路由

| 路径 | 说明 |
|---|---|
| `GET /` | 按设置跳转到 `/market` 或 `/admin` |
| `GET /admin` | 管理后台 |
| `ANY /api/admin/*` | 管理 API（会话 Cookie + 可选 IP 白名单） |
| `GET /s/:token` | 分享页 |
| `GET /s/:token/info` | 分享元信息（状态、是否需要密码 / 人机验证） |
| `POST /s/:token/verify` | 校验访问密码 → 颁发下载令牌（限流 10 次/分钟/IP+token） |
| `GET /s/:token/download` | 下载主流程 |
| `GET /d/:id` | 独立直链下载 |
| `GET /market`、`GET /api/market` | 下载市场页面与查询 |
| `GET /api/codes/status?code=` | 公开查询激活码余额（限流 30 次/分钟/IP） |
| `GET /oauth/{providers,start,callback,session}`、`POST /oauth/logout` | OAuth 登录 |
| `/webdav/*` | WebDAV 挂载点（HTTP Basic Auth） |

---

## 数据模型（D1）

`files` `shares` `direct_links` `folders` `download_logs` `login_logs` `traffic_stats`
`turnstile_visits` `banned_ips` `settings` `oauth_states` `oauth_providers`
`activation_plans` `activation_codes`

表结构在首次请求时自动创建，增量迁移由 `settings.migration_version` 记录进度，
每条迁移只执行一次。

### 目录树

`folders` 是一棵 `parent_id` 树（`parent_id IS NULL` 为顶层），`files.folder_id` 指向目录，
同层不重名、跨层可重名（两条 partial unique index）。**路径只是视图**：URL 里的
`/a/b/c.txt` 由 `src/folders.ts` 现场解析成"目录 id + 文件名"，改名与移动只改一行。

早期版本还留着两套并行的目录事实（`files.path` 存完整路径 + `directories` 路径表）。
现在它们只作为旧数据被读取：`ensureSchema` 里的 `migrateLegacyFolders` 会把旧目录与
文件归属搬进新树，操作幂等、可重入，搬完即停（预检查是两条 `LIMIT 1`）。

### 分享与直链

`shares` 是"带闸门的一次性授权"（有效期、次数上限、访问密码、可选上架市场），
`direct_links` 是"拿了就能下"的独立入口，两者都只引用 `file_id`；
删除文件时按 `file_id` 连带清掉 `shares`、`direct_links`、`download_logs`。

---

## 下载闸门（顺序即语义）

```
封禁 IP → 分享存在/未撤销/未过期/次数未满 → 访问密码 → OAuth 登录 → Turnstile
→ 月度流量限额 → 同 IP 重复下载（可自动封禁）→ 原子扣减次数 → Range 流式输出 → 异步记日志
```

两处关键设计：

- **扣次排在所有闸门之后**。原子更新
  `UPDATE shares SET download_count = download_count + 1 WHERE id = ? AND download_count < ?`
  既保证并发不超卖，又保证被密码/验证码/限流挡掉的请求不会白烧分享人的名额。
- **日志与流量统计走 `ctx.waitUntil`**，不占用响应时间；流量累加由 SQL 完成
  （不是 JS 读-改-写），跨月自动清零且幂等。

---

## 安全实现

- **管理会话**：`cd_admin` Cookie = `过期时间.HMAC-SHA256(admin密钥, 过期时间)`，
  `HttpOnly` + `SameSite=Strict`，HTTPS 下加 `Secure`。登录限流 8 次/分钟/IP，
  成功与失败都写 `login_logs`；可选 TOTP 两步验证与一次性恢复码。
- **IP 白名单**：可限制哪些 IP 能进后台（支持 CIDR），这些 IP 同时豁免流量限额。
- **分享密码**：`shares.password_hash` 用于校验，`password_cipher` 用 admin 密钥
  AES-GCM（HKDF 派生）加密保存，只为让管理员回看口令。列表接口**不再批量下发口令**，
  管理员点"显示"时通过 `GET /api/admin/shares/:id/password` 单条解密。
- **下载令牌**：`?t=过期时间.HMAC(token:过期时间)`，避免把口令反复过网络。
- **Turnstile**：可按"打开分享页 / 点下载 / 两者"配置触发时机与每 IP 每日阈值。
- **WebDAV 凭据**：口令以 PBKDF2-SHA256 存储（5 万轮；workerd 对迭代数有 10 万硬上限）。
  每个 IP 每分钟允许 8 次失败，超限后不再做口令派生；验证通过的凭据在 isolate 内缓存 60 秒。
  旧格式口令登录成功时就地升级。
- **OAuth 回跳**：`?redirect=` 只接受站内绝对路径，协议相对地址与外部 URL 一律回落首页。
- **开放重定向 / XSS**：设置项 `turnstile_sitekey_override` 限定字符集，前端写进
  HTML 属性时统一转义；所有页面下发时带 CSP、`X-Frame-Options`、`Referrer-Policy` 等。
- **错误响应**：管理端异常只回一个 `ref`，堆栈留在 Worker 日志里。

---

## 上传限制

`limits.ts` 是管理端上传与 WebDAV PUT 共用的闸门：

- `max_upload_mb`（默认 100，可小不可大 —— Workers 请求体本身就卡在 100 MB）：
  先用声明体积挡，再给请求体套一层字节计数流挡伪造声明，超限时删掉已写入的对象回滚。
- `storage_quota_mb`（默认 0 = 不限）：按真实写入量事后判定，超配额则回滚并返回 507。

---

## 开发与校验

需要 Node.js 18+（无其他依赖）。

```bash
npm install
npm run typecheck   # tsc --noEmit，严格模式，零错误
npm test            # 用 esbuild 打包 test/*.ts 后逐个跑，断言驱动、无测试框架
```

`npm test` 里每个测试文件是一个独立可执行的断言脚本，跑在内存假 D1 上：
签名对照（`test/s3-signer.ts` 用 `node:crypto` 独立复算 SigV4）、下载闸门顺序、
目录树解析与迁移、WebDAV 全方法读写、管理端各接口边界。加新测试就是往 `test/` 放一个 `.ts`。

本地跑 Worker：`npx wrangler dev`（需在 `.dev.vars` 里写 `admin=你的密钥`）。

---

## 部署

最小部署（详见 [DEPLOY.md](DEPLOY.md)）：

```bash
npx wrangler secret put admin          # 必需：会话与加密主密钥
npx wrangler d1 create cloud-r2pan     # 把返回的 database_id 填进 wrangler.jsonc
npx wrangler r2 bucket create cloud-r2pan
npx wrangler deploy
```

表结构、目录模型迁移、首启设置全部自动完成，不需要手工执行 SQL。
可选密钥：`turnstile_sitekey` / `turnstile_secret`、`totp_recovery`；
可选绑定：`analytics`（全球分布，未绑定时降级用 `download_logs`）。
不用 R2 而用任意 S3 兼容存储（阿里云 OSS / Backblaze / MinIO 等）见 [DEPLOY-S3.md](DEPLOY-S3.md)。
