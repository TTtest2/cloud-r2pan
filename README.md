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
| `GET /s/:token` | 分享页（文件或目录） |
| `GET /s/:token/info` | 分享元信息（状态、`kind`、是否需要密码 / 人机验证） |
| `POST /s/:token/verify` | 校验访问密码 → 颁发下载令牌（限流 10 次/分钟/IP+token） |
| `GET /s/:token/children?dir=` | 浏览被分享的目录（限流 60 次/分钟/IP+token） |
| `GET /s/:token/download` | 下载主流程；目录分享需带 `?file=<id>`；`?inline=1` 可内联预览 |
| `GET /d/:id` | 独立直链下载 |
| `GET /pickup` | 取件页（输码取件 + 匿名投递） |
| `GET /api/pickup/status` | 投递是否开放、限额与所需人机验证 |
| `POST /api/pickup` | 匿名投递一个文件 → 返回取件码（`?once=1` 一次一取） |
| `POST /api/pickup/claim` | 输码 → 文件信息 + 短时效下载票据 |
| `GET /api/pickup/download?c=&t=` | 凭码 + 票据下载（走与 `/s/:token/download` 同一条闸门） |
| `GET /market`、`GET /api/market` | 下载市场页面与查询 |
| `GET /api/codes/status?code=` | 公开查询激活码余额（限流 30 次/分钟/IP） |
| `GET /oauth/{providers,start,callback,session}`、`POST /oauth/logout` | OAuth 登录 |
| `POST /api/admin/upload` | 单次上传（≤100 MB 请求体） |
| `POST /api/admin/upload/check`、`/claim` | 秒传：查指纹命中 → 只写一行元数据 |
| `POST /api/admin/upload/init`、`PUT /upload/part`、`POST /upload/complete`、`DELETE /upload` | 分片上传 |
| `POST /api/admin/cleanup/run` | 立即跑一轮定时清理（与 cron 同一入口，返回报告） |
| `/webdav/*` | WebDAV 挂载点（HTTP Basic Auth） |

---

## 数据模型（D1）

`files` `shares` `direct_links` `folders` `upload_sessions` `download_logs` `login_logs`
`traffic_stats` `turnstile_visits` `banned_ips` `settings` `oauth_states` `oauth_providers`
`activation_plans` `activation_codes`

`files` 除基本字段外还有三个"生命周期/指纹"列：`deleted_at`（非空 = 在回收站里）、
`sha256`（浏览器算的，秒传用）、`etag`（存储回执，写后去重用）。
`shares.folder_id` 非空 = 目录分享，此时 `file_id` 是 `''` 哨兵。

`shares` 另有取件码一组列：`pickup_hash`（= `HMAC(admin, 归一化码)`，唯一 partial
index，**明文码不落库**）、`pickup_cipher`（给后台回看用的 AES-GCM 密文）、
`pickup_claims`（被输码查看的次数），以及 `origin`（`'admin'` / `'drop'`）与
`origin_ip`（投递者 IP）。一条匿名投递 = 一行 `files`（挂在自动创建的顶层"投递箱"
目录里）+ 一行 `shares(origin='drop')`，因此去重、引用计数、回收站、cron 全都白拿。
投递行**刻意不进入**分享列表、下载市场、派生直链与概览计数 —— 否则后台会为它自动
补出一条 `/d/:id`，等于绕过取件码。

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

一条分享要么指向一个文件、要么指向一个目录（`folder_id` + `file_id=''`）。目录分享可浏览
（`/s/:token/children`，只能看到分享子树，面包屑不会越过分享根），文件逐个下载，
有效期 / 次数 / 口令等闸门对整条分享共用一份名额。

`shares` 是"带闸门的一次性授权"，`direct_links` 是"拿了就能下"的独立入口 —— 后者只服务
单个文件，所以目录分享既不上架下载市场，也不派生直链。

文件被移进回收站期间，它的分享与直链一律读不到（所有对外读路径都带 `deleted_at IS NULL`），
恢复后原样可用；只有彻底删除才会连带清掉 `shares`、`direct_links`、`download_logs`。

---

## 取件码投递

收件人只输一枚码就能取件，不需要那条长链接。**既然按码寻址，码本身就是凭据**，
于是它按口令的规格对待：

- 库里只有 `HMAC(admin, 归一化码)` 和一份可解密给后台回看的密文，明文永不落库；
  换 `admin` 密钥 = 所有已发码同时作废。
- 默认**6 位纯数字**：好念好抄，但一共只有 100 万种组合 —— 这个格式下的防爆破靠限流
  与每日尝试预算，不靠组合数。设置项 `pickup_code_style` 可切成 `alnum8`
  （8 位、去掉 `0o1li` 的字符集，约 40 bit），那才是"猜不出来"的强度。
- 输入忽略大小写、空格与连字符（`123-456` ≡ `123456`）；形状不合法的码连哈希与查库
  都不做。查库两种形状都收，所以**切换格式不会让已发出去的码当场作废**。
- 三层限流：形状不符零 D1 开销；按 IP 每分钟 10 次 **加每天 50 次**；同一枚码被反复试
  5 次后不再查库（顺带保住免费档的 D1 读次数）。
- 所有失败回同一张 404，不区分"不存在 / 已过期 / 已被取走"，否则这里就成了码探针。

配额（都在 `settings` 里，默认值按免费档定）：

| 设置项 | 默认 | 作用 |
|---|---|---|
| `pickup_enabled` | 开 | 总开关；**关掉连已发出去的码一起失效** |
| `pickup_max_upload_mb` | 100 | 单件上限（Workers 请求体硬顶，投递通道不分片） |
| `pickup_per_ip_daily_count` | 5 | 单来源 IP 每天件数（同一 NAT 共享） |
| `pickup_per_ip_daily_mb` | 1024 | 单来源 IP 每天字节 |
| `pickup_code_style` | `digits6` | 码格式：6 位纯数字（好抄）或 `alnum8`（猜不出来） |
| `pickup_per_ip_daily_claims` | 50 | 单来源 IP 每天输码尝试次数；6 位数字格式下这是主要防线 |
| `pickup_total_quota_mb` | 1024 | 投递区总占用（约 R2 免费 10 GB 的十分之一），超了 507 并回滚对象 |
| `pickup_retention_days` | 7 | 保留天数；到期 cron 连行带对象清除，**不进回收站** |

两处刻意的设计取舍：

- **投递路径不做去重/秒传。** 陌生人的文件与机主文件共用一个对象会把删除生命周期绑
  在一起，而"这个 sha256 你已经有了"本身是存在性 oracle —— 投件区要的是互相看不见。
- **后台"入库"会删掉投递行（码随之作废）**，只保留文件。一条没人知道 URL、也不该长期
  存在的分享留在库里只会变成暗雷；要对外分享就另建一条。"销毁"则不等保留期，立刻连
  对象清掉。

下载与 `/s/:token/download` 共用同一条闸门流水线（`serveShareDownload`）：有效期、次数、
月度流量、单 IP 重复下载与自动封禁一条都不少 —— 取件码只是多给了一种进入方式。

> 这是公网可写入口：别人可以往你的域名上投文件并以你的域名下载。要么把 Turnstile
> 配上（配了之后投递强制过人机验证），要么随时能用总开关收起。

---

## 下载闸门（顺序即语义）

```
封禁 IP → 分享存在/未撤销/未过期/次数未满 → 访问密码 → OAuth 登录 → Turnstile
→ 月度流量限额 → 同 IP 重复下载（可自动封禁）→ 原子扣减次数 → Range 流式输出 → 异步记日志
```

`/s/:token/download`（文件或目录）与 `/api/pickup/download`（取件码）跑的是同一条
`serveShareDownload`；`/d/:id` 直链按设计跳过密码 / OAuth / Turnstile 三道，其余一致。

三处关键设计：

- **扣次排在所有闸门之后**。原子更新
  `UPDATE shares SET download_count = download_count + 1 WHERE id = ? AND download_count < ?`
  既保证并发不超卖，又保证被密码/验证码/限流挡掉的请求不会白烧分享人的名额。
  没有设上限的分享与直链同样累加这一列（走单条不带 `download_count < ?` 的 UPDATE）——
  后台列表与市场里的"已下载次数"看的就是它，不计数会永远显示 0。
- **206 只回被请求的那一段**。`Range` 由存储层的分段读取实现：R2 的分片参数必须写成
  `get(key, { range: { offset, length } })`，顶层 `offset/length` 是被废弃的老写法，
  运行时会**静默忽略**并把整个对象推回去（响应就成了"Content-Range 正确、body 完整"）。
  S3 后端则发真实的 `Range:` 头。两者都由 `test/storage-range.ts` 钉住。
- **日志与流量统计走 `ctx.waitUntil`**，不占用响应时间；流量累加由 SQL 完成
  （不是 JS 读-改-写），跨月自动清零且幂等。

> 自查提示：`max_downloads_per_ip` 与"重复下载自动封禁"是按 **share/直链 + IP** 计数的，
> 管理员用同一个分享连续点两次下载就可能把自己的出口 IP 关进 `banned_ips`（默认 24 小时）。
> 测试完记得在后台"IP 封禁"里解掉。

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
- **内联预览**：`?inline=1` 只在 `src/preview.ts` 的精确 MIME 白名单内生效（图片 / PDF /
  纯文本 / 音视频）。这个 Worker 与分享页同源，能被浏览器当文档解析的用户内容就是 XSS 面，
  所以 `text/html`、`xhtml`、`image/svg+xml`（可嵌脚本）、各类脚本文本一律排除，
  并且响应带 `X-Content-Type-Options: nosniff` + 专用 CSP。前端藏不藏"预览"按钮无所谓，
  **服务端永远有最终决定权**：不在白名单就退回 `attachment`。
- **目录分享的边界**：浏览与下载都限定在被分享目录的子树内，`dir`/`file` 参数越界一律拒绝，
  面包屑不会显示分享根之上的任何一级路径。
- **OAuth 回跳**：`?redirect=` 只接受站内绝对路径，协议相对地址与外部 URL 一律回落首页。
- **开放重定向 / XSS**：设置项 `turnstile_sitekey_override` 限定字符集，前端写进
  HTML 属性时统一转义；所有页面下发时带 CSP、`X-Frame-Options`、`Referrer-Policy` 等。
- **错误响应**：管理端异常只回一个 `ref`，堆栈留在 Worker 日志里。

---

## 上传与存储配额

`limits.ts` 是管理端上传、分片上传与 WebDAV PUT 共用的闸门：

- `max_upload_mb`（默认 100，上限可设到 50 GB）：先用声明的 Content-Length 挡一道，
  落盘后再用存储层回报的真实 size 复核上限与配额，超标就删对象、行不落库。
  声明可以撒谎，真实字节数不能。
- `storage_quota_mb`（默认 0 = 不限）：按去重后的真实占用判断，超配额返回 507。
- ⚠️ 不能给 `req.body` 插一层 `pipeThrough` 计数：R2 只接受**长度已知**的流
  （请求体本身或 `FixedLengthStream`），管道出来的匿名流会被直接拒绝 ——
  这条踩过一次，全站上传全挂。存储层必须拿到 `req.body` 本尊。

两条上传通道：

| 通道 | 触发条件 | 说明 |
|---|---|---|
| 单次 `POST /api/admin/upload` | ≤64 MB | 一次请求体，上限就是 Workers 的 100 MB |
| 分片 `init` → `part` → `complete` | >64 MB | 8 MiB 一片（协议最小 5 MiB）、最多 10000 片、单片 ≤96 MiB；失败自动重试 3 次，异常会 `abort` 会话 |

分片合并后一样用 `head()` 的真实体积复核，然后才落库。会话表 `upload_sessions` 有 24 小时
TTL，超时未完成的由定时任务 `abort`（残留分片是要计费的）。

### 内容去重与秒传

两条互补指纹，都带方案前缀（`sha256:` / `etag:`），不同方案永不互撞：

- `sha256`：浏览器用 WebCrypto 算（≤256 MB；再大就不算，因为没有流式摘要）。
  命中 `POST /api/admin/upload/check` → `POST /api/admin/upload/claim`，一个字节都不传。
- `etag`：存储后端写完对象的回执（单次上传是内容 MD5，分片是 `"<md5>-N"`），服务端零成本
  可得；发现同指纹同体积已有对象就删掉刚写的那份、把行改指已有 key。

只有管理员上传通道会带 `sha256`（可信通道），WebDAV / S3 直连写进行为 `NULL`、不参与秒传。
去重之后同一个 key 可能被多行引用：**能不能删对象只看剩余引用行数**（`trash.ts` 负责数），
配额与概览统计也一律按 key 去重。

## 回收站与定时清理

删除默认只打 `files.deleted_at`：对象保留、分享/直链原地保留（恢复后继续能用），
到期由 cron 彻底清除。保留期 `trash_retention_days` 默认 7 天、最长 90、0 = 关闭回收站。
软删除期间对象**仍占存储**，所以概览里的 `storage.bytes` 含回收站，另有 `trash_bytes` 显示可回收体积。
目录判空不算回收站条目；目录若已被删除，恢复出来的文件退回根目录。

`wrangler.jsonc` 的 `triggers.crons` 每小时跑一次 `src/cron.ts`：撤销过期分享（保留行）、
删除到期直链、彻底清除到期回收站条目、**清除到期投递（行与对象一起走，不进回收站）**、
中止超时分片、随机抽查若干对象看字节是否还在（只报告不处置）。
后台"回收站"页可以点"立即运行定时清理"看同一份报告。
**cron 不会无人监督地删活文件**：那个"没有任何分享引用的文件"扫描只在手动清理里，
而且现在也只是把文件送进回收站。手动"清理失效分享"也跳过投递行 —— 只删它的分享行会
把投件文件留下成看不见却仍在计费的孤儿。

## 免费档配额对照（本仓库参数就是这么定的）

Cloudflare 免费档实测（2026-09）：

| 项目 | 免费额度 | 这里的取值 |
|---|---|---|
| R2 存储 | 10 GB·月 | 回收站最长留 90 天、默认 7 天，因为软删除照样占额度 |
| R2 Class A（写 / 列举 / 分片上传） | 100 万/月 | 8 MiB 一片：1 GB 文件 ≈ 128 次写 |
| R2 Class B（读） | 1000 万/月 | 每次下载 1 次读；cron 每轮抽查 20 个对象 |
| R2 对象大小 / 分片数 | 5 TiB / 最多 10000 片 | 单文件上限最高设到 50 GB（8 MiB × 10000 ≈ 80 GB 为协议顶） |
| Workers 请求体 | 100 MB（免费与付费相同） | 所以才有分片通道；单片限 96 MiB |
| Workers CPU | **10 ms/次** | 不做 Worker 内 zip 打包、不在服务端算大文件哈希；cron 每步分批 |
| Workers 子请求 | 50 次/请求 | `CLEANUP_BATCH = 50`，分片中止 `UPLOAD_REAP_BATCH = 20`（一次 abort 一次子请求） |
| Workers Cron | 最多 5 条 | 只用 1 条（每小时） |
| 投递区体积 | —— | `pickup_total_quota_mb` 默认 1024 MB，只占 R2 免费 10 GB 的十分之一 |
| 投递频率（防被人刷爆 Class A） | —— | 单 IP 默认 5 件 / 1 GB·天，单请求最多 6 次·分钟 |
| 投递通道 | —— | 只用单次直传（≤100 MB），**不开分片**：分片会把 Class A 写次数放大十倍以上 |
| D1 查询数 | 50 次/请求 | 同上，所有清理步骤都分批 |
| D1 绑定参数 | 100 个/条查询 | 所有 `IN (...)` 一律按 50 分批（软删除还要多绑一个时间戳） |
| D1 单库大小 | 500 MB | 元数据极小；真正吃额度的是 `download_logs`，后台有清理入口 |

---

## 开发与校验

需要 Node.js 18+（无其他依赖）。

```bash
npm install
npm run typecheck   # tsc --noEmit，严格模式，零错误
npm test            # 用 esbuild 打包 test/*.ts 后逐个跑，断言驱动、无测试框架
```

`npm test` 里每个测试文件是一个独立可执行的断言脚本，跑在内存假 D1 上：
签名对照（`test/s3-signer.ts` 用 `node:crypto` 独立复算 SigV4）、下载闸门顺序、内联预览白名单、
目录树解析与迁移、WebDAV 全方法读写、管理端各接口边界、回收站端到端、定时清理的分批与处置语义、
分片上传契约（流必须原样交给存储层、真实体积才是判据）、目录分享与去重/秒传/引用计数、
两个存储后端**分段读取的参数形状**（`test/storage-range.ts`）、取件码投递（归一化、配额回滚、
三层限流、一次一取）与后台投递箱的入库/销毁。加新测试就是往 `test/` 放一个 `.ts`。

> 假 D1 与 Miniflare 都会**照单全收**存储 binding 的选项形状（R2 的分片参数必须嵌在
> `options.range` 里这件事就是这么漏过本地、只在线上炸出来的），所以凡是"某个 binding
> 怎么解释它的参数"这类问题，只能拿部署后的 Worker 验证。

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
