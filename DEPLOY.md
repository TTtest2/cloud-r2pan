# 部署步骤

> 本仓库的 `wrangler.jsonc` 已经声明了 `db` / `r2` / `analytics` 三个绑定。
> 于是有两条路：**(A) 照下面在控制台手工建资源并绑定**（控制台配置优先，不会被覆盖）；
> **(B) 只把 D1 的 `database_id` 填进 `wrangler.jsonc`，其余交给 `wrangler deploy`**。
> 二选一即可，别混着来。部署前建议先跑 `npm run typecheck && npm test`。

## 1. 安装依赖 & 登录

```bash
cd cloud-r2pan
npm install
npx wrangler login
```

浏览器弹出 Cloudflare 授权页面，确认完成。

---

## 2. 在 Cloudflare 控制台创建资源

打开 https://dash.cloudflare.com ，确保你已登录。

### 2.1 创建 R2 存储桶

左侧菜单 → **R2** → **Create bucket**
- Bucket name：**cloud-r2pan**
- Region：任意（离你近的）
- 点 **Create bucket**

### 2.2 创建 D1 数据库

左侧菜单 → **D1** → **Create database**
- Database name：**cloud-r2pan**
- Region：任意
- 点 **Create database**

> ⚠️ 创建完会跳转到数据库详情页，**复制页面顶部的 Database ID**（UUID 格式），后面绑定要用。

### 2.3 创建 Worker

左侧菜单 → **Workers & Pages** → **Create** → **Worker**
- Name：**cloud-r2pan**
- Point：**Upload**（上传代码）
- 点 **Deploy**

> 上传代码这一步直接点 Deploy 就行，代码里还没资源绑定，**首次部署会报错 500，是正常的**，后面绑完资源再跑一次就好。

---

## 3. 在 Worker 里绑定资源（**这步是核心**）

进入刚创建的 Worker 详情页 → 顶部切到 **Settings** → 左侧 **Bindings** → 点 **Add binding**

### 3.1 绑定 R2 Bucket

- Variable name：**`r2`**（固定，代码里就叫这个，别改）
- Bucket：选 **cloud-r2pan**

### 3.2 绑定 D1 Database

- Variable name：**`db`**（固定，别改）
- Database：选 **cloud-r2pan**（或直接粘贴第 2.2 步的 Database ID）

---

## 4. 设置 Secret

同一 Worker → **Settings** → 左侧 **Variables and Secrets** → 点 **Add** → 选 **Secret**

| Variable name | Value | 必填 |
|---|---|---|
| `admin` | 你自己设定的管理后台密码（比如 `MyStr0ng!Pass`） | ✅ 必须 |
| `totp_recovery` | 任意字符串，用作 2FA 万能恢复码（忘 Authenticator 时救回） | ❌ 可选 |
| `turnstile_sitekey` | Cloudflare Turnstile 控制台申请 | ❌ 可选 |
| `turnstile_secret` | Cloudflare Turnstile 控制台申请 | ❌ 可选（不配则 Turnstile 整体不生效） |

> Turnstile 申请方式：Cloudflare 左侧菜单 → **Turnstile** → **Add site** → Site name 随便填，Domain 填你最终用的域名（workers.dev 子域或自定义域），拿 Sitekey 和 Secret key。

每加一个 Secret 点 **Save**。

> ⚠️ **一定要用 Secret，不要用上面的 Environment variables（文本变量）。**
> 每次部署（包括 Workers Builds 自动构建）都会用配置文件里声明的 `vars`
> **整体覆盖**文本变量；本仓库的 `wrangler.jsonc` 没有声明任何 `vars`，所以放在
> Environment variables 里的 `admin` 会在每次构建后消失，表现就是"管理员账户又被重置了，
> 得去后台重新配"。Secrets 是独立存储、跨部署持久，不会被覆盖。
>
> 加完自检（故意用错密钥，看回哪种错）：
>
> ```bash
> curl -s -X POST https://<你的域名>/api/admin/login \
>   -H 'content-type: application/json' -d '{"key":"wrong-on-purpose"}'
> ```
>
> - 回 `401`（管理密钥错误）→ 生效了。
> - 回 `500` 且提示 `admin is not set` → 没读到，多半是放成了文本变量或名字不对。
> - 下次自动构建跑完再执行一次同样的命令：仍回 `401` 才算真的稳。

---

## 5. 正式部署

```bash
npm run deploy
```

输出会显示 `Uploaded...` 和最终地址，类似：
```
https://cloud-r2pan.<你的账号>.workers.dev
```

部署完成后，数据库会在用户首次访问时**自动建表**，不需要手动 SQL。

> 用 `wrangler deploy` 走命令行时，`wrangler.jsonc` 里的 `database_id` 必须填真实值
> （仓库里留空是为了不泄露你的 D1 id）；Workers Builds 走控制台绑定，不受这个空值影响。

---

## 6. 验证

浏览器打开：
```
https://cloud-r2pan.<你的账号>.workers.dev/admin
```
用第 4 步设置的 `admin` 密码登录。

不想开浏览器也可以直接探接口（错密钥应当 401，不是 500 —— 500 说明 `admin` Secret 没设上）：

```bash
curl -i -X POST https://<你的域名>/api/admin/login -H 'content-type: application/json' -d '{"key":"随便乱写"}'
```

这一批改动上线后值得逐项确认（都在后台里点得到）：

| 检查 | 期望 |
|---|---|
| 文件列表搜索框 + 分页 | 输入关键字能过滤、翻页不重画全表 |
| 回收站 | 删除文件 → 切到"回收站"能看到 → 恢复 → 原分享链接又能下 |
| 定时清理 | 后台"回收站"页点"立即运行定时清理"，返回一份 JSON 报告；`npx wrangler deployments status` 里 cron 已注册 |
| 分片上传 | 传一个 >64 MB 的文件，进度条按片推进且最终成功 |
| 秒传 | 同一个文件再传一次，提示"内容已存在，未重复占用存储"，概览的已用存储不翻倍 |
| 目录分享 | 选中目录点"分享目录"，打开链接能进子目录、能逐个下载 |
| 内联预览 | 分享页/后台里图片、PDF、音视频出现"预览"按钮，新标签页直接显示 |
| 取件码投递 | 开 `/pickup`，拖一个文件投进去 → 拿到 8 位码 → 换无痕窗口输入码（大小写随意）能取到并下载 |
| 投递箱 | 后台"投递箱"能看到这件（来源 IP、已取次数）；点"查看取件码"才显示，"入库"后码立即失效 |
| 一次一取 | 勾选"一次一取"投一件，对方第二次取应当显示"取件码无效" |

> 自查注意：`max_downloads_per_ip` 与"重复下载自动封禁"是按 **分享/直链/取件码 + IP**
> 计数的，自己连点几次同一枚码就会把出口 IP 写进 `banned_ips`（默认 24 小时）。
> 测完记得在后台"封禁"里解掉，或者每次换一个新建的投递/分享。

线上确认 cron 是否注册：

```bash
npx wrangler deployments status   # 看当前版本
npx wrangler tail                 # 整点后应当看到 [cron] cleanup {...} 一行
```

---

## 本地开发

```bash
echo 'admin=本地测试密码' > .dev.vars
npm run dev
```

访问 http://localhost:8787/admin 。本地 R2/D1 由 Miniflare 模拟，不会写真实数据。

---

## 查看日志

```bash
npm run tail
```

实时流式线上日志，排查报错用。
