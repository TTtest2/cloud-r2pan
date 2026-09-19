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

---

## 6. 验证

浏览器打开：
```
https://cloud-r2pan.<你的账号>.workers.dev/admin
```
用第 4 步设置的 `admin` 密码登录。

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
