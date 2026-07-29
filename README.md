# DNSPod MCP on Cloudflare Workers

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-green.svg)](https://modelcontextprotocol.io)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://workers.cloudflare.com)

把 **腾讯云 DNSPod** 变成可在线访问的 **MCP（Model Context Protocol）** 服务，跑在 **Cloudflare Workers** 上。

一条 Worker 同时提供：

- **Streamable HTTP / SSE** MCP 端点（给 Grok、Claude、Cursor 等远程连接）
- **OAuth 2.1 + PKCE** 授权（动态客户端注册、登录页、JWT Access Token）
- 调用 DNSPod OpenAPI（域名 / 记录 / 解析量统计）

> 官方 `mcp-server-dnspod` 只支持本地 stdio。本项目把它变成 **公网 HTTPS MCP**，适合 Grok Connectors 等网页端。

---

## 为什么需要它？

| 方式 | 问题 |
| --- | --- |
| 官方 pip `mcp-server-dnspod` | 仅 stdio，本地进程；网页端 Grok 连不上 |
| 直接把 Secret 塞进客户端 | 密钥泄露风险高，且很多客户端不支持 Bearer 字段 |
| **本项目** | Workers 托管 + OAuth 弹窗登录 + 密钥只存在 Cloudflare Secrets |

---

## 架构

```text
Grok / Claude / Cursor
        │  HTTPS  MCP Streamable HTTP
        ▼
Cloudflare Worker  (dnspod-mcp)
  ├── /.well-known/oauth-authorization-server
  ├── /register          动态客户端注册
  ├── /authorize         登录页（OAUTH_PASSWORD）
  ├── /token             code + PKCE → JWT
  └── /mcp               需 Bearer access_token
            │
            │  TC3-HMAC-SHA256
            ▼
     DNSPod OpenAPI (dnspod.tencentcloudapi.com)
```

---

## 功能 / Tools

| Tool | 对应 API | 说明 |
| --- | --- | --- |
| `describe_domain_list` | DescribeDomainList | 域名列表 |
| `create_domain` | CreateDomain | 添加域名 |
| `describe_domain` | DescribeDomain | 域名详情 |
| `describe_record_list` | DescribeRecordList | 解析记录列表 |
| `create_record` | CreateRecord | **新增记录**（官方 MCP 没有） |
| `modify_record` | ModifyRecord | **修改记录** |
| `delete_record` | DeleteRecord | **删除记录** |
| `describe_domain_analytics` | DescribeDomainAnalytics | 域名解析量 |
| `describe_subdomain_analytics` | DescribeSubdomainAnalytics | 子域名解析量 |

与官方 `mcp-server-dnspod` 对比：覆盖其主要查询能力，并额外支持记录增删改；官方的线路查询接口（`DescribeRecordLineList` 等）尚未接入。

---

## 快速部署

### 1. 准备

- Cloudflare 账号
- 腾讯云 [API 密钥](https://console.cloud.tencent.com/cam/capi)（SecretId / SecretKey）
- Node.js ≥ 18

### 2. 克隆 & 安装

```bash
git clone https://github.com/zfx-t/dnspod-mcp-workers.git
cd dnspod-mcp-workers
npm install
```

### 3. 创建 KV（OAuth 存储）

```bash
npx wrangler kv namespace create dnspod-mcp-oauth
```

把返回的 `id` 填进 [`wrangler.toml`](wrangler.toml) 的 `[[kv_namespaces]]`。

### 4. 配置 Secrets

```bash
npx wrangler secret put TENCENTCLOUD_SECRET_ID
npx wrangler secret put TENCENTCLOUD_SECRET_KEY
npx wrangler secret put OAUTH_PASSWORD          # 授权页访问密码
npx wrangler secret put OAUTH_JWT_SECRET        # 随机长字符串
```

可选：`TENCENTCLOUD_REGION`（默认 `ap-guangzhou`，已在 `wrangler.toml` vars）。

### 5. 部署

```bash
npx wrangler deploy
```

得到类似：

```text
https://dnspod-mcp.<your-subdomain>.workers.dev
```

自定义域名（可选）：

```bash
# 在 Cloudflare Dashboard → Workers → dnspod-mcp → Triggers → Custom Domains
# 或使用 wrangler domains / 路由绑定
```

### 6. 本地开发

```bash
cp .env.example .dev.vars   # 填入真实密钥（勿提交）
npx wrangler dev
```

---

## 接入 Grok Connectors

1. 打开 Grok → Connectors → Custom  
2. **URL 只填：**

```text
https://<your-worker-host>/mcp
```

3. 保存后触发连接 → 浏览器打开授权页  
4. 输入 **`OAUTH_PASSWORD`** → 授权  
5. 回到 Grok，即可调用 DNS 工具  

> Grok 不支持手填 Bearer 时，本项目的 OAuth 弹窗就是为此设计的。

### 其它客户端

任何支持 **Remote MCP + OAuth 2.1（PKCE）** 的客户端都可连接同一 URL。

手动调试：

```bash
# 元数据
curl https://<host>/.well-known/oauth-authorization-server

# 未授权应 401 + WWW-Authenticate
curl -i -X POST https://<host>/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

---

## HTTP 路由一览

| 路径 | 说明 |
| --- | --- |
| `GET /` | 说明页 |
| `GET /health` | 健康检查 |
| `GET /.well-known/oauth-authorization-server` | OAuth AS 元数据 |
| `GET /.well-known/oauth-protected-resource` | Protected Resource 元数据 |
| `POST /register` | 动态客户端注册（RFC 7591） |
| `GET/POST /authorize` | 授权码 + 密码登录 |
| `POST /token` | code / refresh → access_token |
| `POST /mcp` | MCP Streamable HTTP（需 Bearer） |
| `GET /sse` | 兼容 SSE 传输（需 Bearer） |

---

## 安全说明

- **腾讯云密钥** 只存在 Cloudflare Secrets，不会出现在客户端配置里  
- **OAuth 访问密码** 仅在浏览器授权页输入，不写进 Connector  
- Access Token 默认 **1 小时**，Refresh Token **30 天**  
- 建议：生产环境使用强随机 `OAUTH_PASSWORD` / `OAUTH_JWT_SECRET`，并限制腾讯云子账号仅 DNSPod 权限  
- **不要** 把 `.dev.vars`、真实 Secret 提交到 Git  

---

## 与官方 DNSPod MCP 的关系

- 官方包：`pip install mcp-server-dnspod`（stdio，适合 Claude Desktop 本地）  
- 本仓库：Cloudflare Workers **远程** MCP，OAuth 网关 + 部分写操作增强  
- API 签名：TC3-HMAC-SHA256，与腾讯云 OpenAPI 一致  

---

## 开发

单文件 Worker，无运行时依赖：

```text
src/index.js      # MCP + OAuth + DNSPod 客户端
wrangler.toml     # 部署配置
```

欢迎 PR：补齐线路查询工具、支持更多 DNSPod API、接入 Cloudflare Access 等。

---

## License

[MIT](LICENSE)

---

## 致谢

- [Model Context Protocol](https://modelcontextprotocol.io)
- [Tencent Cloud DNSPod API](https://cloud.tencent.com/document/product/1427)
- [Cloudflare Workers](https://workers.cloudflare.com)
- 官方 [mcp-server-dnspod](https://cloud.tencent.com/developer/mcp/server/11743)
