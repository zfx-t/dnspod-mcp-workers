/**
 * DNSPod MCP + OAuth 2.1 (PKCE, dynamic client registration)
 * For Grok Connectors: paste https://<your-domain>/mcp only.
 * Secrets: OAUTH_PASSWORD, OAUTH_JWT_SECRET, TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY
 * Binding: OAUTH_KV (KV namespace)
 */

const SERVER = {
  name: "dnspod-mcp",
  version: "2.3.0",
  title: "DNSPod MCP — Tencent Cloud DNS",
  description:
    "腾讯云 DNSPod 远程 MCP 服务：通过 Streamable HTTP + OAuth 2.1 管理权威 DNS。" +
    "Remote MCP for Tencent Cloud DNSPod — manage domains & DNS records, query analytics.\n\n" +
    "能力 / Capabilities:\n" +
    "• 域名：列表 / 添加 / 详情（describe_domain_list, create_domain, describe_domain）\n" +
    "• 解析记录：列表 / 新增 / 修改 / 删除（A AAAA CNAME MX TXT NS SRV CAA 等）\n" +
    "• 解析量统计：整域 / 子域名（DATE 或 HOUR 粒度）\n\n" +
    "安全 / Security: 腾讯云 SecretId/Key 仅存于 Cloudflare Worker Secrets，客户端只走 OAuth。" +
    "适合 Grok Connectors、Claude 等远程 MCP 客户端。",
};
const MCP_PROTOCOL = "2025-03-26";
const ACCESS_TTL = 3600;
const REFRESH_TTL = 30 * 24 * 3600;
const CODE_TTL = 600;

// ---------- crypto ----------
function b64url(bytes) {
  let s;
  if (typeof bytes === "string") s = btoa(bytes);
  else {
    let bin = "";
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
    s = btoa(bin);
  }
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(obj) {
  return b64url(new TextEncoder().encode(JSON.stringify(obj)));
}
async function randomToken(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return b64url(buf);
}
async function sha256b64url(str) {
  const dig = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return b64url(new Uint8Array(dig));
}
async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
async function signJwt(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const body = b64urlJson(header) + "." + b64urlJson(payload);
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  return body + "." + b64url(new Uint8Array(sig));
}
async function verifyJwt(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const key = await hmacKey(secret);
  const data = parts[0] + "." + parts[1];
  const sig = parts[2].replace(/-/g, "+").replace(/_/g, "/");
  const pad = sig + "===".slice((sig.length + 3) % 4);
  const sigBytes = Uint8Array.from(atob(pad), (c) => c.charCodeAt(0));
  const ok = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
  if (!ok) return null;
  try {
    const payload = JSON.parse(
      new TextDecoder().decode(
        Uint8Array.from(
          atob(parts[1].replace(/-/g, "+").replace(/_/g, "/") + "===".slice((parts[1].length + 3) % 4)),
          (c) => c.charCodeAt(0)
        )
      )
    );
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------- Tencent DNSPod ----------
async function hmacSha256(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? new TextEncoder().encode(key) : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message)));
}
async function sha256Hex(message) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(message));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const toHex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

function stripUndefined(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (v !== undefined && v !== null && v !== "") out[k] = v;
  }
  return out;
}

async function tencentRequest(env, action, payload = {}) {
  const secretId = env.TENCENTCLOUD_SECRET_ID;
  const secretKey = env.TENCENTCLOUD_SECRET_KEY;
  if (!secretId || !secretKey) throw new Error("Missing TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY");
  const service = "dnspod";
  const host = "dnspod.tencentcloudapi.com";
  const region = env.TENCENTCLOUD_REGION || "ap-guangzhou";
  const version = "2021-03-23";
  const ts = Math.floor(Date.now() / 1000);
  const date = new Date(ts * 1000).toISOString().slice(0, 10);
  const body = JSON.stringify(stripUndefined(payload));
  const hp = await sha256Hex(body);
  const ch = `content-type:application/json; charset=utf-8\nhost:${host}\nx-tc-action:${action.toLowerCase()}\n`;
  const shd = "content-type;host;x-tc-action";
  const cr = ["POST", "/", "", ch, shd, hp].join("\n");
  const scope = `${date}/${service}/tc3_request`;
  const sts = ["TC3-HMAC-SHA256", String(ts), scope, await sha256Hex(cr)].join("\n");
  const kDate = await hmacSha256("TC3" + secretKey, date);
  const kSvc = await hmacSha256(kDate, service);
  const kSign = await hmacSha256(kSvc, "tc3_request");
  const sig = toHex(await hmacSha256(kSign, sts));
  const authorization = `TC3-HMAC-SHA256 Credential=${secretId}/${scope}, SignedHeaders=${shd}, Signature=${sig}`;
  const res = await fetch(`https://${host}/`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Host: host,
      "X-TC-Action": action,
      "X-TC-Timestamp": String(ts),
      "X-TC-Version": version,
      "X-TC-Region": region,
      Authorization: authorization,
    },
    body,
  });
  const data = await res.json();
  if (data.Response?.Error) throw new Error(data.Response.Error.Code + ": " + data.Response.Error.Message);
  return data.Response;
}

/**
 * Rich tool definitions for MCP clients (Grok / Claude / Cursor).
 * Each tool description is written for LLM tool-selection: what / when / not-when /
 * prerequisites / side-effects / returns / examples / API mapping.
 * Parameter descriptions are bilingual and include units, enums, and pitfalls.
 */
const TOOLS = [
  {
    name: "describe_domain_list",
    title: "列出 DNS 域名 / List domains",
    description:
      "【作用】查询当前腾讯云账号在 DNSPod 中托管的域名列表（权威 DNS 域名库存）。\n" +
      "[What] List all DNS domains hosted on DNSPod for this Tencent Cloud account.\n\n" +
      "【何时用 / When】\n" +
      "• 用户问：我有哪些域名、域名列表、DomainId、套餐等级、解析条数、NS 是什么\n" +
      "• 后续要增删改记录但还不知道 Domain / DomainId 时，先调本工具\n" +
      "• 按关键字搜索域名（Keyword）或分页浏览\n\n" +
      "【不要用 / Do not use】\n" +
      "• 查某域名下的解析记录 → describe_record_list\n" +
      "• 只要某一个域名的深度详情 → describe_domain\n\n" +
      "【返回要点 / Returns】DomainList[]：Name, DomainId, Status(ENABLE/…), Grade/GradeTitle(套餐),\n" +
      "RecordCount, IsVip, TTL, EffectiveDNS(NS), CreatedOn, UpdatedOn；以及 DomainCountInfo 汇总计数。\n\n" +
      "【示例 / Examples】\n" +
      '1) 全部：{} 或 { "Type": "ALL", "Limit": 20 }\n' +
      '2) 搜索：{ "Keyword": "zfxt", "Type": "ALL" }\n' +
      '3) 仅付费：{ "Type": "VIP" }\n' +
      '4) 第 2 页：{ "Offset": 20, "Limit": 20 }\n\n' +
      "API: DescribeDomainList (dnspod 2021-03-23). 只读、无副作用。",
    inputSchema: {
      type: "object",
      properties: {
        Type: {
          type: "string",
          description:
            "域名分组过滤 / Domain group filter。默认 ALL。\n" +
            "枚举：ALL=全部 | MINE=我的 | SHARE=共享给我 | ISMARK=星标 | PAUSE=暂停 |\n" +
            "VIP=付费 | RECENT=最近操作 | SHARE_OUT=我共享出 | FREE=免费。",
          enum: ["ALL", "MINE", "SHARE", "ISMARK", "PAUSE", "VIP", "RECENT", "SHARE_OUT", "FREE"],
          default: "ALL",
        },
        Offset: {
          type: "integer",
          description: "分页偏移（从 0 开始）/ Pagination offset, 0-based. 默认 0。",
          minimum: 0,
          default: 0,
        },
        Limit: {
          type: "integer",
          description: "每页条数 / Page size。默认 20，最大 100。",
          minimum: 1,
          maximum: 100,
          default: 20,
        },
        GroupId: {
          type: "integer",
          description: "可选。只返回该 DNSPod 域名分组 ID 内的域名 / Optional domain group ID filter.",
        },
        Keyword: {
          type: "string",
          description:
            "按域名关键字模糊搜索 / Fuzzy search on domain name。如 zfxt、example.com。可与 Type 联用。",
        },
      },
      additionalProperties: false,
    },
    annotations: {
      title: "List DNS domains",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: "create_domain",
    title: "添加域名到 DNSPod / Add domain",
    description:
      "【作用】在 DNSPod 中添加一个待托管的主域名（把域名加入 DNSPod 权威解析管理）。\n" +
      "[What] Register an apex domain into DNSPod management (not domain-name registration purchase).\n\n" +
      "【何时用 / When】\n" +
      "• 用户说：把 example.com 加到 DNSPod、创建/添加域名、开始用 DNSPod 解析某域名\n\n" +
      "【重要 / Important】\n" +
      "1) 这不是在注册商处「购买域名」，只是 DNSPod 侧托管配置。\n" +
      "2) 全网生效还需在注册商把 NS 改成接口返回的 DNSPod 服务器（如 *.dnspod.net）。\n" +
      "3) 只传主域名（apex）：example.com / zfxt.top。不要带 http://、路径、www 或子域名。\n" +
      "4) 域名已被他人添加或已存在时会报错。\n\n" +
      "【返回】新域名 DomainId 及元数据。\n" +
      '【示例】{ "Domain": "example.com" }\n\n' +
      "API: CreateDomain. 有副作用（创建域名对象）。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description:
            "要添加的主域名 / Apex domain only。示例：example.com、zfxt.top。禁止 scheme、路径、端口、子域前缀。",
        },
        GroupId: {
          type: "integer",
          description: "可选。加入指定域名分组 ID / Optional group ID to place the domain into.",
        },
      },
      required: ["Domain"],
      additionalProperties: false,
    },
    annotations: {
      title: "Add domain",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: "describe_domain",
    title: "域名详情 / Domain details",
    description:
      "【作用】查询单个域名的详细状态：是否启用、套餐、NS、记录数、VIP、默认 TTL、创建/更新时间等。\n" +
      "[What] Get deep details for one domain (status, plan, NS, counts, VIP, TTL defaults, timestamps).\n\n" +
      "【何时用 / When】\n" +
      "• 用户问某个具体域名是否启用、用什么套餐、NS 是什么、DomainId 是多少\n" +
      "• 已有明确域名，不需要整表列表时优先本工具（比 describe_domain_list 更聚焦）\n\n" +
      "【参数】Domain 或 DomainId 至少一个；两者都传时 DomainId 优先。\n" +
      '【示例】{ "Domain": "zfxt.top" }\n\n' +
      "API: DescribeDomain. 只读。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "主域名 / Apex domain name，如 zfxt.top。",
        },
        DomainId: {
          type: "integer",
          description:
            "域名数字 ID（来自 describe_domain_list）/ Numeric DomainId. 与 Domain 同传时优先使用 DomainId。",
        },
      },
      additionalProperties: false,
    },
    annotations: {
      title: "Get domain details",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: "describe_record_list",
    title: "解析记录列表 / List DNS records",
    description:
      "【作用】列出指定域名下的 DNS 资源记录（A/AAAA/CNAME/MX/TXT/NS/SRV/CAA/显性URL/隐性URL 等）。\n" +
      "[What] List DNS resource records under one domain; primary way to obtain RecordId.\n\n" +
      "【何时用 / When】\n" +
      "• 用户问：有哪些解析、www 指到哪、列出 TXT/MX、某 IP 对应哪条记录\n" +
      "• 在 modify_record 或 delete_record 之前必须先调用，以获取并核对 RecordId\n\n" +
      "【过滤 / Filters】\n" +
      "• Subdomain：主机记录，如 www / @ / * / mail（不要写 FQDN）\n" +
      "• RecordType：A、AAAA、CNAME、MX、TXT…\n" +
      "• RecordLine / RecordLineId：线路（默认、电信…）\n" +
      "• Keyword：搜主机头或记录值；Offset/Limit/SortField/SortType 分页排序\n\n" +
      "【返回要点】RecordList[]：RecordId, Name(主机), Type, Value, Line, LineId, TTL, MX, Weight, Status, UpdatedOn, Remark。\n\n" +
      "【示例】\n" +
      '{ "Domain": "zfxt.top" }\n' +
      '{ "Domain": "zfxt.top", "Subdomain": "www", "RecordType": "A" }\n' +
      '{ "Domain": "zfxt.top", "RecordType": "TXT" }\n' +
      '{ "Domain": "zfxt.top", "Keyword": "1.2.3" }\n\n' +
      "API: DescribeRecordList. 只读。改删记录前的必经步骤。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "主域名 / Apex domain，如 zfxt.top。一般必填（或用 DomainId）。",
        },
        DomainId: {
          type: "integer",
          description: "域名 ID；若提供则优先于 Domain / DomainId preferred over Domain.",
        },
        Subdomain: {
          type: "string",
          description:
            "主机记录过滤 / Host label filter only。填 www、@、*、mail，不要填 www.zfxt.top。省略则返回全部主机。",
        },
        RecordType: {
          type: "string",
          description:
            "记录类型过滤 / Type filter：A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, 显性URL, 隐性URL 等。",
        },
        RecordLine: {
          type: "string",
          description:
            "线路中文名过滤 / Chinese line name：默认, 电信, 联通, 移动, 境外 等。",
        },
        RecordLineId: {
          type: "string",
          description:
            "线路 ID（如 0、10=1）。与 RecordLine 同传时优先 RecordLineId / Line ID overrides RecordLine.",
        },
        Keyword: {
          type: "string",
          description: "关键字，匹配主机头或记录值 / Search host name or record value.",
        },
        SortField: {
          type: "string",
          description: "排序字段：name, line, type, value, weight, mx, ttl, updated_on。",
        },
        SortType: {
          type: "string",
          description: "排序方向 ASC 或 DESC，默认 ASC。",
          enum: ["ASC", "DESC"],
          default: "ASC",
        },
        Offset: {
          type: "integer",
          description: "分页偏移，默认 0。",
          minimum: 0,
          default: 0,
        },
        Limit: {
          type: "integer",
          description: "返回条数，默认 100，最大约 3000。",
          minimum: 1,
          maximum: 3000,
          default: 100,
        },
      },
      required: ["Domain"],
      additionalProperties: false,
    },
    annotations: {
      title: "List DNS records",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: "create_record",
    title: "新增解析记录 / Create DNS record",
    description:
      "【作用】为域名新增一条 DNS 解析记录（A/AAAA/CNAME/MX/TXT/NS/SRV/CAA 等）。\n" +
      "[What] Create one DNS resource record under a domain. Returns new RecordId.\n\n" +
      "【何时用 / When】\n" +
      "• 用户说：加一条 A 记录、www 指到 IP、添加 CNAME/TXT/MX/AAAA、做邮箱/验证 TXT\n\n" +
      "【硬规则 / Rules】\n" +
      "1) SubDomain 只写主机头：@（根域名）、www、*、mail、api — 禁止 FQDN\n" +
      "2) RecordLine 默认「默认」；免费套餐通常只能用默认线路\n" +
      "3) MX 类型必须传 MX 优先级（整数，越小越优先，常见 1–20）\n" +
      "4) Value 格式：A=IPv4；AAAA=IPv6；CNAME/MX/NS=主机名（建议以 . 结尾）；TXT=原文\n" +
      "5) TTL 单位秒；免费套餐常见 600（允许范围依套餐，如 60–604800）\n" +
      "6) 生效时间取决于 TTL 与各地缓存，不是接口返回即全球立即刷新\n\n" +
      "【示例】\n" +
      'A: { "Domain": "zfxt.top", "SubDomain": "www", "RecordType": "A", "Value": "1.2.3.4", "TTL": 600 }\n' +
      '根域 A: { "Domain": "zfxt.top", "SubDomain": "@", "RecordType": "A", "Value": "1.2.3.4" }\n' +
      'CNAME: { "Domain": "zfxt.top", "SubDomain": "blog", "RecordType": "CNAME", "Value": "xxx.github.io." }\n' +
      'TXT: { "Domain": "zfxt.top", "SubDomain": "@", "RecordType": "TXT", "Value": "v=spf1 include:_spf.google.com ~all" }\n' +
      'MX: { "Domain": "zfxt.top", "SubDomain": "@", "RecordType": "MX", "Value": "mx.example.com.", "MX": 10 }\n' +
      'AAAA: { "Domain": "zfxt.top", "SubDomain": "@", "RecordType": "AAAA", "Value": "2400:3200::1" }\n\n' +
      "API: CreateRecord. 有副作用（DNS 变更）。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "主域名 / Apex domain，如 zfxt.top。",
        },
        DomainId: {
          type: "integer",
          description: "可选域名 ID；与 Domain 同传时优先 DomainId。",
        },
        SubDomain: {
          type: "string",
          description:
            "主机记录 / Host label。@ = 根域名，www = www.域名，* = 泛解析。禁止传完整 FQDN。",
        },
        RecordType: {
          type: "string",
          description: "记录类型 / Type：A, AAAA, CNAME, MX, TXT, NS, SRV, CAA 等。",
        },
        RecordLine: {
          type: "string",
          description:
            "解析线路中文名 / Line name。默认「默认」。常见：默认, 电信, 联通, 移动, 境外。免费版多用默认。",
          default: "默认",
        },
        RecordLineId: {
          type: "string",
          description: "线路 ID；提供时优先于 RecordLine / Line ID overrides RecordLine.",
        },
        Value: {
          type: "string",
          description:
            "记录值 / Value。A=IPv4；AAAA=IPv6；CNAME/MX/NS=目标主机名(建议以.结尾)；TXT=文本；SRV 按规范格式。",
        },
        TTL: {
          type: "integer",
          description: "TTL（秒）/ TTL in seconds。免费套餐常见 600。",
          minimum: 1,
        },
        MX: {
          type: "integer",
          description: "MX 优先级（仅 MX 类型需要）/ MX priority required for MX. 越小越优先，常见 1–20。",
          minimum: 0,
          maximum: 50,
        },
        Weight: {
          type: "integer",
          description: "可选权重（部分套餐支持加权轮询）/ Optional weight 0–100.",
          minimum: 0,
          maximum: 100,
        },
        Remark: {
          type: "string",
          description: "可选备注 / Optional remark string.",
        },
      },
      required: ["Domain", "SubDomain", "RecordType", "Value"],
      additionalProperties: false,
    },
    annotations: {
      title: "Create DNS record",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: "modify_record",
    title: "修改解析记录 / Update DNS record",
    description:
      "【作用】修改已存在的一条 DNS 记录。必须提供 RecordId。\n" +
      "[What] Update an existing DNS record. RecordId is REQUIRED.\n\n" +
      "【何时用 / When】\n" +
      "• 用户要改 IP、改 CNAME 目标、改 TTL、改主机头、改线路、改 MX 优先级\n\n" +
      "【推荐流程 / Workflow】\n" +
      "1) describe_record_list → 找到正确的 RecordId 及当前 Type/Value/Line/SubDomain\n" +
      "2) 再调 modify_record，带上修改后的完整必填字段\n" +
      "3) 必填：Domain, RecordId, SubDomain, RecordType, Value；RecordLine 默认「默认」\n\n" +
      "【不要用】新建记录用 create_record；删除用 delete_record。\n\n" +
      "【示例】\n" +
      '{ "Domain": "zfxt.top", "RecordId": 123456789, "SubDomain": "www", "RecordType": "A", "RecordLine": "默认", "Value": "5.6.7.8", "TTL": 600 }\n\n' +
      "API: ModifyRecord. 有副作用（DNS 变更）。同一 RecordId 重复提交相同内容可视为幂等。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "主域名 / Apex domain，如 zfxt.top。",
        },
        DomainId: {
          type: "integer",
          description: "可选域名 ID / Optional DomainId.",
        },
        RecordId: {
          type: "integer",
          description:
            "要修改的记录 ID（必填，来自 describe_record_list）/ Target RecordId from list API. Required.",
        },
        SubDomain: {
          type: "string",
          description: "修改后的主机记录 / Host label after change，如 www 或 @。",
        },
        RecordType: {
          type: "string",
          description: "修改后的类型 / Type after change：A, AAAA, CNAME, MX, TXT 等。",
        },
        RecordLine: {
          type: "string",
          description: "线路中文名，默认「默认」/ Line name, default 默认.",
          default: "默认",
        },
        RecordLineId: {
          type: "string",
          description: "线路 ID，优先于 RecordLine / Line ID preferred over RecordLine.",
        },
        Value: {
          type: "string",
          description: "新的记录值 / New value（IP、CNAME 目标、TXT 文本等）。",
        },
        TTL: {
          type: "integer",
          description: "TTL（秒）/ TTL in seconds.",
          minimum: 1,
        },
        MX: {
          type: "integer",
          description: "MX 优先级；当 RecordType=MX 时必填 / MX priority when type is MX.",
        },
        Weight: {
          type: "integer",
          description: "可选权重 / Optional weight.",
        },
        Remark: {
          type: "string",
          description: "可选备注 / Optional remark.",
        },
      },
      required: ["Domain", "RecordId", "SubDomain", "RecordType", "Value"],
      additionalProperties: false,
    },
    annotations: {
      title: "Update DNS record",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: "delete_record",
    title: "删除解析记录 / Delete DNS record",
    description:
      "【作用】按 RecordId 永久删除一条 DNS 解析记录（不可恢复）。\n" +
      "[What] Permanently delete one DNS record by RecordId. Destructive, not undoable via this tool.\n\n" +
      "【何时用 / When】\n" +
      "• 用户明确要求删除某条解析、去掉某主机头的 A/CNAME/TXT 等\n\n" +
      "【安全 / Safety】\n" +
      "1) 必须先 describe_record_list，核对 RecordId + 主机头 + 类型 + 记录值\n" +
      "2) 禁止猜测 RecordId\n" +
      "3) 删除 @ 根记录、MX、关键 NS/验证 TXT 可能导致网站/邮箱/证书验证失败——有歧义时先向用户确认\n\n" +
      '【示例】{ "Domain": "zfxt.top", "RecordId": 123456789 }\n\n' +
      "API: DeleteRecord. 破坏性副作用。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "主域名 / Apex domain。",
        },
        DomainId: {
          type: "integer",
          description: "可选域名 ID / Optional DomainId.",
        },
        RecordId: {
          type: "integer",
          description: "要删除的记录 ID（必填）/ RecordId to delete. Required.",
        },
      },
      required: ["Domain", "RecordId"],
      additionalProperties: false,
    },
    annotations: {
      title: "Delete DNS record",
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: "describe_domain_analytics",
    title: "域名解析量统计 / Domain analytics",
    description:
      "【作用】查询整个域名在指定日期范围内的 DNS 解析请求量统计（按天或按小时）。\n" +
      "[What] DNS query volume analytics for a whole domain over a date range.\n\n" +
      "【何时用 / When】\n" +
      "• 用户问：这个域名解析量多少、最近访问/查询量、按天/小时流量\n" +
      "• 需要整域合计时用本工具；若只要某一个主机头 → describe_subdomain_analytics\n\n" +
      "【参数说明】\n" +
      "• StartDate / EndDate：YYYY-MM-DD（闭区间以 API 为准）\n" +
      "• DnsFormat：DATE=按天聚合，HOUR=按小时聚合（默认 DATE）\n" +
      "• 免费套餐可能限制可查历史长度或粒度\n\n" +
      "【示例】\n" +
      '{ "Domain": "zfxt.top", "StartDate": "2026-07-01", "EndDate": "2026-07-29", "DnsFormat": "DATE" }\n\n' +
      "API: DescribeDomainAnalytics. 只读。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "主域名 / Apex domain。",
        },
        DomainId: {
          type: "integer",
          description: "可选域名 ID，优先于 Domain / Optional DomainId preferred over Domain.",
        },
        StartDate: {
          type: "string",
          description: "开始日期，格式 YYYY-MM-DD / Range start, e.g. 2026-07-01。",
        },
        EndDate: {
          type: "string",
          description: "结束日期，格式 YYYY-MM-DD / Range end, e.g. 2026-07-29。",
        },
        DnsFormat: {
          type: "string",
          description: "统计粒度：DATE=按天，HOUR=按小时。默认 DATE。",
          enum: ["DATE", "HOUR"],
          default: "DATE",
        },
      },
      required: ["Domain", "StartDate", "EndDate"],
      additionalProperties: false,
    },
    annotations: {
      title: "Domain analytics",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
  {
    name: "describe_subdomain_analytics",
    title: "子域名解析量统计 / Subdomain analytics",
    description:
      "【作用】查询指定主机记录（子域名）在日期范围内的 DNS 解析量。\n" +
      "[What] DNS query analytics for one host/subdomain under a domain.\n\n" +
      "【何时用 / When】\n" +
      "• 用户问：www 的解析量、api 子域名请求量、某个主机头的查询统计\n" +
      "• 不要用本工具查整域合计 → 用 describe_domain_analytics\n\n" +
      "【参数说明】\n" +
      "• Subdomain 只填主机头：www / @ / api，不要带主域名后缀（禁止 www.zfxt.top）\n" +
      "• StartDate/EndDate：YYYY-MM-DD；DnsFormat：DATE 或 HOUR\n\n" +
      "【示例】\n" +
      '{ "Domain": "zfxt.top", "Subdomain": "www", "StartDate": "2026-07-01", "EndDate": "2026-07-29", "DnsFormat": "DATE" }\n\n' +
      "API: DescribeSubdomainAnalytics. 只读。",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "主域名 / Apex domain。",
        },
        DomainId: {
          type: "integer",
          description: "可选域名 ID / Optional DomainId.",
        },
        Subdomain: {
          type: "string",
          description:
            "主机记录 / Host label only：www、@、api。禁止写完整 FQDN（不要写 www.zfxt.top）。",
        },
        StartDate: {
          type: "string",
          description: "开始日期 YYYY-MM-DD / Range start.",
        },
        EndDate: {
          type: "string",
          description: "结束日期 YYYY-MM-DD / Range end.",
        },
        DnsFormat: {
          type: "string",
          description: "DATE=按天，HOUR=按小时。默认 DATE。",
          enum: ["DATE", "HOUR"],
          default: "DATE",
        },
      },
      required: ["Domain", "Subdomain", "StartDate", "EndDate"],
      additionalProperties: false,
    },
    annotations: {
      title: "Subdomain analytics",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },
];


async function callTool(env, n, a = {}) {
  const M = {
    describe_domain_list: [
      "DescribeDomainList",
      {
        Type: a.Type || "ALL",
        Offset: a.Offset ?? 0,
        Limit: a.Limit ?? 20,
        GroupId: a.GroupId,
        Keyword: a.Keyword,
        Tags: a.Tags,
      },
    ],
    create_domain: ["CreateDomain", { Domain: a.Domain, GroupId: a.GroupId, TagList: a.TagList || a.Tags }],
    describe_domain: ["DescribeDomain", { Domain: a.Domain, DomainId: a.DomainId }],
    describe_record_list: [
      "DescribeRecordList",
      {
        Domain: a.Domain,
        DomainId: a.DomainId,
        Subdomain: a.Subdomain ?? a.SubDomain,
        RecordType: a.RecordType,
        RecordLine: a.RecordLine,
        RecordLineId: a.RecordLineId,
        GroupId: a.GroupId,
        Keyword: a.Keyword,
        SortField: a.SortField,
        SortType: a.SortType,
        Offset: a.Offset ?? 0,
        Limit: a.Limit ?? 100,
      },
    ],
    create_record: [
      "CreateRecord",
      {
        Domain: a.Domain,
        DomainId: a.DomainId,
        SubDomain: a.SubDomain ?? a.Subdomain,
        RecordType: a.RecordType,
        RecordLine: a.RecordLine || "默认",
        RecordLineId: a.RecordLineId,
        Value: a.Value,
        TTL: a.TTL,
        MX: a.MX,
        Weight: a.Weight,
        Remark: a.Remark,
      },
    ],
    modify_record: [
      "ModifyRecord",
      {
        Domain: a.Domain,
        DomainId: a.DomainId,
        RecordId: a.RecordId,
        SubDomain: a.SubDomain ?? a.Subdomain,
        RecordType: a.RecordType,
        RecordLine: a.RecordLine || "默认",
        RecordLineId: a.RecordLineId,
        Value: a.Value,
        TTL: a.TTL,
        MX: a.MX,
        Weight: a.Weight,
        Remark: a.Remark,
      },
    ],
    delete_record: ["DeleteRecord", { Domain: a.Domain, DomainId: a.DomainId, RecordId: a.RecordId }],
    describe_domain_analytics: [
      "DescribeDomainAnalytics",
      {
        Domain: a.Domain,
        DomainId: a.DomainId,
        StartDate: a.StartDate,
        EndDate: a.EndDate,
        DnsFormat: a.DnsFormat || "DATE",
      },
    ],
    describe_subdomain_analytics: [
      "DescribeSubdomainAnalytics",
      {
        Domain: a.Domain,
        DomainId: a.DomainId,
        Subdomain: a.Subdomain ?? a.SubDomain,
        StartDate: a.StartDate,
        EndDate: a.EndDate,
        DnsFormat: a.DnsFormat || "DATE",
      },
    ],
  };
  const x = M[n];
  if (!x) throw new Error("Unknown tool: " + n);
  return tencentRequest(env, x[0], x[1]);
}

const TR = (o) => ({ content: [{ type: "text", text: typeof o === "string" ? o : JSON.stringify(o, null, 2) }], isError: false });
const ER = (e) => ({ content: [{ type: "text", text: String(e?.message || e) }], isError: true });

async function handleMcp(env, msg) {
  const { id, method, params } = msg;
  if (method?.startsWith("notifications/")) return null;
  try {
    if (method === "initialize") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: params?.protocolVersion || MCP_PROTOCOL,
          capabilities: {
            tools: { listChanged: false },
            logging: {},
          },
          serverInfo: {
            name: SERVER.name,
            version: SERVER.version,
            title: SERVER.title,
            description: SERVER.description,
          },
          instructions:
            "【DNSPod MCP 使用说明 / Agent Instructions】\n" +
            "你已通过 OAuth 连接到腾讯云 DNSPod。用下列工具管理账号下权威 DNS，不要编造解析数据。\n" +
            "\n" +
            "【选工具】\n" +
            "• 有哪些域名 / DomainId / 套餐 → describe_domain_list\n" +
            "• 单个域名状态/NS → describe_domain\n" +
            "• 查解析、找 RecordId → describe_record_list（改/删前必调）\n" +
            "• 加解析 → create_record；改解析 → modify_record；删解析 → delete_record\n" +
            "• 整域解析量 → describe_domain_analytics；某主机解析量 → describe_subdomain_analytics\n" +
            "\n" +
            "【硬规则】\n" +
            "1) modify_record / delete_record 前必须 describe_record_list 核实 RecordId、主机头、记录值。\n" +
            "2) SubDomain/Subdomain 只填主机记录：@ / www / api / *，禁止 FQDN（不要写 www.example.com）。\n" +
            "3) RecordLine 默认「默认」；免费套餐通常仅支持默认线路。\n" +
            "4) MX 必须带 MX 优先级（数字，越小越优先）；TTL 单位为秒，免费套餐常见 600。\n" +
            "5) create_domain 只在 DNSPod 添加域名，注册商 NS 改到 DNSPod 后才全网生效。\n" +
            "6) 统计日期格式 YYYY-MM-DD；DnsFormat 为 DATE（按天）或 HOUR（按小时）。\n" +
            "7) delete_record 不可恢复；删除 @ / MX / 关键记录前先向用户确认。\n" +
            "8) API 报 AuthFailure/SecretIdNotFound 时说明服务端密钥无效，勿假装查询成功。\n" +
            "底层 API：腾讯云 DNSPod 2021-03-23（TC3-HMAC-SHA256）。",
        },
      };
    }
    if (method === "ping") return { jsonrpc: "2.0", id, result: {} };
    if (method === "tools/list") return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
    if (method === "tools/call") {
      try {
        return { jsonrpc: "2.0", id, result: TR(await callTool(env, params?.name, params?.arguments || {})) };
      } catch (e) {
        return { jsonrpc: "2.0", id, result: ER(e) };
      }
    }
    if (method === "resources/list") return { jsonrpc: "2.0", id, result: { resources: [] } };
    if (method === "prompts/list") return { jsonrpc: "2.0", id, result: { prompts: [] } };
    return { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found: " + method } };
  } catch (e) {
    return { jsonrpc: "2.0", id, error: { code: -32000, message: String(e?.message || e) } };
  }
}

// ---------- helpers ----------
function cors(req) {
  return {
    "Access-Control-Allow-Origin": req.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, Accept, Mcp-Session-Id, Last-Event-ID, mcp-protocol-version",
    "Access-Control-Expose-Headers": "Mcp-Session-Id, WWW-Authenticate",
  };
}
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...extra },
  });
}
function formHtml(error = "") {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Authorize DNSPod MCP</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1020;color:#e8eefc;padding:24px}
.card{max-width:420px;width:100%;background:#121a33;border:1px solid #243056;border-radius:16px;padding:28px}
h1{margin:0 0 8px;font-size:1.25rem}
p{color:#a9b6d6;line-height:1.5;font-size:.95rem}
label{display:block;margin:16px 0 6px;font-size:.85rem;color:#c5d0ea}
input{width:100%;box-sizing:border-box;padding:12px 14px;border-radius:10px;border:1px solid #243056;background:#0b1226;color:#e8eefc}
button{margin-top:18px;width:100%;padding:12px;border:0;border-radius:10px;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
.err{color:#fca5a5;margin-top:12px}
.meta{font-size:.8rem;color:#7a89ad;margin-top:16px}
</style></head><body>
<div class="card">
  <h1>授权 DNSPod MCP</h1>
  <p>客户端请求访问你的 DNSPod 管理工具（域名列表、解析增删改、解析量统计）。输入访问密码以继续 OAuth 授权。</p>
  ${error ? `<p class="err">${error}</p>` : ""}
  <form method="POST">
    <label for="password">访问密码</label>
    <input id="password" name="password" type="password" required autocomplete="current-password" autofocus/>
    <button type="submit">授权连接</button>
  </form>
  <p class="meta">授权后返回客户端。腾讯云 Secret 不会暴露给客户端。</p>
</div>
</body></html>`;
}

function issuerFrom(url) {
  return url.origin;
}

function asMeta(issuer) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256", "plain"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    scopes_supported: ["mcp", "openid"],
    service_documentation: issuer + "/",
    ui_locales_supported: ["zh-CN", "en"],
  };
}

async function requireAccess(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  if (token.split(".").length === 3) {
    const secret = env.OAUTH_JWT_SECRET || env.OAUTH_PASSWORD || "change-me";
    return verifyJwt(token, secret);
  }
  if (env.OAUTH_KV) {
    const raw = await env.OAUTH_KV.get("at:" + token, "json");
    if (!raw) return null;
    if (raw.exp && raw.exp < Math.floor(Date.now() / 1000)) {
      await env.OAUTH_KV.delete("at:" + token);
      return null;
    }
    return raw;
  }
  return null;
}

function unauthorized(req, issuer) {
  return json(
    { error: "invalid_token", error_description: "Authentication required" },
    401,
    {
      ...cors(req),
      "WWW-Authenticate": `Bearer realm="dnspod-mcp", resource_metadata="${issuer}/.well-known/oauth-protected-resource"`,
      "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id",
    }
  );
}

function homeHtml(issuer) {
  const tools = TOOLS.map((t) => {
    const first = String(t.description || "").split("\n")[0];
    const second = String(t.description || "").split("\n")[1] || "";
    const req = (t.inputSchema?.required || []).join(", ") || "—";
    const props = Object.keys(t.inputSchema?.properties || {}).join(", ") || "—";
    const flags = [];
    if (t.annotations?.readOnlyHint) flags.push("read-only");
    if (t.annotations?.destructiveHint) flags.push("destructive");
    if (t.annotations?.idempotentHint) flags.push("idempotent");
    return (
      `<li class="tool">` +
      `<div class="tool-head"><strong>${t.name}</strong>` +
      (t.title ? ` <span class="t">${t.title}</span>` : "") +
      (flags.length ? ` <span class="flags">${flags.join(" · ")}</span>` : "") +
      `</div>` +
      `<p class="d">${first}</p>` +
      (second ? `<p class="d2">${second}</p>` : "") +
      `<p class="meta">required: <code>${req}</code> · params: <code>${props}</code></p>` +
      `</li>`
    );
  }).join("");
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DNSPod MCP</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif}
body{margin:0;background:#0b1020;color:#e8eefc;padding:2rem;line-height:1.55;max-width:860px}
a{color:#7dd3fc} pre,code{background:#121a33;padding:.15rem .4rem;border-radius:6px;font-size:.9em}
pre{padding:12px;overflow:auto} h1{margin-top:0} h2{margin-top:1.6rem}
.badge{display:inline-block;background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:999px;font-size:.8rem;margin:0 6px 6px 0}
ul.tools{list-style:none;padding:0;margin:0}
li.tool{background:#121a33;border:1px solid #243056;border-radius:12px;padding:14px 16px;margin:0 0 12px}
.tool-head{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}
.tool-head strong{font-family:ui-monospace,monospace;color:#f8fafc}
.t{color:#93c5fd;font-size:.92rem}
.flags{font-size:.75rem;color:#86efac;background:#052e16;padding:1px 8px;border-radius:999px}
.d{margin:.45rem 0 0;color:#e2e8f0}.d2{margin:.2rem 0 0;color:#94a3b8;font-size:.92rem}
.meta{margin:.55rem 0 0;color:#7a89ad;font-size:.82rem}
.note{background:#0f172a;border-left:3px solid #3b82f6;padding:10px 14px;margin:1rem 0;color:#cbd5e1}
</style></head><body>
<span class="badge">MCP ${MCP_PROTOCOL}</span>
<span class="badge">OAuth 2.1 + PKCE</span>
<span class="badge">v${SERVER.version}</span>
<span class="badge">${TOOLS.length} tools</span>
<h1>DNSPod MCP</h1>
<p>${SERVER.description}</p>
<div class="note">
<strong>Grok / 远程 MCP 连接</strong>：Connector URL 只填下方地址，连接时浏览器完成 OAuth（输入访问密码）。腾讯云 SecretId/Key 仅存在 Worker Secrets，不会暴露给客户端。
</div>
<p>MCP endpoint:</p>
<pre>${issuer}/mcp</pre>
<h2>Tools（${TOOLS.length}）— detailed descriptions for agents</h2>
<ul class="tools">${tools}</ul>
<h2>Agent workflow tips</h2>
<ol>
<li>改/删记录前先 <code>describe_record_list</code> 拿到并核对 <code>RecordId</code></li>
<li><code>SubDomain</code> 只填主机头（@ / www / api），不要写完整 FQDN</li>
<li>线路默认「默认」；MX 记录必须带优先级；TTL 单位秒</li>
<li>统计类工具日期格式 <code>YYYY-MM-DD</code>，粒度 DATE 或 HOUR</li>
</ol>
<p><a href="/health">/health</a> ·
<a href="/.well-known/oauth-authorization-server">OAuth metadata</a> ·
<a href="https://github.com/zfx-t/dnspod-mcp-workers">GitHub</a></p>
</body></html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const issuer = issuerFrom(url);
    const c = cors(request);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: c });

    if (path === "/health") {
      return json(
        {
          ok: true,
          server: SERVER,
          protocol: MCP_PROTOCOL,
          auth: "oauth2.1+pkce",
          tools: TOOLS.map((t) => ({
            name: t.name,
            title: t.title,
            descriptionChars: (t.description || "").length,
            paramCount: Object.keys(t.inputSchema?.properties || {}).length,
            required: t.inputSchema?.required || [],
            readOnly: !!t.annotations?.readOnlyHint,
            destructive: !!t.annotations?.destructiveHint,
          })),
          toolCount: TOOLS.length,
        },
        200,
        c
      );
    }
    if (path === "/") {
      return new Response(homeHtml(issuer), {
        headers: { "Content-Type": "text/html;charset=utf-8", ...c },
      });
    }

    if (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration") {
      return json(asMeta(issuer), 200, c);
    }
    if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
      return json(
        {
          resource: issuer + "/mcp",
          authorization_servers: [issuer],
          scopes_supported: ["mcp"],
          bearer_methods_supported: ["header"],
          resource_documentation: issuer + "/",
        },
        200,
        c
      );
    }

    if (path === "/register" && request.method === "POST") {
      let body = {};
      try {
        body = await request.json();
      } catch {}
      const client_id = await randomToken(16);
      const client_secret = body.token_endpoint_auth_method === "none" ? null : await randomToken(24);
      const redirect_uris = Array.isArray(body.redirect_uris) ? body.redirect_uris : [];
      const client = {
        client_id,
        client_secret,
        redirect_uris,
        client_name: body.client_name || "MCP Client",
        token_endpoint_auth_method: body.token_endpoint_auth_method || (client_secret ? "client_secret_post" : "none"),
        grant_types: body.grant_types || ["authorization_code", "refresh_token"],
        response_types: body.response_types || ["code"],
        created_at: Math.floor(Date.now() / 1000),
      };
      if (env.OAUTH_KV) {
        await env.OAUTH_KV.put("client:" + client_id, JSON.stringify(client), { expirationTtl: 90 * 24 * 3600 });
      }
      return json(
        {
          ...client,
          client_id_issued_at: client.created_at,
          client_secret_expires_at: 0,
        },
        201,
        c
      );
    }

    if (path === "/authorize") {
      if (request.method === "GET") {
        const q = url.searchParams;
        if (!q.get("client_id") || !q.get("redirect_uri") || !q.get("response_type")) {
          return new Response(formHtml("缺少 OAuth 参数（client_id / redirect_uri / response_type）"), {
            status: 400,
            headers: { "Content-Type": "text/html;charset=utf-8", ...c },
          });
        }
        const action = url.pathname + url.search;
        let html = formHtml("");
        html = html.replace('<form method="POST">', `<form method="POST" action="${action}">`);
        return new Response(html, { headers: { "Content-Type": "text/html;charset=utf-8", ...c } });
      }
      if (request.method === "POST") {
        const q = url.searchParams;
        const form = await request.formData();
        const password = String(form.get("password") || "");
        const expected = env.OAUTH_PASSWORD || env.MCP_AUTH_TOKEN || "";
        if (!expected || password !== expected) {
          const action = url.pathname + url.search;
          let html = formHtml("密码错误");
          html = html.replace('<form method="POST">', `<form method="POST" action="${action}">`);
          return new Response(html, {
            status: 401,
            headers: { "Content-Type": "text/html;charset=utf-8", ...c },
          });
        }
        const client_id = q.get("client_id");
        const redirect_uri = q.get("redirect_uri");
        const state = q.get("state");
        const code_challenge = q.get("code_challenge");
        const code_challenge_method = q.get("code_challenge_method") || "plain";
        const scope = q.get("scope") || "mcp";
        if (!client_id || !redirect_uri) {
          return new Response(formHtml("无效请求"), {
            status: 400,
            headers: { "Content-Type": "text/html;charset=utf-8", ...c },
          });
        }
        if (env.OAUTH_KV) {
          const client = await env.OAUTH_KV.get("client:" + client_id, "json");
          if (client?.redirect_uris?.length && !client.redirect_uris.includes(redirect_uri)) {
            return new Response(formHtml("redirect_uri 未登记"), {
              status: 400,
              headers: { "Content-Type": "text/html;charset=utf-8", ...c },
            });
          }
        }
        const code = await randomToken(24);
        const record = {
          client_id,
          redirect_uri,
          code_challenge,
          code_challenge_method,
          scope,
          user_id: "owner",
          exp: Math.floor(Date.now() / 1000) + CODE_TTL,
        };
        if (env.OAUTH_KV) {
          await env.OAUTH_KV.put("code:" + code, JSON.stringify(record), { expirationTtl: CODE_TTL });
        }
        const redir = new URL(redirect_uri);
        redir.searchParams.set("code", code);
        if (state) redir.searchParams.set("state", state);
        return Response.redirect(redir.toString(), 302);
      }
    }

    if (path === "/token" && request.method === "POST") {
      const ct = request.headers.get("Content-Type") || "";
      let params = {};
      if (ct.includes("application/json")) {
        params = await request.json();
      } else {
        const fd = await request.formData();
        for (const [k, v] of fd.entries()) params[k] = String(v);
      }
      const auth = request.headers.get("Authorization") || "";
      if (auth.startsWith("Basic ")) {
        try {
          const decoded = atob(auth.slice(6));
          const i = decoded.indexOf(":");
          params.client_id = params.client_id || decoded.slice(0, i);
          params.client_secret = params.client_secret || decoded.slice(i + 1);
        } catch {}
      }

      const jwtSecret = env.OAUTH_JWT_SECRET || env.OAUTH_PASSWORD || "change-me";
      const now = Math.floor(Date.now() / 1000);

      if (params.grant_type === "authorization_code") {
        const code = params.code;
        if (!code || !env.OAUTH_KV) return json({ error: "invalid_grant" }, 400, c);
        const rec = await env.OAUTH_KV.get("code:" + code, "json");
        await env.OAUTH_KV.delete("code:" + code);
        if (!rec || rec.exp < now) return json({ error: "invalid_grant", error_description: "code expired" }, 400, c);
        if (params.client_id && params.client_id !== rec.client_id) return json({ error: "invalid_client" }, 401, c);
        if (params.redirect_uri && params.redirect_uri !== rec.redirect_uri) return json({ error: "invalid_grant" }, 400, c);
        if (rec.code_challenge) {
          const verifier = params.code_verifier || "";
          let challenge;
          if ((rec.code_challenge_method || "plain") === "S256") {
            challenge = await sha256b64url(verifier);
          } else {
            challenge = verifier;
          }
          if (challenge !== rec.code_challenge) {
            return json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400, c);
          }
        }
        const access = await signJwt(
          {
            sub: rec.user_id,
            client_id: rec.client_id,
            scope: rec.scope,
            iss: issuer,
            aud: issuer + "/mcp",
            iat: now,
            exp: now + ACCESS_TTL,
          },
          jwtSecret
        );
        const refresh = await randomToken(32);
        await env.OAUTH_KV.put(
          "rt:" + refresh,
          JSON.stringify({ client_id: rec.client_id, user_id: rec.user_id, scope: rec.scope, exp: now + REFRESH_TTL }),
          { expirationTtl: REFRESH_TTL }
        );
        return json(
          {
            access_token: access,
            token_type: "Bearer",
            expires_in: ACCESS_TTL,
            refresh_token: refresh,
            scope: rec.scope,
          },
          200,
          c
        );
      }

      if (params.grant_type === "refresh_token") {
        const rt = params.refresh_token;
        if (!rt || !env.OAUTH_KV) return json({ error: "invalid_grant" }, 400, c);
        const rec = await env.OAUTH_KV.get("rt:" + rt, "json");
        if (!rec || rec.exp < now) return json({ error: "invalid_grant" }, 400, c);
        if (params.client_id && params.client_id !== rec.client_id) return json({ error: "invalid_client" }, 401, c);
        const access = await signJwt(
          {
            sub: rec.user_id,
            client_id: rec.client_id,
            scope: rec.scope,
            iss: issuer,
            aud: issuer + "/mcp",
            iat: now,
            exp: now + ACCESS_TTL,
          },
          jwtSecret
        );
        return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL, scope: rec.scope }, 200, c);
      }

      return json({ error: "unsupported_grant_type" }, 400, c);
    }

    if (path === "/mcp" || path === "/sse" || path === "/message") {
      const session = await requireAccess(request, env);
      if (!session) return unauthorized(request, issuer);

      if (request.method === "GET") {
        const sid = crypto.randomUUID();
        const stream = new ReadableStream({
          start(ctl) {
            const e = new TextEncoder();
            ctl.enqueue(e.encode(`event: endpoint\ndata: ${issuer}/message?sessionId=${sid}\n\n`));
            const iv = setInterval(() => {
              try {
                ctl.enqueue(e.encode(`: ping ${Date.now()}\n\n`));
              } catch {
                clearInterval(iv);
              }
            }, 25000);
            request.signal?.addEventListener("abort", () => {
              clearInterval(iv);
              try {
                ctl.close();
              } catch {}
            });
          },
        });
        return new Response(stream, {
          headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", "Mcp-Session-Id": sid, ...c },
        });
      }

      if (request.method === "POST") {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ jsonrpc: "2.0", error: { code: -32700, message: "Parse error" } }, 400, c);
        }
        const msgs = Array.isArray(body) ? body : [body];
        const out = [];
        for (const msg of msgs) {
          const r = await handleMcp(env, msg);
          if (r !== null) out.push(r);
        }
        if (!out.length) return new Response(null, { status: 202, headers: c });
        const payload = Array.isArray(body) ? out : out[0];
        const sid = request.headers.get("Mcp-Session-Id") || crypto.randomUUID();
        return new Response(JSON.stringify(payload), {
          status: 200,
          headers: { "Content-Type": "application/json", "Mcp-Session-Id": sid, ...c },
        });
      }
      if (request.method === "DELETE") return new Response(null, { status: 204, headers: c });
      return json({ error: "Method not allowed" }, 405, c);
    }

    return json({ error: "Not found", path }, 404, c);
  },
};
