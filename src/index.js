/**
 * DNSPod MCP + OAuth 2.1 (PKCE, dynamic client registration)
 * For Grok Connectors: paste https://<your-domain>/mcp only.
 * Secrets: OAUTH_PASSWORD, OAUTH_JWT_SECRET, TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY
 * Binding: OAUTH_KV (KV namespace)
 */

const SERVER = {
  name: "dnspod-mcp",
  version: "2.1.0",
  title: "DNSPod MCP",
  description:
    "Remote MCP server for Tencent Cloud DNSPod. Manage DNS domains and records, and query resolution analytics over Streamable HTTP with OAuth 2.1.",
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
 * Rich tool definitions for MCP clients (Grok / Claude).
 * Descriptions are bilingual and include when-to-use + examples so models pick tools correctly.
 */
const TOOLS = [
  {
    name: "describe_domain_list",
    title: "List DNS domains",
    description:
      "查询当前账号在 DNSPod 中的域名列表（权威 DNS 托管域名）。\n" +
      "List all DNS domains managed in DNSPod for this account.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户问「我有哪些域名」「列出域名」\n" +
      "- 需要 DomainId、套餐等级、记录数量、DNS 服务器等概览信息\n" +
      "- 后续改记录前先确认域名是否存在\n\n" +
      "返回 / Returns: DomainList（Name, DomainId, Status, Grade, RecordCount, EffectiveDNS 等）与 DomainCountInfo。\n" +
      "示例 / Example: { \"Limit\": 20 } 或 { \"Keyword\": \"zfxt\", \"Type\": \"ALL\" }",
    inputSchema: {
      type: "object",
      properties: {
        Type: {
          type: "string",
          description:
            "域名分组类型。可选: ALL(全部,默认), MINE(我的), SHARE(共享给我), ISMARK(星标), PAUSE(暂停), VIP(付费), RECENT(最近操作), SHARE_OUT(我共享出), FREE(免费)。",
          enum: ["ALL", "MINE", "SHARE", "ISMARK", "PAUSE", "VIP", "RECENT", "SHARE_OUT", "FREE"],
          default: "ALL",
        },
        Offset: { type: "integer", description: "分页偏移，从 0 开始。默认 0。", minimum: 0, default: 0 },
        Limit: {
          type: "integer",
          description: "返回条数，默认 20，最大 100（API 侧更大值也可能被截断）。",
          minimum: 1,
          maximum: 100,
          default: 20,
        },
        GroupId: { type: "integer", description: "域名分组 ID；传入则只返回该分组内的域名。" },
        Keyword: { type: "string", description: "按域名关键字模糊搜索，如 zfxt 或 example.com。" },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "create_domain",
    title: "Add domain to DNSPod",
    description:
      "在 DNSPod 中添加一个待解析的域名（将域名托管到 DNSPod 权威解析）。\n" +
      "Add a new domain into DNSPod authoritative DNS management.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户要「把 xxx.com 加到 DNSPod」「创建/添加域名」\n" +
      "- 注意：这只是在 DNSPod 侧添加域名，注册商 NS 仍需改成 DNSPod 给的 DNS 服务器后才生效\n\n" +
      "返回 / Returns: 新建域名的 DomainId 等信息。\n" +
      "示例 / Example: { \"Domain\": \"example.com\" }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: {
          type: "string",
          description: "要添加的主域名，不含协议与路径，如 example.com 或 zfxt.top。",
        },
        GroupId: { type: "integer", description: "可选，加入指定域名分组。" },
      },
      required: ["Domain"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  },
  {
    name: "describe_domain",
    title: "Get domain details",
    description:
      "查询单个域名的详细信息（状态、套餐、NS、记录数、创建时间等）。\n" +
      "Get detailed information for one DNS domain.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户问某个域名是否启用、用的什么套餐、NS 是什么\n" +
      "- 比 describe_domain_list 更聚焦单个域名\n\n" +
      "参数: Domain 与 DomainId 二选一，DomainId 优先。\n" +
      "示例 / Example: { \"Domain\": \"zfxt.top\" }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: { type: "string", description: "域名，如 zfxt.top。" },
        DomainId: {
          type: "integer",
          description: "域名 ID（来自 describe_domain_list）。若同时传 Domain 与 DomainId，DomainId 优先。",
        },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "describe_record_list",
    title: "List DNS records",
    description:
      "查询指定域名下的 DNS 解析记录列表（A/AAAA/CNAME/MX/TXT/NS 等）。\n" +
      "List DNS records under a domain (A, AAAA, CNAME, MX, TXT, NS, etc.).\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户问「有哪些解析」「www 指到哪」「列出 TXT 记录」\n" +
      "- 修改/删除记录前必须先查 RecordId\n\n" +
      "返回 / Returns: RecordList（RecordId, Name, Type, Value, Line, TTL, MX, Status 等）。\n" +
      "示例 / Example:\n" +
      "{ \"Domain\": \"zfxt.top\" }\n" +
      "{ \"Domain\": \"zfxt.top\", \"Subdomain\": \"www\", \"RecordType\": \"A\" }\n" +
      "{ \"Domain\": \"zfxt.top\", \"Keyword\": \"1.2.3\" }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: { type: "string", description: "主域名，如 zfxt.top。必填（除非用 DomainId）。" },
        DomainId: {
          type: "integer",
          description: "域名 ID；优先级高于 Domain。",
        },
        Subdomain: {
          type: "string",
          description: "主机记录过滤。如 www、@、*、mail。不传则返回全部主机记录。",
        },
        RecordType: {
          type: "string",
          description: "记录类型过滤：A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, 显性URL, 隐性URL 等。",
        },
        RecordLine: {
          type: "string",
          description: "线路名称过滤（中文），如 默认、电信、联通、移动、境外。",
        },
        RecordLineId: {
          type: "string",
          description: "线路 ID（英文编码，如 0 或 10=1）。优先级高于 RecordLine。",
        },
        Keyword: { type: "string", description: "关键字搜索：匹配主机头或记录值。" },
        SortField: {
          type: "string",
          description: "排序字段：name, line, type, value, weight, mx, ttl, updated_on。",
        },
        SortType: { type: "string", description: "排序方向：ASC 或 DESC。默认 ASC。", enum: ["ASC", "DESC"] },
        Offset: { type: "integer", description: "分页偏移，默认 0。", minimum: 0, default: 0 },
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
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "create_record",
    title: "Create DNS record",
    description:
      "为域名新增一条 DNS 解析记录。\n" +
      "Create a new DNS record under a domain.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户说「加一条 A 记录」「把 www 指到 IP」「添加 CNAME / TXT / MX」\n\n" +
      "注意 / Notes:\n" +
      "- SubDomain 用主机头：www / @ / * / mail，不要写成完整 FQDN\n" +
      "- RecordLine 默认「默认」；免费版通常只用默认线路\n" +
      "- MX 记录必须传 MX 优先级（越小越优先）\n" +
      "- TTL 单位秒，免费版常见 600\n\n" +
      "示例 / Examples:\n" +
      "A: { \"Domain\": \"zfxt.top\", \"SubDomain\": \"www\", \"RecordType\": \"A\", \"Value\": \"1.2.3.4\" }\n" +
      "CNAME: { \"Domain\": \"zfxt.top\", \"SubDomain\": \"blog\", \"RecordType\": \"CNAME\", \"Value\": \"xxx.github.io.\" }\n" +
      "TXT: { \"Domain\": \"zfxt.top\", \"SubDomain\": \"@\", \"RecordType\": \"TXT\", \"Value\": \"v=spf1 include:_spf.google.com ~all\" }\n" +
      "MX: { \"Domain\": \"zfxt.top\", \"SubDomain\": \"@\", \"RecordType\": \"MX\", \"Value\": \"mx.example.com.\", \"MX\": 10 }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: { type: "string", description: "主域名，如 zfxt.top。" },
        DomainId: { type: "integer", description: "可选，域名 ID；优先于 Domain。" },
        SubDomain: {
          type: "string",
          description: "主机记录。@ 表示根域名，www 表示 www.域名，* 表示泛解析。",
        },
        RecordType: {
          type: "string",
          description: "记录类型：A, AAAA, CNAME, MX, TXT, NS, SRV, CAA 等。",
        },
        RecordLine: {
          type: "string",
          description: "解析线路，中文。默认「默认」。常见: 默认, 电信, 联通, 移动, 境外。",
          default: "默认",
        },
        RecordLineId: { type: "string", description: "线路 ID；若提供则优先于 RecordLine。" },
        Value: {
          type: "string",
          description:
            "记录值。A=IPv4；AAAA=IPv6；CNAME/MX/NS=目标主机名（建议以.结尾）；TXT=文本内容。",
        },
        TTL: {
          type: "integer",
          description: "TTL（秒）。免费版常用 600；可设 60–604800（受套餐限制）。",
          minimum: 1,
        },
        MX: {
          type: "integer",
          description: "MX 优先级，仅 MX 记录需要。取值通常 1–20，数字越小优先级越高。",
          minimum: 0,
          maximum: 50,
        },
        Weight: { type: "integer", description: "权重（部分套餐/类型支持加权轮询）。", minimum: 0, maximum: 100 },
        Remark: { type: "string", description: "记录备注（可选）。" },
      },
      required: ["Domain", "SubDomain", "RecordType", "Value"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  },
  {
    name: "modify_record",
    title: "Update DNS record",
    description:
      "修改已有 DNS 解析记录（必须提供 RecordId）。\n" +
      "Update an existing DNS record. RecordId is required.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户要改 IP、改 CNAME 目标、改 TTL、改主机头\n" +
      "- 流程：先 describe_record_list 拿到 RecordId，再调用本工具\n\n" +
      "注意：修改时通常需完整传入 SubDomain、RecordType、Value、RecordLine（与创建类似）。\n\n" +
      "示例 / Example:\n" +
      "{ \"Domain\": \"zfxt.top\", \"RecordId\": 123456789, \"SubDomain\": \"www\", \"RecordType\": \"A\", \"RecordLine\": \"默认\", \"Value\": \"5.6.7.8\", \"TTL\": 600 }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: { type: "string", description: "主域名。" },
        DomainId: { type: "integer", description: "可选域名 ID。" },
        RecordId: {
          type: "integer",
          description: "要修改的记录 ID（来自 describe_record_list）。必填。",
        },
        SubDomain: { type: "string", description: "主机记录，如 www 或 @。" },
        RecordType: { type: "string", description: "记录类型：A, AAAA, CNAME, MX, TXT 等。" },
        RecordLine: { type: "string", description: "线路，默认「默认」。", default: "默认" },
        RecordLineId: { type: "string", description: "线路 ID（可选，优先于 RecordLine）。" },
        Value: { type: "string", description: "新的记录值。" },
        TTL: { type: "integer", description: "TTL（秒）。" },
        MX: { type: "integer", description: "MX 优先级（MX 记录必填）。" },
        Weight: { type: "integer", description: "权重（若套餐支持）。" },
        Remark: { type: "string", description: "备注。" },
      },
      required: ["Domain", "RecordId", "SubDomain", "RecordType", "Value"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
  },
  {
    name: "delete_record",
    title: "Delete DNS record",
    description:
      "删除一条 DNS 解析记录（不可恢复，请确认 RecordId）。\n" +
      "Permanently delete one DNS record by RecordId.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户明确要求删除某条解析\n" +
      "- 务必先 describe_record_list 核对 RecordId、主机头与记录值，避免误删\n\n" +
      "示例 / Example: { \"Domain\": \"zfxt.top\", \"RecordId\": 123456789 }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: { type: "string", description: "主域名。" },
        DomainId: { type: "integer", description: "可选域名 ID。" },
        RecordId: { type: "integer", description: "要删除的记录 ID。必填。" },
      },
      required: ["Domain", "RecordId"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
  },
  {
    name: "describe_domain_analytics",
    title: "Domain DNS query analytics",
    description:
      "查询整个域名在指定时间范围内的 DNS 解析量统计。\n" +
      "Get DNS query volume analytics for a whole domain.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户问「这个域名解析量多少」「最近访问/查询量」\n" +
      "- 需要按天或按小时的解析请求统计\n\n" +
      "注意: StartDate/EndDate 格式 YYYY-MM-DD；免费套餐可能限制统计范围。\n" +
      "示例 / Example: { \"Domain\": \"zfxt.top\", \"StartDate\": \"2026-07-01\", \"EndDate\": \"2026-07-29\", \"DnsFormat\": \"DATE\" }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: { type: "string", description: "主域名。" },
        DomainId: { type: "integer", description: "可选域名 ID，优先于 Domain。" },
        StartDate: { type: "string", description: "开始日期，YYYY-MM-DD。" },
        EndDate: { type: "string", description: "结束日期，YYYY-MM-DD。" },
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
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "describe_subdomain_analytics",
    title: "Subdomain DNS query analytics",
    description:
      "查询指定子域名（主机记录）的 DNS 解析量统计。\n" +
      "Get DNS query analytics for one subdomain/host record.\n\n" +
      "何时使用 / When to use:\n" +
      "- 用户问「www 的解析量」「某个子域名请求量」\n\n" +
      "示例 / Example: { \"Domain\": \"zfxt.top\", \"Subdomain\": \"www\", \"StartDate\": \"2026-07-01\", \"EndDate\": \"2026-07-29\" }",
    inputSchema: {
      type: "object",
      properties: {
        Domain: { type: "string", description: "主域名。" },
        DomainId: { type: "integer", description: "可选域名 ID。" },
        Subdomain: {
          type: "string",
          description: "主机记录，如 www、@、api（不要带主域名后缀）。",
        },
        StartDate: { type: "string", description: "开始日期，YYYY-MM-DD。" },
        EndDate: { type: "string", description: "结束日期，YYYY-MM-DD。" },
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
    annotations: { readOnlyHint: true, openWorldHint: true },
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
            // Advertise useful server surface for clients
            logging: {},
          },
          serverInfo: {
            name: SERVER.name,
            version: SERVER.version,
            title: SERVER.title,
            description: SERVER.description,
          },
          instructions:
            "This is a remote DNSPod MCP server. Use describe_domain_list / describe_record_list before mutating records. " +
            "For create_record/modify_record, SubDomain is the host label (@, www, api) not the FQDN. " +
            "RecordLine defaults to 默认. Always confirm RecordId via describe_record_list before delete_record or modify_record. " +
            "Dates for analytics use YYYY-MM-DD. Prefer Chinese domain/line names as returned by DNSPod APIs.",
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
  const tools = TOOLS.map(
    (t) =>
      `<li><strong>${t.name}</strong> — ${String(t.description).split("\n")[0]}</li>`
  ).join("");
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>DNSPod MCP</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif}
body{margin:0;background:#0b1020;color:#e8eefc;padding:2rem;line-height:1.55;max-width:760px}
a{color:#7dd3fc} pre,code{background:#121a33;padding:.15rem .4rem;border-radius:6px}
pre{padding:12px;overflow:auto} h1{margin-top:0} ul{padding-left:1.2rem} li{margin:.45rem 0}
.badge{display:inline-block;background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:999px;font-size:.8rem;margin-right:6px}
</style></head><body>
<span class="badge">MCP ${MCP_PROTOCOL}</span>
<span class="badge">OAuth 2.1 + PKCE</span>
<span class="badge">v${SERVER.version}</span>
<h1>DNSPod MCP（Cloudflare Workers）</h1>
<p>${SERVER.description}</p>
<p>Grok Connector / 远程 MCP 客户端只需填写：</p>
<pre>${issuer}/mcp</pre>
<p>连接时会弹出浏览器完成 OAuth（输入访问密码）。腾讯云密钥仅保存在 Worker Secrets。</p>
<h2>Tools（${TOOLS.length}）</h2>
<ul>${tools}</ul>
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
          tools: TOOLS.map((t) => ({ name: t.name, title: t.title })),
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
