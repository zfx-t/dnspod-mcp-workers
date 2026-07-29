/**
 * DNSPod MCP + OAuth 2.1 (PKCE, dynamic client registration)
 * For Grok Connectors: paste https://<your-domain>/mcp only.
 * Secrets: OAUTH_PASSWORD, OAUTH_JWT_SECRET, TENCENTCLOUD_SECRET_ID, TENCENTCLOUD_SECRET_KEY
 * Binding: OAUTH_KV (KV namespace)
 */

const SERVER = { name: "dnspod-mcp", version: "2.0.0" };
const MCP_PROTOCOL = "2025-03-26";
const ACCESS_TTL = 3600; // 1h
const REFRESH_TTL = 30 * 24 * 3600; // 30d
const CODE_TTL = 600; // 10m

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
    const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/") + "===".slice((parts[1].length + 3) % 4)), (c) => c.charCodeAt(0))));
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
  const body = JSON.stringify(payload);
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

const TOOLS = [
  { name: "describe_domain_list", description: "List DNSPod domains", inputSchema: { type: "object", properties: { Type: { type: "string" }, Offset: { type: "number" }, Limit: { type: "number" }, Keyword: { type: "string" } } } },
  { name: "create_domain", description: "Create domain", inputSchema: { type: "object", properties: { Domain: { type: "string" } }, required: ["Domain"] } },
  { name: "describe_domain", description: "Domain details", inputSchema: { type: "object", properties: { Domain: { type: "string" } }, required: ["Domain"] } },
  { name: "describe_record_list", description: "List DNS records", inputSchema: { type: "object", properties: { Domain: { type: "string" }, Subdomain: { type: "string" }, RecordType: { type: "string" }, Keyword: { type: "string" }, Offset: { type: "number" }, Limit: { type: "number" } }, required: ["Domain"] } },
  { name: "create_record", description: "Create DNS record", inputSchema: { type: "object", properties: { Domain: { type: "string" }, SubDomain: { type: "string" }, RecordType: { type: "string" }, RecordLine: { type: "string" }, Value: { type: "string" }, TTL: { type: "number" }, MX: { type: "number" } }, required: ["Domain", "SubDomain", "RecordType", "Value"] } },
  { name: "modify_record", description: "Modify DNS record", inputSchema: { type: "object", properties: { Domain: { type: "string" }, RecordId: { type: "number" }, SubDomain: { type: "string" }, RecordType: { type: "string" }, RecordLine: { type: "string" }, Value: { type: "string" }, TTL: { type: "number" } }, required: ["Domain", "RecordId", "SubDomain", "RecordType", "Value"] } },
  { name: "delete_record", description: "Delete DNS record", inputSchema: { type: "object", properties: { Domain: { type: "string" }, RecordId: { type: "number" } }, required: ["Domain", "RecordId"] } },
  { name: "describe_domain_analytics", description: "Domain analytics", inputSchema: { type: "object", properties: { Domain: { type: "string" }, StartDate: { type: "string" }, EndDate: { type: "string" }, DnsFormat: { type: "string" } }, required: ["Domain", "StartDate", "EndDate"] } },
  { name: "describe_subdomain_analytics", description: "Subdomain analytics", inputSchema: { type: "object", properties: { Domain: { type: "string" }, Subdomain: { type: "string" }, StartDate: { type: "string" }, EndDate: { type: "string" }, DnsFormat: { type: "string" } }, required: ["Domain", "Subdomain", "StartDate", "EndDate"] } },
];

async function callTool(env, n, a = {}) {
  const M = {
    describe_domain_list: ["DescribeDomainList", { Type: a.Type || "ALL", Offset: a.Offset ?? 0, Limit: a.Limit ?? 20, Keyword: a.Keyword }],
    create_domain: ["CreateDomain", { Domain: a.Domain }],
    describe_domain: ["DescribeDomain", { Domain: a.Domain, DomainId: a.DomainId }],
    describe_record_list: ["DescribeRecordList", { Domain: a.Domain, Subdomain: a.Subdomain, RecordType: a.RecordType, Keyword: a.Keyword, Offset: a.Offset ?? 0, Limit: a.Limit ?? 100 }],
    create_record: ["CreateRecord", { Domain: a.Domain, SubDomain: a.SubDomain, RecordType: a.RecordType, RecordLine: a.RecordLine || "默认", Value: a.Value, TTL: a.TTL, MX: a.MX }],
    modify_record: ["ModifyRecord", { Domain: a.Domain, RecordId: a.RecordId, SubDomain: a.SubDomain, RecordType: a.RecordType, RecordLine: a.RecordLine || "默认", Value: a.Value, TTL: a.TTL }],
    delete_record: ["DeleteRecord", { Domain: a.Domain, RecordId: a.RecordId }],
    describe_domain_analytics: ["DescribeDomainAnalytics", { Domain: a.Domain, StartDate: a.StartDate, EndDate: a.EndDate, DnsFormat: a.DnsFormat || "DATE" }],
    describe_subdomain_analytics: ["DescribeSubdomainAnalytics", { Domain: a.Domain, Subdomain: a.Subdomain, StartDate: a.StartDate, EndDate: a.EndDate, DnsFormat: a.DnsFormat || "DATE" }],
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
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER,
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
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept, Mcp-Session-Id, Last-Event-ID, mcp-protocol-version",
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
  <p>Grok 请求访问你的 DNSPod 管理工具。输入访问密码以继续（OAuth 授权码流程）。</p>
  ${error ? `<p class="err">${error}</p>` : ""}
  <form method="POST">
    <label for="password">访问密码</label>
    <input id="password" name="password" type="password" required autocomplete="current-password" autofocus/>
    <button type="submit">授权连接</button>
  </form>
  <p class="meta">授权后将返回 Grok，不会暴露腾讯云密钥。</p>
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
    // MCP-friendly
    revocation_endpoint_auth_methods_supported: ["none"],
  };
}

async function requireAccess(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  // JWT path
  if (token.split(".").length === 3) {
    const secret = env.OAUTH_JWT_SECRET || env.OAUTH_PASSWORD || "change-me";
    return verifyJwt(token, secret);
  }
  // opaque token in KV
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
  const resource = issuer + "/mcp";
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const issuer = issuerFrom(url);
    const c = cors(request);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: c });

    // Health / home
    if (path === "/health") {
      return json({ ok: true, server: SERVER, protocol: MCP_PROTOCOL, auth: "oauth2.1+pkce" }, 200, c);
    }
    if (path === "/") {
      return new Response(
        `<!doctype html><meta charset=utf-8><title>DNSPod MCP</title>
<body style="font-family:system-ui;background:#0b1020;color:#e8eefc;padding:2rem;max-width:640px">
<h1>DNSPod MCP (OAuth)</h1>
<p>Grok Connector 只需填写：</p>
<pre style="background:#121a33;padding:12px;border-radius:8px">${issuer}/mcp</pre>
<p>连接时会弹出浏览器完成 OAuth 授权（输入访问密码）。</p>
<p><a style="color:#7dd3fc" href="/health">/health</a></p>
</body>`,
        { headers: { "Content-Type": "text/html;charset=utf-8", ...c } }
      );
    }

    // OAuth discovery
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
        },
        200,
        c
      );
    }

    // Dynamic client registration (RFC 7591)
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

    // Authorize
    if (path === "/authorize") {
      if (request.method === "GET") {
        // Validate params lightly; show form (preserve query on POST via form action)
        const q = url.searchParams;
        if (!q.get("client_id") || !q.get("redirect_uri") || !q.get("response_type")) {
          return new Response(formHtml("缺少 OAuth 参数（client_id / redirect_uri / response_type）"), {
            status: 400,
            headers: { "Content-Type": "text/html;charset=utf-8", ...c },
          });
        }
        // Preserve full query string when posting
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
          return new Response(html, { status: 401, headers: { "Content-Type": "text/html;charset=utf-8", ...c } });
        }
        const client_id = q.get("client_id");
        const redirect_uri = q.get("redirect_uri");
        const state = q.get("state");
        const code_challenge = q.get("code_challenge");
        const code_challenge_method = q.get("code_challenge_method") || "plain";
        const scope = q.get("scope") || "mcp";
        if (!client_id || !redirect_uri) {
          return new Response(formHtml("无效请求"), { status: 400, headers: { "Content-Type": "text/html;charset=utf-8", ...c } });
        }
        // Optional: validate client redirect_uri if registered
        if (env.OAUTH_KV) {
          const client = await env.OAUTH_KV.get("client:" + client_id, "json");
          if (client?.redirect_uris?.length && !client.redirect_uris.includes(redirect_uri)) {
            return new Response(formHtml("redirect_uri 未登记"), { status: 400, headers: { "Content-Type": "text/html;charset=utf-8", ...c } });
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

    // Token
    if (path === "/token" && request.method === "POST") {
      const ct = request.headers.get("Content-Type") || "";
      let params = {};
      if (ct.includes("application/json")) {
        params = await request.json();
      } else {
        const fd = await request.formData();
        for (const [k, v] of fd.entries()) params[k] = String(v);
      }
      // Basic auth client credentials
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
        // PKCE
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
          { sub: rec.user_id, client_id: rec.client_id, scope: rec.scope, iss: issuer, aud: issuer + "/mcp", iat: now, exp: now + ACCESS_TTL },
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
          { sub: rec.user_id, client_id: rec.client_id, scope: rec.scope, iss: issuer, aud: issuer + "/mcp", iat: now, exp: now + ACCESS_TTL },
          jwtSecret
        );
        return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL, scope: rec.scope }, 200, c);
      }

      return json({ error: "unsupported_grant_type" }, 400, c);
    }

    // MCP endpoints (protected)
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
