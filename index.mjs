// OpenCode & Magpie provider plugin for Baidu DuMate Enterprise (百度搭子企业版).
//
// Chain (verified 2026-11-03 on an enterprise tenant):
//   enterprise session cookie (dumate_enterprise_sessionid)
//     -> GET {TENANT_API}/v1/user               (whoami: tenantId, userId, displayName)
//     -> GET {TENANT_API}/v1/user_token         (Bearer token, ~6h TTL)
//     -> POST https://dumate-svc.baidu.com/gateway/apis/ais-v2/chat/completions
//        (OpenAI-compatible; consumes the tenant's shared resource pool)
//
// Login methods:
// 1. desktop — reuse the local DuMate (enterprise) login: read auth.json's
//    enterpriseApiBaseUrl and decrypt its "cookies" with the .cookie-key
//    AES-256-GCM key (read-only, never writes)
// 2. manual — paste "dumate_enterprise_sessionid=...; tenantApi=https://<tenant-domain>/api/dumate-enterprise/app"
//    (cookie decrypted from the desktop client's auth.json; tenantApi points at the tenant)
//
// Usage/quota: GET {TENANT_API}/users/{bceUserId}/info returns userCredits
// (totalCredits/usedCredits/remainingCredits) plus today/month call stats.
// The enterprise edition has no daily check-in (resource points are
// organization-purchased), so no checkin hook is implemented on purpose.
import { createDecipheriv } from "node:crypto"
import { readFileSync, statSync } from "node:fs"
import { join } from "node:path"

const PROVIDER_ID = "dumate-enterprise"
const PROVIDER_NAME = "百度搭子企业版"
const GATEWAY_CHAT = "https://dumate-svc.baidu.com/gateway/apis/ais-v2/chat/completions"
const GATEWAY_BASE = "https://dumate-svc.baidu.com/gateway/apis/ais-v2"
const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) DuMate/1.0.87 Chrome/130.0.0.0 Electron/33.0.0 Safari/537.36"
const TOKEN_TTL_MS = 30 * 60 * 1000 // proactive refresh; server gives ~6h
const ENTERPRISE_API_PATH = "/api/dumate-enterprise/app" // fixed prefix on every tenant domain

// Fallback catalog (mirrors POST /v1/model/list-all on an enterprise tenant).
const FALLBACK_MODELS = [
  { id: "kimi-k31", name: "Kimi-K3.1 Pro", context: 1048576, output: 1048576, reasoning: true },
  { id: "glm-53", name: "GLM-5.3", context: 1000000, output: 128000, reasoning: true },
  { id: "glm-53-flash", name: "GLM-5.3 Flash", context: 1000000, output: 128000, reasoning: true },
  { id: "deepseek-v4-pro", name: "DeepSeek-V4 Pro", context: 1000000, output: 384000, reasoning: true },
  { id: "deepseek-v41-flash", name: "DeepSeek-V4.1 Flash", context: 1000000, output: 384000, reasoning: true },
  { id: "qwen38-flash", name: "Qwen-3.8 Flash", context: 983000, output: 128000, reasoning: true },
]

// ---- icon (same degradation chain as magpie-dumate) ------------------------
const MAX_ICON_URI = 1024 * 1024
function pngDataUri(buf) {
  if (!buf?.length) return ""
  if (!(buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47)) return ""
  const encoded = buf.toString("base64")
  if (encoded.length + 32 > MAX_ICON_URI) return ""
  return `data:image/png;base64,${encoded}`
}
function iconFromPluginDir() {
  try { return pngDataUri(readFileSync(new URL("./icon.png", import.meta.url))) } catch { return "" }
}
function iconFromDesktopApp() {
  try {
    const installJson = JSON.parse(readFileSync(join(desktopUserDataDir(), "install.json"), "utf8"))
    const installDir = String(installJson?.installDir ?? "").trim()
    if (!installDir) return ""
    for (const name of ["256x256.png", "128x128.png", "512x512.png"]) {
      try {
        const uri = pngDataUri(readFileSync(join(installDir, "program", "resources", "resources", "icons", name)))
        if (uri) return uri
      } catch { /* next size */ }
    }
  } catch { /* not installed */ }
  return ""
}
function iconFromBundle() {
  try {
    const svg = readFileSync(new URL("./icon.svg", import.meta.url), "utf8")
    if (!svg.trim()) return ""
    return `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`
  } catch { return "" }
}
const pluginIcon = iconFromPluginDir() || iconFromDesktopApp() || iconFromBundle()

// ---- desktop login reuse (read-only, same data dir as personal edition) ----
function desktopUserDataDir() {
  const v = String(process.env.DUMATE_USER_DATA_DIR ?? "").trim()
  if (v) return v
  return join(process.env.APPDATA ?? "", "qianfan-desktop-app")
}
// tenantApi = <enterpriseApiBaseUrl from auth.json> + the fixed app path
function tenantApiFromBaseUrl(baseUrl) {
  const base = String(baseUrl ?? "").trim().replace(/\/+$/, "")
  return base ? base + ENTERPRISE_API_PATH : ""
}
function readDesktopLogin() {
  try {
    const dir = desktopUserDataDir()
    const authPath = join(dir, "auth.json")
    const st = statSync(authPath)
    if (!st.isFile() || st.size <= 0 || st.size > 1024 * 1024) return null
    const auth = JSON.parse(readFileSync(authPath, "utf8"))
    const cookiesField = auth?.cookies
    if (typeof cookiesField !== "string" || !cookiesField) return null
    const key = readFileSync(join(dir, ".cookie-key"))
    if (key.length !== 32) return null
    const buf = Buffer.from(cookiesField, "base64")
    const decipher = createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12))
    decipher.setAuthTag(buf.subarray(12, 28))
    const arr = JSON.parse(Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8"))
    if (!Array.isArray(arr) || !arr.length) return null
    const profile = Array.isArray(auth.accountProfiles) && auth.activeProfileId
      ? auth.accountProfiles.find((p) => p?.profileId === auth.activeProfileId)
      : null
    const first = auth?.accountProfiles?.[0] ?? {}
    return {
      cookies: arr,
      accountId: String(first.bceAccountId ?? ""),
      userId: String(first.bceUserId ?? ""),
      tenantApi: tenantApiFromBaseUrl(auth?.enterpriseApiBaseUrl ?? first.enterpriseApiBaseUrl),
      name: String(profile?.displayName ?? first.displayName ?? ""),
      source: "desktop",
    }
  } catch { return null }
}

// ---- cookie helpers --------------------------------------------------------
function parseCookieString(raw) {
  const out = []
  for (const part of String(raw ?? "").split(/;\s*/)) {
    const idx = part.indexOf("=")
    if (idx <= 0) continue
    const name = part.slice(0, idx).trim()
    let value = part.slice(idx + 1).trim()
    if (!name) continue
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1)
    out.push({ name, value, domain: ".dumate.cn" })
  }
  return out
}
const cookieHeaderOf = (cookies) => cookies.map((c) => `${c.name}=${c.value}`).join("; ")

// ---- text safety (same as magpie-dumate) -----------------------------------
const cardText = (value, max = 200) => {
  const cleaned = String(value ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, " ")
    .trim()
  const points = Array.from(cleaned)
  return points.length > max ? points.slice(0, max).join("") : cleaned
}

// ---- tenant console API ----------------------------------------------------
function htmlSignInError() {
  const err = new Error("DuMate 企业版登录态已失效（接口返回登录页），请重新登录")
  err.signIn = "expired"
  return err
}
async function consoleGet(path, cookieStr) {
  const res = await fetch(path, {
    headers: { Cookie: cookieStr, "User-Agent": UA, Accept: "application/json" },
    signal: AbortSignal.timeout(20_000),
  })
  const text = await res.text()
  let payload = null
  try { payload = JSON.parse(text) } catch {}
  if (payload === null || typeof payload !== "object") throw htmlSignInError()
  return payload
}

// ---- token lifecycle (single-flight cache) ---------------------------------
const tokenCache = new Map() // cookieHeader -> {token, expiresAt} | pending promise
async function fetchGatewayToken(cookieHeader, tenantApi) {
  const cached = tokenCache.get(cookieHeader)
  if (cached && Date.now() < cached.expiresAt - 5 * 60_000) return cached
  let pending = tokenCache.get(cookieHeader + "\u0000pending")
  if (!pending) {
    pending = (async () => {
      const result = await consoleGet(`${tenantApi}/v1/user_token`, cookieHeader)
      const token = String(result?.token ?? "")
      if (!token) throw new Error("DuMate 企业版未返回 gateway token")
      const expiresAt = result?.expired_at ? Date.parse(result.expired_at) : Date.now() + TOKEN_TTL_MS
      return { token, expiresAt: Number.isFinite(expiresAt) && expiresAt > Date.now() ? expiresAt : Date.now() + TOKEN_TTL_MS }
    })().finally(() => tokenCache.delete(cookieHeader + "\u0000pending"))
    tokenCache.set(cookieHeader + "\u0000pending", pending)
  }
  const next = await pending
  tokenCache.set(cookieHeader, next)
  return next
}

// ---- plugin ----------------------------------------------------------------
export const DuMateEnterprisePlugin = async () => {
  const consoleCookies = async (auth) => {
    if (auth?.type !== "oauth" || !Array.isArray(auth.cookies) || !auth.cookies.length) throw signInError(auth)
    return auth.cookies
  }
  const signInError = (auth) => {
    const err = new Error(
      auth?.source === "desktop"
        ? "DuMate 企业版桌面端登录态已失效，请打开百度搭子重新登录后在此重新登录"
        : "DuMate 企业版登录态已失效，请重新登录",
    )
    err.signIn = "expired"
    return err
  }
  const tenantApiOf = (auth) =>
    String(auth?.tenantApi ?? process.env.DUMATE_ENTERPRISE_API ?? "").replace(/\/+$/, "")

  return {
    config: async (config) => {
      config.provider ??= {}
      const was = config.provider[PROVIDER_ID] ?? {}
      config.provider[PROVIDER_ID] = {
        name: PROVIDER_NAME,
        npm: "@ai-sdk/openai-compatible",
        api: GATEWAY_BASE,
        ...was,
        models: {
          ...Object.fromEntries(
            FALLBACK_MODELS.map((m) => [
              m.id,
              {
                name: m.name,
                limit: { context: m.context, output: m.output },
                tool_call: true,
                reasoning: !!m.reasoning,
                attachment: false,
                modalities: { input: ["text"], output: ["text"] },
              },
            ]),
          ),
          ...(was.models ?? {}),
        },
      }
    },
    provider: {
      id: PROVIDER_ID,
      async models(provider) {
        return provider.models
      },
    },
    auth: {
      provider: PROVIDER_ID,
      icon: pluginIcon,
      async refresh(auth) {
        // Cookies have no refresh flow. For desktop-source seats, follow the
        // app: if it re-logged-in, pick up its newer cookies transparently.
        if (auth?.type !== "oauth" || auth.source !== "desktop") return undefined
        const d = readDesktopLogin()
        if (!d) return undefined
        const oldHeader = cookieHeaderOf(auth.cookies ?? [])
        const newHeader = cookieHeaderOf(d.cookies)
        if (newHeader === oldHeader) return undefined
        return {
          access: "cookie:" + newHeader,
          refresh: "",
          expires: 0,
          source: "desktop",
          accountId: d.accountId || auth.accountId,
          userId: d.userId || auth.userId,
          tenantApi: d.tenantApi || auth.tenantApi,
          tenantId: auth.tenantId,
          name: d.name || auth.name || "",
          cookies: d.cookies,
        }
      },
      async loader(getAuth) {
        let auth
        try {
          auth = await getAuth()
        } catch (e) {
          return {
            baseURL: GATEWAY_BASE,
            apiKey: "dumate-enterprise",
            async fetch() {
              return new Response(
                JSON.stringify({ error: { message: `DuMate 企业版登录态读取失败: ${e?.message ?? e}`, type: "api_error" } }),
                { status: 502, headers: { "Content-Type": "application/json", "X-Magpie-Sign-In": "kept" } },
              )
            },
          }
        }
        const tenantApi = tenantApiOf(auth)
        if (auth?.type !== "oauth" || !Array.isArray(auth.cookies) || !auth.cookies.length || !tenantApi) {
          return {
            baseURL: GATEWAY_BASE,
            apiKey: "dumate-enterprise",
            async fetch() {
              return new Response(
                JSON.stringify({
                  error: {
                    message: !tenantApi
                      ? "缺少租户 API 基址（tenantApi）。桌面端登录会自动从 auth.json 读取；手动登录需在 Cookie 串里附带 tenantApi=https://<租户域名>/api/dumate-enterprise/app"
                      : "DuMate 企业版未登录，请先在 Magpie 登录",
                    type: "authentication_error",
                  },
                }),
                { status: 401, headers: { "Content-Type": "application/json", "X-Magpie-Sign-In": "expired" } },
              )
            },
          }
        }
        const cookies = auth.cookies
        return {
          baseURL: GATEWAY_BASE,
          apiKey: "dumate-enterprise",
          async fetch(input, init = {}) {
            const req = input instanceof Request ? input : null
            let bodyText = init?.body
            if (bodyText === undefined && req) bodyText = await req.clone().text()
            let cred
            try {
              cred = await fetchGatewayToken(cookieHeaderOf(cookies), tenantApi)
            } catch (e) {
              const expired = e?.signIn === "expired"
              return new Response(
                JSON.stringify({ error: { message: e?.message ?? String(e), type: expired ? "authentication_error" : "api_error" } }),
                { status: expired ? 401 : 502, headers: { "Content-Type": "application/json", "X-Magpie-Sign-In": expired ? "expired" : "kept" } },
              )
            }
            const headers = new Headers(init?.headers ?? req?.headers)
            headers.set("Authorization", `Bearer ${cred.token}`)
            headers.set("Content-Type", "application/json")
            headers.set("X-Dumate-Prd-Source", "enterprise")
            headers.set("X-Dumate-Tenant-Id", String(auth?.tenantId ?? process.env.DUMATE_ENTERPRISE_TENANT_ID ?? ""))
            headers.delete("x-api-key")
            headers.delete("content-length")
            const res = await fetch(req ? req.url : input, {
              ...init,
              method: init?.method ?? req?.method ?? "POST",
              headers,
              body: bodyText,
            })
            if (res.status === 401) {
              tokenCache.delete(cookieHeaderOf(cookies))
              return new Response(
                JSON.stringify({ error: { message: "DuMate 企业版 gateway token 已失效并清除缓存，请重试或重新登录", type: "authentication_error" } }),
                { status: 401, headers: { "Content-Type": "application/json", "X-Magpie-Sign-In": "expired" } },
              )
            }
            return res
          },
        }
      },
      async usage(getAuth) {
        let auth
        try {
          auth = await getAuth()
        } catch (e) {
          return { error: cardText(e?.message) || "登录态读取失败", signIn: e?.signIn === "expired" ? "expired" : "kept" }
        }
        const tenantApi = tenantApiOf(auth)
        if (auth?.type !== "oauth" || !Array.isArray(auth.cookies) || !auth.cookies.length || !tenantApi) {
          return { error: "没有登录信息或缺少 tenantApi，请先在 Magpie 登录", signIn: "kept" }
        }
        try {
          const cookies = await consoleCookies(auth)
          const header = cookieHeaderOf(cookies)
          let userId = String(auth?.userId ?? "")
          if (!userId) {
            // Resolve the current user id from the whoami endpoint.
            const me = await consoleGet(`${tenantApi}/v1/user`, header)
            userId = String(me?.userId ?? "")
            if (!userId) throw new Error("无法确定 userId")
          }
          const info = await consoleGet(`${tenantApi}/users/${encodeURIComponent(userId)}/info`, header)
          const uc = info?.userCredits ?? {}
          const total = Number(uc.totalCredits) || 0
          const used = Number(uc.usedCredits) || 0
          const remain = Number(uc.remainingCredits) || Math.max(0, total - used)
          const consume = info?.consume ?? {}
          return {
            plan: `企业席位 · 今日 ${Number(consume.todayCallCount) || 0} 次`,
            balance: `${remain.toFixed(2)} 资源点`,
            windows: [
              {
                name: "Points",
                used: total > 0 ? (100 * used) / total : 0,
                display: `${used.toFixed(2)} / ${total.toFixed(2)}`,
                amount: used,
                limit: total,
                unit: "points",
              },
            ],
            user: auth.name || auth.accountId || "DuMate Enterprise",
            signIn: "kept",
          }
        } catch (e) {
          return { error: cardText(e?.message) || "用量查询失败", signIn: e?.signIn === "expired" ? "expired" : "kept" }
        }
      },
      // No daily check-in exists on the enterprise edition (resource points are
      // organization-purchased), so the hook is intentionally omitted.
      methods: [
        {
          type: "oauth",
          label: "百度搭子企业版桌面端登录态（本机 auth.json，只读复用）",
          authorize: async () => ({
            url: "",
            instructions: "直接复用本机百度搭子（企业版登录）客户端的登录态（解密 auth.json + .cookie-key，只读，不写任何文件）。",
            method: "auto",
            async callback() {
              const d = readDesktopLogin()
              if (!d) {
                return {
                  type: "failed",
                  error: "未检测到本机百度搭子企业版登录态（qianfan-desktop-app/auth.json）。请先安装并登录百度搭子企业版客户端。",
                }
              }
              if (!d.tenantApi) {
                return { type: "failed", error: "auth.json 中缺少 enterpriseApiBaseUrl，无法确定租户 API 基址" }
              }
              // Probe whoami: validates the cookie and captures tenantId/userId
              // in one call (tenantId is required by the chat gateway headers).
              const header = cookieHeaderOf(d.cookies)
              let me = null
              try {
                me = await consoleGet(`${d.tenantApi}/v1/user`, header)
              } catch (e) {
                return { type: "failed", error: `登录态验证失败：${e?.message ?? e}` }
              }
              const tenantId = String(me?.tenantId ?? "")
              const userId = String(me?.userId ?? d.userId ?? "")
              if (!tenantId || !userId) {
                return { type: "failed", error: "租户身份探测失败（/v1/user 缺少 tenantId/userId）" }
              }
              return {
                type: "success",
                access: "cookie:" + header,
                refresh: "",
                expires: 0,
                source: "desktop",
                accountId: d.accountId || PROVIDER_NAME,
                userId,
                tenantApi: d.tenantApi,
                tenantId,
                name: String(me?.displayName ?? d.name ?? ""),
                cookies: d.cookies,
              }
            },
          }),
        },
        {
          type: "oauth",
          label: "粘贴 auth.json 内容（自动计算鉴权，需 .cookie-key）",
          authorize: async () => ({
            url: "",
            instructions:
              "1. 打开本机 qianfan-desktop-app/auth.json，复制完整内容粘贴到下方。\n" +
              "2. 提供 .cookie-key（32 字节 AES 密钥，解密 cookies 必需，三选一）：\n" +
              "   a. 在粘贴的 JSON 顶层加一行 \"_cookieKeyBase64\": \"<.cookie-key 文件内容转 base64>\"\n" +
              "   b. 环境变量 DUMATE_COOKIE_KEY_BASE64（不便内联时用）\n" +
              "   c. auth.json 与 .cookie-key 在同一台机器时，插件会从同目录自动读取\n" +
              "3. 插件自动：从 enterpriseApiBaseUrl 算租户 API 基址 → 从 bceUserId 算 userId →\n" +
              "   解密 cookies → 调 /v1/user 探测 tenantId/displayName → 完成登录。",
            method: "code",
            async callback(input) {
              const raw = String(input ?? "").trim()
              let auth
              try {
                auth = JSON.parse(raw)
              } catch {
                return { type: "failed", error: "无法解析为 JSON，请粘贴 auth.json 的完整内容" }
              }
              const cookiesField = auth?.cookies
              if (typeof cookiesField !== "string" || !cookiesField) {
                return { type: "failed", error: "auth.json 缺少 cookies 字段" }
              }
              // ---- resolve the 32-byte key: inline > env > local file ----
              let key = null
              const inlineB64 = String(auth._cookieKeyBase64 ?? "").trim()
              if (inlineB64) {
                try { key = Buffer.from(inlineB64, "base64") } catch { key = null }
              }
              if (!key || key.length !== 32) {
                const envB64 = String(process.env.DUMATE_COOKIE_KEY_BASE64 ?? "").trim()
                if (envB64) {
                  try { key = Buffer.from(envB64, "base64") } catch { key = null }
                }
              }
              if (!key || key.length !== 32) {
                try {
                  const k = readFileSync(join(desktopUserDataDir(), ".cookie-key"))
                  if (k.length === 32) key = k
                } catch { key = null }
              }
              if (!key || key.length !== 32) {
                return {
                  type: "failed",
                  error: "未取得 .cookie-key（需 32 字节）。请在 JSON 顶层加 \"_cookieKeyBase64\": \"<.cookie-key的base64>\"，"
                    + "或设环境变量 DUMATE_COOKIE_KEY_BASE64，或把 auth.json 与 .cookie-key 放同一台机器的 qianfan-desktop-app 目录。",
                }
              }
              // ---- decrypt cookies (same AAD-less AES-256-GCM as desktop) ----
              let cookies
              try {
                const buf = Buffer.from(cookiesField, "base64")
                const d = createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12))
                d.setAuthTag(buf.subarray(12, 28))
                cookies = JSON.parse(Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString("utf8"))
              } catch (e) {
                return { type: "failed", error: `cookies 解密失败（确认 _cookieKeyBase64 是 .cookie-key 的 base64）：${e?.message ?? e}` }
              }
              if (!Array.isArray(cookies) || !cookies.length) {
                return { type: "failed", error: "解密结果不是 cookie 数组，key 可能不对" }
              }
              const tenantApi = tenantApiFromBaseUrl(
                auth?.enterpriseApiBaseUrl ?? auth?.accountProfiles?.[0]?.enterpriseApiBaseUrl,
              )
              if (!tenantApi) {
                return { type: "failed", error: "auth.json 缺少 enterpriseApiBaseUrl，无法确定租户 API 基址" }
              }
              const first = auth?.accountProfiles?.[0] ?? {}
              const header = cookieHeaderOf(cookies)
              // Probe whoami: validates the cookie and captures tenant identity.
              let me = null
              try {
                me = await consoleGet(`${tenantApi}/v1/user`, header)
              } catch (e) {
                return { type: "failed", error: `登录态验证失败：${e?.message ?? e}` }
              }
              const tenantId = String(me?.tenantId ?? "")
              const userId = String(me?.userId ?? first.bceUserId ?? "")
              if (!tenantId || !userId) {
                return { type: "failed", error: "租户身份探测失败（/v1/user 缺少 tenantId/userId）" }
              }
              return {
                type: "success",
                access: "cookie:" + header,
                refresh: "",
                expires: 0,
                source: "manual",
                accountId: String(first.bceAccountId ?? userId),
                userId,
                tenantApi,
                tenantId,
                name: String(me?.displayName ?? first.displayName ?? ""),
                cookies,
              }
            },
          }),
        },
      ],
    },
  }
}

export default DuMateEnterprisePlugin

// Test hooks: pure helpers exported for unit tests (no network).
export const _internal = {
  parseCookieString,
  readDesktopLogin,
  tenantApiFromBaseUrl,
  iconFromPluginDir,
  iconFromDesktopApp,
  iconFromBundle,
  FALLBACK_MODELS,
  ENTERPRISE_API_PATH,
}
