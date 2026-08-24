/**
 * CombatForge — Bug Report Worker
 * Serves a styled bug-report form, stores each submission in D1, and posts it to
 * a Discord webhook (#bug-reports). The private inbox uses a short-lived, HttpOnly
 * admin session; the administrator secret never appears in a URL.
 *
 * Bindings:  DB (D1)
 * Secrets:   DISCORD_WEBHOOK_URL, ADMIN_KEY, IP_SALT
 */

const VERSION_DEFAULT = "0.1.0-alpha.19";
const SEVERITIES = ["Low", "Medium", "High", "Crash"];
const LIMITS = {
  summary: 200, steps: 4000, expected: 1000, actual: 2000,
  version: 40, platform: 40, severity: 20, media_url: 500,
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (request.method === "GET" && p === "/") return htmlResponse(renderForm());
      if (request.method === "POST" && p === "/submit") return await handleSubmit(request, env, ctx);
      if (request.method === "GET" && p === "/admin/login") return htmlResponse(renderAdminLogin());
      if (request.method === "POST" && p === "/admin/login") return await handleAdminLogin(request, env);
      if (request.method === "POST" && p === "/admin/logout") return handleAdminLogout();
      if (request.method === "GET" && p === "/admin") return await handleAdmin(request, env);
      if (request.method === "GET" && p === "/health") {
        const configured = !!(env.DB && env.IP_SALT && env.ADMIN_KEY && env.DISCORD_WEBHOOK_URL);
        return new Response(JSON.stringify({ ok: configured }), {
          status: configured ? 200 : 503,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
        });
      }
      return new Response("Not found", { status: 404 });
    } catch (_) {
      return new Response("Server error", { status: 500 });
    }
  },
};

/* ---------------- helpers ---------------- */
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function clamp(v, n) {
  const s = String(v ?? "").trim();
  return s.length > n ? s.slice(0, n) : s;
}
function cut(v, n) {
  const s = String(v ?? "");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
      "x-frame-options": "DENY",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'none'; style-src 'unsafe-inline'",
      "permissions-policy": "camera=(), geolocation=(), microphone=()",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
    },
  });
}
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length || a.length === 0) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
function isAllowedMediaUrl(s) {
  if (!s) return true; // optional field
  try {
    const u = new URL(s);
    if (u.protocol !== "https:") return false;
    const host = u.hostname.toLowerCase();
    return [
      "youtube.com", "www.youtube.com", "youtu.be", "imgur.com", "i.imgur.com",
      "streamable.com", "www.streamable.com", "cdn.discordapp.com", "media.discordapp.net",
    ].includes(host);
  }
  catch { return false; }
}

function cookieValue(request, name) {
  const cookies = request.headers.get("cookie") || "";
  for (const part of cookies.split(";")) {
    const at = part.indexOf("=");
    if (at > 0 && part.slice(0, at).trim() === name) {
      try { return decodeURIComponent(part.slice(at + 1).trim()); }
      catch { return ""; }
    }
  }
  return "";
}

async function validAdminSession(request, env) {
  if (!env.ADMIN_KEY) return false;
  const token = cookieValue(request, "cf_admin");
  const [issuedRaw, signature, extra] = token.split(".");
  const issued = Number(issuedRaw);
  const now = Math.floor(Date.now() / 1000);
  if (extra !== undefined || !Number.isInteger(issued) || issued > now + 60 || now - issued > 3600) return false;
  return safeEqual(signature, await hmacHex(env.ADMIN_KEY, `combatforge-admin:${issued}`));
}
// Neutralize Discord markdown so reporter text can't inject masked links / formatting.
function mdEsc(s) {
  return String(s ?? "").replace(/[\\*_~`>|\[\]()@#-]/g, (c) => "\\" + c);
}
// Read the request body but stop hard at maxBytes — never trust Content-Length as the gate.
async function readBodyCapped(request, maxBytes) {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { await reader.cancel(); return null; }
      chunks.push(value);
    }
  } catch (_) { return null; }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.byteLength; }
  return new TextDecoder().decode(buf);
}

/* ---------------- submit ---------------- */
async function handleSubmit(request, env, ctx) {
  // Only accept the form's own content type; refuse anything else before reading the body.
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (!ct.includes("application/x-www-form-urlencoded")) {
    return htmlResponse(renderError("Unexpected submission."), 415);
  }
  // Fast-path reject if the client advertises an oversized body...
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > 25000) return htmlResponse(renderError("That report is too large."), 413);
  // ...but the real gate counts actual bytes, so a missing/chunked length can't
  // smuggle a huge body into the parser.
  const text = await readBodyCapped(request, 25000);
  if (text === null) return htmlResponse(renderError("That report is too large."), 413);

  const form = new URLSearchParams(text);

  // Honeypot: real users never fill this hidden field.
  if (clamp(form.get("website"), 100) !== "") return htmlResponse(renderThanks());

  const d = {
    summary: clamp(form.get("summary"), LIMITS.summary),
    steps: clamp(form.get("steps"), LIMITS.steps),
    expected: clamp(form.get("expected"), LIMITS.expected),
    actual: clamp(form.get("actual"), LIMITS.actual),
    version: clamp(form.get("version"), LIMITS.version) || VERSION_DEFAULT,
    platform: clamp(form.get("platform"), LIMITS.platform) || "Windows",
    severity: clamp(form.get("severity"), LIMITS.severity),
    media_url: clamp(form.get("media_url"), LIMITS.media_url),
  };
  if (!d.summary) return htmlResponse(renderError("Please add a short summary of the bug."), 400);
  if (!SEVERITIES.includes(d.severity)) d.severity = "Medium";
  if (!isAllowedMediaUrl(d.media_url)) {
    return htmlResponse(renderError("Use an HTTPS YouTube, Imgur, Streamable, or Discord media link."), 400);
  }

  const host = new URL(request.url).hostname;
  const ip = request.headers.get("CF-Connecting-IP") ||
    (["127.0.0.1", "localhost"].includes(host) ? "local-dev" : "");
  // Abuse protection is required, not optional. A production deployment missing its salt or
  // Cloudflare client-IP header refuses submissions instead of silently disabling rate limiting.
  if (!ip || !env.IP_SALT) {
    console.error("bug reporter rate-limit configuration missing");
    return htmlResponse(renderError("Reporting is temporarily unavailable. Please try again later."), 503);
  }
  const ipHash = await sha256Hex(ip + "|" + env.IP_SALT);
  const windowStart = Math.floor(Date.now() / 300000) * 300000;
  const nonce = crypto.randomUUID();

  let id = null;
  try {
    const results = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO bug_rate_limits (ip_hash, window_start, count, last_nonce)
         VALUES (?, ?, 1, ?)
         ON CONFLICT(ip_hash, window_start) DO UPDATE SET
           count = count + 1, last_nonce = excluded.last_nonce
         WHERE bug_rate_limits.count < 5`)
        .bind(ipHash, windowStart, nonce),
      env.DB.prepare(
        `INSERT INTO bugs
           (summary, steps, expected, actual, version, platform, severity, media_url,
            contact, ip_hash, user_agent)
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, '', '', ''
         WHERE EXISTS (
           SELECT 1 FROM bug_rate_limits
           WHERE ip_hash = ? AND window_start = ? AND last_nonce = ?)`)
        .bind(d.summary, d.steps, d.expected, d.actual, d.version, d.platform, d.severity,
          d.media_url, ipHash, windowStart, nonce),
    ]);
    if ((results[0]?.meta?.changes ?? 0) === 0) {
      return htmlResponse(renderError("Whoa — too many reports at once. Give it a few minutes and try again."), 429);
    }
    id = results[1]?.meta?.last_row_id ?? null;
    // Retain only short-lived abuse counters, detached from the report itself.
    ctx.waitUntil(env.DB.prepare(
      `DELETE FROM bug_rate_limits WHERE window_start < ?`).bind(windowStart - 24 * 60 * 60 * 1000).run());
  } catch (error) {
    console.error("bug report database write failed", String(error));
    return htmlResponse(renderError("Couldn't save that — please try again in a moment."), 500);
  }

  // Notify Discord out-of-band; never fail the user if the webhook is down.
  if (env.DISCORD_WEBHOOK_URL) ctx.waitUntil(postToDiscord(env.DISCORD_WEBHOOK_URL, id, d));

  return htmlResponse(renderThanks());
}

async function postToDiscord(webhook, id, d) {
  const color = { Low: 0x8b95a2, Medium: 0xff6a1a, High: 0xff3b1a, Crash: 0xd40000 }[d.severity] || 0xff6a1a;
  const fields = [];
  if (d.steps) fields.push({ name: "Steps", value: cut(mdEsc(d.steps), 1024) });
  if (d.expected) fields.push({ name: "Expected", value: cut(mdEsc(d.expected), 1024), inline: true });
  if (d.actual) fields.push({ name: "Actual", value: cut(mdEsc(d.actual), 1024), inline: true });
  fields.push({ name: "Version", value: cut(mdEsc(d.version), 60) || "—", inline: true });
  fields.push({ name: "Platform", value: cut(mdEsc(d.platform), 60) || "—", inline: true });
  fields.push({ name: "Severity", value: d.severity, inline: true });
  if (d.media_url) fields.push({ name: "Media", value: cut(d.media_url, 1024) });

  const payload = {
    username: "CombatForge Bugs",
    allowed_mentions: { parse: [] }, // block @everyone/@here/role/user pings from user text
    embeds: [{
      title: cut("🐛 #" + (id ?? "?") + " — " + mdEsc(d.summary), 256),
      color,
      fields,
      footer: { text: "CombatForge • alpha bug report" },
      timestamp: new Date().toISOString(),
    }],
  };
  try {
    const response = await fetch(webhook, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`Discord webhook returned ${response.status}`);
  } catch (error) {
    // The report is already durable in D1; surface notification failures to Worker logs/alerts.
    console.error("Discord bug notification failed", String(error));
  }
}

/* ---------------- admin inbox ---------------- */
async function handleAdminLogin(request, env) {
  if (!env.ADMIN_KEY) return htmlResponse(renderError("Admin access is not configured."), 503);
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (!ct.includes("application/x-www-form-urlencoded")) {
    return htmlResponse(renderAdminLogin("Unexpected submission."), 415);
  }
  const text = await readBodyCapped(request, 4096);
  if (text === null) return htmlResponse(renderAdminLogin("Unexpected submission."), 413);
  const password = new URLSearchParams(text).get("password") || "";
  if (!safeEqual(password, env.ADMIN_KEY)) {
    return htmlResponse(renderAdminLogin("Invalid administrator password."), 401);
  }
  const issued = Math.floor(Date.now() / 1000);
  const signature = await hmacHex(env.ADMIN_KEY, `combatforge-admin:${issued}`);
  return new Response(null, {
    status: 303,
    headers: {
      location: "/admin",
      "cache-control": "no-store",
      "set-cookie": `cf_admin=${issued}.${signature}; Path=/admin; Max-Age=3600; HttpOnly; Secure; SameSite=Strict`,
    },
  });
}

function handleAdminLogout() {
  return new Response(null, {
    status: 303,
    headers: {
      location: "/admin/login",
      "cache-control": "no-store",
      "set-cookie": "cf_admin=; Path=/admin; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
    },
  });
}

async function handleAdmin(request, env) {
  if (!await validAdminSession(request, env)) {
    return new Response(null, {
      status: 303,
      headers: { location: "/admin/login", "cache-control": "no-store" },
    });
  }
  try {
    const q = await env.DB.prepare(
      `SELECT id, created_at, severity, version, platform, summary, actual, media_url
       FROM bugs ORDER BY id DESC LIMIT 200`
    ).all();
    return htmlResponse(renderAdmin(q.results || []));
  } catch (error) {
    console.error("admin inbox database read failed", String(error));
    return htmlResponse(renderError("The inbox could not be loaded. Check the Worker logs."), 500);
  }
}

/* ---------------- views ---------------- */
const STYLE = `
:root{--bg:#0b0d10;--ink:#e9edf2;--muted:#8b95a2;--line:rgba(255,255,255,.08);--orange:#ff6a1a;--tan:#c9b48b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);line-height:1.5;
  font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background-image:linear-gradient(rgba(255,255,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.04) 1px,transparent 1px);
  background-size:44px 44px;background-attachment:fixed}
.wrap{max-width:660px;margin:0 auto;padding:40px 20px 64px}
.brand{font-weight:800;letter-spacing:.02em;text-transform:uppercase;font-size:28px;margin:0}
.brand .f{color:var(--orange)}
.kick{font-size:12px;letter-spacing:.24em;text-transform:uppercase;color:var(--tan);margin:2px 0 22px}
h1{font-size:22px;margin:0 0 6px}
p.sub{color:var(--muted);margin:0 0 24px}
label{display:block;font-size:13px;font-weight:600;letter-spacing:.02em;margin:18px 0 6px}
label .req{color:var(--orange)}
.hint{font-weight:400;color:var(--muted);font-size:12px}
input,textarea,select{width:100%;background:#12151a;border:1px solid var(--line);border-radius:8px;color:var(--ink);
  padding:11px 12px;font:inherit;font-size:15px}
input:focus,textarea:focus,select:focus{outline:none;border-color:var(--orange)}
textarea{min-height:88px;resize:vertical}
.row{display:flex;gap:12px;flex-wrap:wrap}.row>div{flex:1;min-width:150px}
.hp{position:absolute!important;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden}
button{margin-top:26px;background:var(--orange);color:#140a03;border:0;border-radius:8px;padding:14px 28px;
  font-weight:800;letter-spacing:.06em;text-transform:uppercase;font-size:14px;cursor:pointer}
button:hover{background:#ff7d38}
a{color:var(--orange)}
.card{background:rgba(255,255,255,.02);border:1px solid var(--line);border-radius:12px;padding:28px}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--tan);text-transform:uppercase;font-size:11px;letter-spacing:.1em}
`;

function page(inner, title) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${esc(title || "CombatForge — Report a Bug")}</title><style>${STYLE}</style></head>
<body><div class="wrap">${inner}</div></body></html>`;
}

function renderForm() {
  return page(`
  <p class="brand">Combat<span class="f">Forge</span></p>
  <div class="kick">Alpha Bug Report</div>
  <h1>Found a bug? Tell us.</h1>
  <p class="sub">The more detail you give, the faster we squash it. Fields marked <span style="color:var(--orange)">*</span> are required.</p>
  <form method="POST" action="/submit" autocomplete="off">
    <div class="hp" aria-hidden="true"><label>Leave this empty<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>
    <label>Summary <span class="req">*</span> <span class="hint">— one line</span></label>
    <input type="text" name="summary" maxlength="200" required placeholder="e.g. Game crashes when I place a wall on a ramp">
    <label>Steps to reproduce <span class="hint">— how did it happen?</span></label>
    <textarea name="steps" maxlength="4000" placeholder="1. Start a Build phase&#10;2. Place a ramp&#10;3. Place a wall on top of it …"></textarea>
    <div class="row">
      <div><label>Expected</label><textarea name="expected" maxlength="1000" placeholder="What you thought would happen"></textarea></div>
      <div><label>Actual</label><textarea name="actual" maxlength="2000" placeholder="What actually happened"></textarea></div>
    </div>
    <div class="row">
      <div><label>Severity</label><select name="severity">
        <option>Low</option><option selected>Medium</option><option>High</option><option>Crash</option>
      </select></div>
      <div><label>Version</label><input type="text" name="version" maxlength="40" value="${esc(VERSION_DEFAULT)}"></div>
      <div><label>Platform</label><input type="text" name="platform" maxlength="40" value="Windows"></div>
    </div>
    <label>Screenshot / clip link <span class="hint">— HTTPS YouTube, Imgur, Streamable, or Discord link</span></label>
    <input type="url" name="media_url" maxlength="500" placeholder="https://…">
    <p class="sub" style="margin-top:18px">Do not include your name, email, passwords, account tokens,
      or other personal information. Reports are stored for development and may be forwarded to our
      private Discord bug channel.</p>
    <button type="submit">Submit Report</button>
  </form>`);
}

function renderThanks() {
  return page(`<div class="card">
    <p class="brand">Combat<span class="f">Forge</span></p>
    <h1 style="margin-top:16px">Report received. 🫡</h1>
    <p class="sub">Thanks for helping make CombatForge better.</p>
    <p><a href="/">← Submit another bug</a></p>
  </div>`, "CombatForge — Thanks");
}

function renderError(msg) {
  return page(`<div class="card">
    <p class="brand">Combat<span class="f">Forge</span></p>
    <h1 style="margin-top:16px">Hmm.</h1>
    <p class="sub">${esc(msg)}</p>
    <p><a href="/">← Back to the form</a></p>
  </div>`, "CombatForge — Error");
}

function renderAdminLogin(error = "") {
  return page(`<div class="card">
    <p class="brand">Combat<span class="f">Forge</span></p>
    <div class="kick">Bug Inbox</div>
    <h1>Administrator login</h1>
    ${error ? `<p class="sub" style="color:#ff7a70">${esc(error)}</p>` : ""}
    <form method="POST" action="/admin/login">
      <label>Password</label>
      <input type="password" name="password" required autocomplete="current-password">
      <button type="submit">Open Inbox</button>
    </form>
  </div>`, "CombatForge — Admin Login");
}

function renderAdmin(rows) {
  const sevColor = { Low: "#8b95a2", Medium: "#ff6a1a", High: "#ff3b1a", Crash: "#ff5555" };
  const body = rows.map((r) => `<tr>
    <td>${esc(r.id)}</td>
    <td style="white-space:nowrap">${esc(String(r.created_at || "").replace("T", " ").slice(0, 16))}</td>
    <td style="font-weight:700;color:${sevColor[r.severity] || "#e9edf2"}">${esc(r.severity)}</td>
    <td style="white-space:nowrap">${esc(r.version)}</td>
    <td><strong>${esc(r.summary)}</strong>${r.actual ? `<br><span style="color:#8b95a2">${esc(r.actual)}</span>` : ""}${r.media_url ? `<br><a href="${esc(r.media_url)}" target="_blank" rel="noopener noreferrer nofollow">media ↗</a>` : ""}</td>
  </tr>`).join("");
  return page(`<p class="brand">Combat<span class="f">Forge</span></p>
    <div class="kick">Bug Inbox — ${rows.length} report${rows.length === 1 ? "" : "s"}</div>
    <form method="POST" action="/admin/logout"><button type="submit">Log out</button></form>
    <div class="tablewrap"><table>
      <thead><tr><th>#</th><th>When</th><th>Sev</th><th>Ver</th><th>Bug</th></tr></thead>
      <tbody>${body || `<tr><td colspan="5" style="color:#8b95a2;padding:22px">No bugs yet.</td></tr>`}</tbody>
    </table></div>`, "CombatForge — Bug Inbox");
}
