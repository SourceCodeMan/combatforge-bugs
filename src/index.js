/**
 * CombatForge — Bug Report Worker
 * Serves a styled bug-report form, stores each submission in D1, and posts it to
 * a Discord webhook (#bug-reports). Also a private /admin?key=... inbox view.
 *
 * Bindings:  DB (D1)
 * Secrets:   DISCORD_WEBHOOK_URL, ADMIN_KEY, IP_SALT
 */

const VERSION_DEFAULT = "0.1.0-alpha.1";
const SEVERITIES = ["Low", "Medium", "High", "Crash"];
const LIMITS = {
  summary: 200, steps: 4000, expected: 1000, actual: 2000,
  version: 40, platform: 40, severity: 20, media_url: 500, contact: 120,
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (request.method === "GET" && p === "/") return htmlResponse(renderForm());
      if (request.method === "POST" && p === "/submit") return await handleSubmit(request, env, ctx);
      if (request.method === "GET" && p === "/admin") return await handleAdmin(request, env);
      if (request.method === "GET" && p === "/health") return new Response("ok");
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
    },
  });
}
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function safeEqual(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length || a.length === 0) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
function isHttpUrl(s) {
  if (!s) return true; // optional field
  try { const u = new URL(s); return u.protocol === "http:" || u.protocol === "https:"; }
  catch { return false; }
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
    contact: clamp(form.get("contact"), LIMITS.contact),
  };
  if (!d.summary) return htmlResponse(renderError("Please add a short summary of the bug."), 400);
  if (!SEVERITIES.includes(d.severity)) d.severity = "Medium";
  if (!isHttpUrl(d.media_url)) d.media_url = "";

  const ip = request.headers.get("CF-Connecting-IP") || "";
  // Fail closed: with no salt configured, store NO hash rather than a reversible one.
  const ipHash = (ip && env.IP_SALT) ? await sha256Hex(ip + "|" + env.IP_SALT) : "";
  const ua = clamp(request.headers.get("user-agent"), 300);

  const cols = "summary, steps, expected, actual, version, platform, severity, media_url, contact, ip_hash, user_agent";
  const vals = [d.summary, d.steps, d.expected, d.actual, d.version, d.platform, d.severity, d.media_url, d.contact, ipHash, ua];

  let id = null;
  try {
    let res;
    if (ipHash) {
      // Atomic insert-if-under-limit — no check-then-insert race. Max 5 per hashed IP / 5 min.
      res = await env.DB.prepare(
        `INSERT INTO bugs (${cols})
         SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
         WHERE (SELECT COUNT(*) FROM bugs WHERE ip_hash = ? AND created_at > datetime('now','-5 minutes')) < 5`
      ).bind(...vals, ipHash).run();
      if (!res.meta || res.meta.changes === 0) {
        return htmlResponse(renderError("Whoa — too many reports at once. Give it a few minutes and try again."), 429);
      }
    } else {
      res = await env.DB.prepare(
        `INSERT INTO bugs (${cols}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(...vals).run();
    }
    id = res.meta && res.meta.last_row_id != null ? res.meta.last_row_id : null;
  } catch (_) {
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
  if (d.contact) fields.push({ name: "Reporter", value: cut(mdEsc(d.contact), 256) });

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
    await fetch(webhook, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (_) { /* swallow — the bug is already saved in D1 */ }
}

/* ---------------- admin inbox ---------------- */
async function handleAdmin(request, env) {
  const key = new URL(request.url).searchParams.get("key") || "";
  if (!env.ADMIN_KEY || !safeEqual(key, env.ADMIN_KEY)) {
    return new Response("Unauthorized", { status: 401, headers: { "cache-control": "no-store" } });
  }
  let rows = [];
  try {
    const q = await env.DB.prepare(
      `SELECT id, created_at, severity, version, platform, summary, actual, media_url, contact
       FROM bugs ORDER BY id DESC LIMIT 200`
    ).all();
    rows = q.results || [];
  } catch (_) { /* show empty table */ }
  return htmlResponse(renderAdmin(rows));
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
    <label>Screenshot / clip link <span class="hint">— paste a link (YouTube, Imgur, Streamable…)</span></label>
    <input type="url" name="media_url" maxlength="500" placeholder="https://…">
    <label>Your Discord or email <span class="hint">— optional, so we can follow up</span></label>
    <input type="text" name="contact" maxlength="120" placeholder="@yourhandle">
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

function renderAdmin(rows) {
  const sevColor = { Low: "#8b95a2", Medium: "#ff6a1a", High: "#ff3b1a", Crash: "#ff5555" };
  const body = rows.map((r) => `<tr>
    <td>${esc(r.id)}</td>
    <td style="white-space:nowrap">${esc(String(r.created_at || "").replace("T", " ").slice(0, 16))}</td>
    <td style="font-weight:700;color:${sevColor[r.severity] || "#e9edf2"}">${esc(r.severity)}</td>
    <td style="white-space:nowrap">${esc(r.version)}</td>
    <td><strong>${esc(r.summary)}</strong>${r.actual ? `<br><span style="color:#8b95a2">${esc(r.actual)}</span>` : ""}${r.media_url ? `<br><a href="${esc(r.media_url)}" target="_blank" rel="noopener noreferrer nofollow">media ↗</a>` : ""}</td>
    <td>${esc(r.contact)}</td>
  </tr>`).join("");
  return page(`<p class="brand">Combat<span class="f">Forge</span></p>
    <div class="kick">Bug Inbox — ${rows.length} report${rows.length === 1 ? "" : "s"}</div>
    <div class="tablewrap"><table>
      <thead><tr><th>#</th><th>When</th><th>Sev</th><th>Ver</th><th>Bug</th><th>By</th></tr></thead>
      <tbody>${body || `<tr><td colspan="6" style="color:#8b95a2;padding:22px">No bugs yet.</td></tr>`}</tbody>
    </table></div>`, "CombatForge — Bug Inbox");
}
