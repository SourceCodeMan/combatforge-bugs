import worker from "../src/index.js";


const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const ctx = { waitUntil() {} };
const configured = {
  DB: {},
  IP_SALT: "test-salt-which-is-long-enough",
  ADMIN_KEY: "test-admin-key-which-is-at-least-32-characters",
  DISCORD_WEBHOOK_URL: "https://discord.invalid",
};

let response = await worker.fetch(new Request("https://report.test/"), configured, ctx);
let body = await response.text();
assert(response.status === 200 && body.includes("Do not include your name"), "public report form failed");
for (const header of [
  "content-security-policy",
  "permissions-policy",
  "referrer-policy",
  "strict-transport-security",
  "x-content-type-options",
  "x-frame-options",
]) {
  assert(response.headers.has(header), `public form lacks ${header}`);
}
assert(response.headers.get("content-security-policy")?.includes("script-src 'none'"),
  "public form CSP permits scripts");

response = await worker.fetch(new Request("https://report.test/health"), configured, ctx);
assert(response.status === 200 && (await response.json()).ok === true, "configured health check failed");
response = await worker.fetch(new Request("https://report.test/health"), {
  ...configured,
  ADMIN_KEY: "weak",
}, ctx);
assert(response.status === 503 && (await response.json()).ok === false,
  "health check accepted a weak administrator secret");

response = await worker.fetch(new Request("https://report.test/submit", {
  method: "POST",
  headers: { "content-type": "text/plain" },
  body: "summary=test",
}), configured, ctx);
assert(response.status === 415, "report endpoint accepted the wrong content type");

response = await worker.fetch(new Request("https://report.test/submit", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ summary: "test", media_url: "http://example.com/file" }),
}), configured, ctx);
assert(response.status === 400, "report endpoint accepted a non-HTTPS media URL");

const originalConsoleError = console.error;
let configurationErrorLogged = false;
console.error = (...args) => {
  if (args.join(" ").includes("rate-limit configuration missing")) configurationErrorLogged = true;
  else originalConsoleError(...args);
};
try {
  response = await worker.fetch(new Request("https://report.test/submit", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ summary: "test" }),
  }), { ...configured, IP_SALT: "" }, ctx);
} finally {
  console.error = originalConsoleError;
}
assert(response.status === 503, "report submission failed open without rate-limit configuration");
assert(configurationErrorLogged, "missing rate-limit configuration was not logged for operators");

response = await worker.fetch(new Request("https://report.test/admin", {
  headers: { cookie: "cf_admin=%E0%A4%A" },
}), configured, ctx);
assert(response.status === 303 && response.headers.get("location") === "/admin/login",
  "malformed administrator cookie was not rejected cleanly");

response = await worker.fetch(new Request("https://report.test/admin/login", {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ password: "weak" }),
}), { ...configured, ADMIN_KEY: "weak" }, ctx);
assert(response.status === 503, "administrator login accepted weak server-side configuration");

response = await worker.fetch(new Request("https://report.test/missing"), configured, ctx);
assert(response.status === 404, "unknown reporter route did not return 404");

console.log("PASS reporter surface, fail-safe configuration, and browser security gates");
