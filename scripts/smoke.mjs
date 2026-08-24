const base = process.env.SMOKE_BASE ?? "http://127.0.0.1:8788";
const adminKey = process.env.SMOKE_ADMIN_KEY ?? "combatforge-ci-admin-key-0000000000000000";
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

let response = await fetch(`${base}/health`);
assert(response.status === 200 && (await response.json()).ok === true, "reporter health check failed");

response = await fetch(`${base}/`);
let html = await response.text();
assert(response.status === 200 && html.includes("Do not include your name"), "report form failed");
assert(response.headers.get("content-security-policy")?.includes("script-src 'none'"),
  "report form security headers failed");

response = await fetch(`${base}/submit`, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "192.0.2.10" },
  body: new URLSearchParams({ summary: "bad media", media_url: "http://example.com/capture.png" }),
});
assert(response.status === 400, "reporter accepted a non-HTTPS media link");

for (let index = 0; index < 5; index += 1) {
  const summary = index === 0 ? "<img src=x onerror=alert(1)>" : `CI report ${index + 1}`;
  response = await fetch(`${base}/submit`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "192.0.2.10" },
    body: new URLSearchParams({
      summary,
      actual: "The arena behaved unexpectedly.",
      severity: "High",
      version: "0.1.0-alpha.20",
      platform: "Windows",
    }),
  });
  assert(response.status === 200 && (await response.text()).includes("Report received"),
    `valid report ${index + 1} failed`);
}

response = await fetch(`${base}/submit`, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded", "CF-Connecting-IP": "192.0.2.10" },
  body: new URLSearchParams({ summary: "sixth report", severity: "Medium" }),
});
assert(response.status === 429, "five-per-window reporter rate limit was not enforced");

response = await fetch(`${base}/admin/login`, {
  method: "POST",
  headers: { "content-type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({ password: adminKey }),
  redirect: "manual",
});
const cookie = (response.headers.get("set-cookie") ?? "").split(";")[0];
assert(response.status === 303 && cookie.startsWith("cf_admin="), "administrator login failed");

response = await fetch(`${base}/admin`, { headers: { cookie } });
html = await response.text();
assert(response.status === 200 && html.includes("CI report 5"), "administrator inbox did not show reports");
assert(html.includes("&lt;img src=x onerror=alert(1)&gt;") && !html.includes("<img src=x"),
  "administrator inbox rendered reporter HTML");

console.log("PASS local reporter Worker, D1 writes, rate limit, and administrator inbox smoke");
