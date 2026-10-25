// سلّم الفينيكس — small server for Render.
// The data lives in data.json inside this same GitHub repo, so nothing is lost when Render restarts.
// Env vars (set them on Render): ADMIN_PASSWORD, GITHUB_TOKEN, GITHUB_REPO (owner/name).
// The page itself is a Render static site (public/) that reads data.json straight from GitHub, so it opens instantly.
const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.ADMIN_PASSWORD || "";
const TOKEN = process.env.GITHUB_TOKEN || "";
const REPO = process.env.GITHUB_REPO || "";
const BRANCH = process.env.GITHUB_BRANCH || "main";
const FILE = "data.json";

const DEFAULT = { name: "سلّم الفينيكس", size: 200, startAccounts: 1, startWallet: 0, targets: [5, 13], entries: [] };
let data = null, sha = null, writing = Promise.resolve();
const page = fs.readFileSync(path.join(__dirname, "public", "index.html"));
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type" };

const gh = (url, opts = {}) => fetch("https://api.github.com/repos/" + REPO + url, {
  ...opts,
  headers: { Authorization: "Bearer " + TOKEN, Accept: "application/vnd.github+json", "User-Agent": "phoenix-ladder", ...(opts.headers || {}) }
});

async function load() {
  if (data) return data;
  if (!TOKEN || !REPO) { data = { ...DEFAULT }; return data; }
  const r = await gh("/contents/" + FILE + "?ref=" + BRANCH);
  if (r.status === 404) { data = { ...DEFAULT }; sha = null; return data; }
  if (!r.ok) throw new Error("github read " + r.status);
  const j = await r.json();
  sha = j.sha;
  data = { ...DEFAULT, ...JSON.parse(Buffer.from(j.content, "base64").toString("utf8")) };
  return data;
}

function save(msg) {
  writing = writing.then(async () => {
    if (!TOKEN || !REPO) return;
    const body = { message: msg + " [skip render]", branch: BRANCH, content: Buffer.from(JSON.stringify(data, null, 2)).toString("base64") };
    if (sha) body.sha = sha;
    const r = await gh("/contents/" + FILE, { method: "PUT", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
    if (!r.ok) throw new Error("github write " + r.status);
    sha = (await r.json()).content.sha;
  });
  return writing;
}

function send(res, code, obj) {
  res.writeHead(code, { ...CORS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((ok, bad) => {
    let s = "";
    req.on("data", c => { s += c; if (s.length > 1e5) req.destroy(); });
    req.on("end", () => { try { ok(JSON.parse(s || "{}")); } catch (e) { bad(e); } });
  });
}

const num = (v, min = 0) => { const n = Number(v); return Number.isFinite(n) && n >= min ? n : null; };
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(String(s || ""));

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }
    if (url.pathname === "/api/ping") { load().catch(() => {}); return send(res, 200, { ok: true }); }
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(page);
    }
    if (req.method === "GET" && url.pathname === "/api/data") return send(res, 200, await load());

    if (req.method === "POST" && url.pathname.startsWith("/api/")) {
      const b = await readBody(req);
      if (!PASSWORD || b.password !== PASSWORD) return send(res, 401, { error: "كلمة السر غلط" });
      await load();
      const action = url.pathname.slice(5);
      if (action === "login") return send(res, 200, { ok: true });
      if (action === "entry") {
        const amt = num(b.amt);
        if (amt === null || !isDate(b.d)) return send(res, 400, { error: "حط تاريخ ومبلغ صح" });
        data.entries.push({ id: Date.now().toString(36), d: b.d, amt, note: String(b.note || "").slice(0, 80) });
        await save("entry " + b.d);
      } else if (action === "delete") {
        data.entries = data.entries.filter(e => e.id !== b.id);
        await save("delete entry");
      } else if (action === "settings") {
        const t = (Array.isArray(b.targets) ? b.targets : []).map(Number).filter(n => n > 0);
        data.name = String(b.name || data.name).slice(0, 40);
        data.size = num(b.size, 1) ?? data.size;
        data.startAccounts = num(b.startAccounts) ?? data.startAccounts;
        data.startWallet = num(b.startWallet) ?? data.startWallet;
        if (t.length) data.targets = [...new Set(t)].sort((x, y) => x - y);
        await save("settings");
      } else return send(res, 404, { error: "not found" });
      return send(res, 200, data);
    }
    res.writeHead(404); res.end("not found");
  } catch (e) {
    console.error(e);
    data = null; // reload from GitHub next time
    send(res, 500, { error: "صار خطأ، جرّب كمان مرة" });
  }
}).listen(PORT, () => console.log("listening on " + PORT));
