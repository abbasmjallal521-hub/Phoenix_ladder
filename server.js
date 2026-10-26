// سلّم الفينيكس — save server for Render (no dependencies).
// - data.json and subs.json live in this same GitHub repo, so nothing is lost when Render restarts.
// - Push notifications use standard Web Push (VAPID). The VAPID key is derived from ADMIN_PASSWORD,
//   so no extra settings are needed. Changing the password means everyone has to tap "enable" again.
// Env vars on Render: ADMIN_PASSWORD, GITHUB_TOKEN, GITHUB_REPO (owner/name).
const http = require("http");
const crypto = require("crypto");
const path = require("path");
const PHRASES = require(path.join(__dirname, "public", "phrases.js"));

const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.ADMIN_PASSWORD || "";
const TOKEN = process.env.GITHUB_TOKEN || "";
const REPO = process.env.GITHUB_REPO || "";
const BRANCH = process.env.GITHUB_BRANCH || "main";
const SITE = process.env.SITE_URL || "https://phoenix-ladder.onrender.com";

const DEFAULT = { name: "سلّم الفينيكس", size: 200, startAccounts: 1, startWallet: 0, targets: [5, 13], entries: [], goals: [], phrases: [] };
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET,POST,OPTIONS", "Access-Control-Allow-Headers": "Content-Type" };

// ---------- GitHub-backed JSON files ----------
const gh = (url, opts = {}) => fetch("https://api.github.com/repos/" + REPO + url, {
  ...opts,
  headers: { Authorization: "Bearer " + TOKEN, Accept: "application/vnd.github+json", "User-Agent": "phoenix-ladder", ...(opts.headers || {}) }
});

function store(file, def) {
  const s = { val: null, sha: null, q: Promise.resolve() };
  s.load = async () => {
    if (s.val) return s.val;
    if (!TOKEN || !REPO) return (s.val = structuredClone(def));
    const r = await gh("/contents/" + file + "?ref=" + BRANCH);
    if (r.status === 404) { s.sha = null; return (s.val = structuredClone(def)); }
    if (!r.ok) throw new Error("github read " + r.status);
    const j = await r.json();
    s.sha = j.sha;
    s.val = Object.assign(structuredClone(def), JSON.parse(Buffer.from(j.content, "base64").toString("utf8")));
    return s.val;
  };
  s.save = msg => (s.q = s.q.then(async () => {
    if (!TOKEN || !REPO) return;
    const body = { message: msg + " [skip render]", branch: BRANCH, content: Buffer.from(JSON.stringify(s.val, null, 2)).toString("base64") };
    if (s.sha) body.sha = s.sha;
    const r = await gh("/contents/" + file, { method: "PUT", body: JSON.stringify(body), headers: { "Content-Type": "application/json" } });
    if (!r.ok) { s.val = null; throw new Error("github write " + r.status); }
    s.sha = (await r.json()).content.sha;
  }));
  return s;
}
const DATA = store("data.json", DEFAULT);
const SUBS = store("subs.json", { list: [] });

// ---------- plan math ----------
function accounts(d) {
  let acc = +d.startAccounts || 0, wal = +d.startWallet || 0;
  const size = +d.size || 200;
  d.entries.slice().sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : 0)).forEach(e => {
    wal += +e.amt || 0;
    while (wal >= size) { wal -= size; acc++; }
  });
  return { acc, wal };
}

// ---------- Web Push (RFC 8291 + VAPID RFC 8292), no libraries ----------
const b64u = b => Buffer.from(b).toString("base64url");
const vapid = (() => {
  if (!PASSWORD) return null;
  let d = Buffer.from(crypto.hkdfSync("sha256", PASSWORD, "phoenix-ladder-vapid", "p256", 32));
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey(); // 65 bytes, uncompressed
  const key = crypto.createPrivateKey({ key: { kty: "EC", crv: "P-256", d: b64u(d), x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33)) }, format: "jwk" });
  return { pub, pubB64: b64u(pub), key };
})();

function vapidHeader(endpoint) {
  const aud = new URL(endpoint).origin;
  const head = b64u(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const claims = b64u(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SITE }));
  const sig = crypto.sign("sha256", Buffer.from(head + "." + claims), { key: vapid.key, dsaEncoding: "ieee-p1363" });
  return "vapid t=" + head + "." + claims + "." + b64u(sig) + ", k=" + vapid.pubB64;
}

const hmac = (k, d) => crypto.createHmac("sha256", k).update(d).digest();
function encrypt(sub, payload) {
  const uaPub = Buffer.from(sub.keys.p256dh, "base64url");
  const auth = Buffer.from(sub.keys.auth, "base64url");
  const as = crypto.createECDH("prime256v1"); as.generateKeys();
  const asPub = as.getPublicKey();
  const shared = as.computeSecret(uaPub);
  const ikm = hmac(hmac(auth, shared), Buffer.concat([Buffer.from("WebPush: info\0"), uaPub, asPub, Buffer.from([1])]));
  const salt = crypto.randomBytes(16);
  const prk = hmac(salt, ikm);
  const cek = hmac(prk, Buffer.from("Content-Encoding: aes128gcm\0\x01")).subarray(0, 16);
  const nonce = hmac(prk, Buffer.from("Content-Encoding: nonce\0\x01")).subarray(0, 12);
  const c = crypto.createCipheriv("aes-128-gcm", cek, nonce);
  const body = Buffer.concat([c.update(Buffer.concat([Buffer.from(payload), Buffer.from([2])])), c.final(), c.getAuthTag()]);
  const rs = Buffer.alloc(4); rs.writeUInt32BE(4096);
  return Buffer.concat([salt, rs, Buffer.from([asPub.length]), asPub, body]);
}

async function pushOne(sub, payload) {
  const r = await fetch(sub.endpoint, {
    method: "POST",
    headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "86400", Urgency: "high", Authorization: vapidHeader(sub.endpoint) },
    body: encrypt(sub, payload)
  });
  return r.status;
}

async function notify(title, body) {
  if (!vapid) return;
  try {
    const s = await SUBS.load();
    if (!s.list.length) return;
    const msg = JSON.stringify({ title, body, url: SITE });
    const dead = [];
    await Promise.all(s.list.map(async sub => {
      try { const st = await pushOne(sub, msg); if (st === 404 || st === 410) dead.push(sub.endpoint); }
      catch (e) { console.error("push", e.message); }
    }));
    if (dead.length) { s.list = s.list.filter(x => !dead.includes(x.endpoint)); await SUBS.save("drop old devices"); }
  } catch (e) { console.error("notify", e); }
}

// ---------- HTTP ----------
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
const id = () => Date.now().toString(36) + crypto.randomBytes(2).toString("hex");
const money = v => "$" + (Math.round(v * 100) / 100).toLocaleString("en-US");
const P = (kind, vars, extra) => PHRASES.pick("ar", kind, vars, extra);

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x");
    if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }
    if (url.pathname === "/api/ping") { DATA.load().catch(() => {}); SUBS.load().catch(() => {}); return send(res, 200, { ok: true }); }
    if (req.method === "GET" && url.pathname === "/api/data") return send(res, 200, await DATA.load());
    if (req.method === "GET" && url.pathname === "/api/vapid") return send(res, 200, { key: vapid ? vapid.pubB64 : null });
    if (req.method === "GET" && url.pathname === "/") { res.writeHead(200, { "Content-Type": "text/plain" }); return res.end("ok"); }

    if (req.method === "POST" && url.pathname === "/api/subscribe") {
      const b = await readBody(req);
      const sub = b.subscription;
      if (!sub || typeof sub.endpoint !== "string" || !/^https:\/\//.test(sub.endpoint) || !sub.keys || !sub.keys.p256dh || !sub.keys.auth)
        return send(res, 400, { error: "bad subscription" });
      const s = await SUBS.load();
      if (!s.list.some(x => x.endpoint === sub.endpoint)) {
        if (s.list.length >= 200) s.list.shift();
        s.list.push({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } });
        await SUBS.save("new device");
      }
      if (b.test) pushOne(s.list.find(x => x.endpoint === sub.endpoint), JSON.stringify({ title: "🔔 تمام!", body: "رح يوصلك كل شي جديد بالفينيكس 🔥", url: SITE })).catch(() => {});
      return send(res, 200, { ok: true });
    }

    if (req.method === "POST" && url.pathname.startsWith("/api/")) {
      const b = await readBody(req);
      if (!PASSWORD || b.password !== PASSWORD) return send(res, 401, { error: "كلمة السر غلط" });
      const data = await DATA.load();
      data.goals = data.goals || []; data.phrases = data.phrases || [];
      const action = url.pathname.slice(5);
      const before = accounts(data).acc;
      let note = null;

      if (action === "login") return send(res, 200, { ok: true });
      if (action === "entry") {
        const amt = num(b.amt);
        if (amt === null || !isDate(b.d)) return send(res, 400, { error: "حط تاريخ ومبلغ صح" });
        data.entries.push({ id: id(), d: b.d, amt, note: String(b.note || "").slice(0, 80) });
        await DATA.save("entry " + b.d);
        const after = accounts(data).acc;
        if (after > before) note = ["👶 انخلق بيبي جديد! صاروا " + after, P("baby", { n: after })];
        else if (amt > 0) note = ["💸 نزل " + money(amt) + " عالواليت", P("money", {}, data.phrases)];
        else note = ["😴 يوم صفر", P("zero")];
      } else if (action === "delete") {
        data.entries = data.entries.filter(e => e.id !== b.id);
        await DATA.save("delete entry");
      } else if (action === "settings") {
        const t = (Array.isArray(b.targets) ? b.targets : []).map(Number).filter(n => n > 0);
        data.name = String(b.name || data.name).slice(0, 40);
        data.size = num(b.size, 1) ?? data.size;
        data.startAccounts = num(b.startAccounts) ?? data.startAccounts;
        data.startWallet = num(b.startWallet) ?? data.startWallet;
        if (t.length) data.targets = [...new Set(t)].sort((x, y) => x - y);
        await DATA.save("settings");
      } else if (action === "goalAdd") {
        const target = num(b.target, 0.01), name = String(b.name || "").trim().slice(0, 40);
        if (!name || target === null) return send(res, 400, { error: "حط اسم الهدف وقديش بدّو" });
        data.goals.push({ id: id(), name, target, saved: 0, emoji: String(b.emoji || "🎯").slice(0, 4) });
        await DATA.save("goal add");
        note = ["🎯 هدف جديد: " + name, "بدنا نعبّي " + money(target) + ". يلا يا زلم"];
      } else if (action === "goalFill") {
        const g = data.goals.find(x => x.id === b.id), amt = num(b.amt);
        if (!g || amt === null) return send(res, 400, { error: "حط مبلغ صح" });
        const was = g.saved >= g.target;
        g.saved = Math.max(0, Math.round((g.saved + amt) * 100) / 100);
        await DATA.save("goal fill");
        if (!was && g.saved >= g.target) note = [g.emoji + " " + g.name + " تعبّى! 🏆", P("goal", { g: g.name })];
        else note = [g.emoji + " " + g.name + ": +" + money(amt), P("fill", { g: g.name, s: money(g.saved), t: money(g.target) })];
      } else if (action === "goalDel") {
        data.goals = data.goals.filter(x => x.id !== b.id);
        await DATA.save("goal delete");
      } else if (action === "phraseAdd") {
        const t = String(b.text || "").trim().slice(0, 160);
        if (!t) return send(res, 400, { error: "اكتب العبارة" });
        data.phrases.push(t);
        await DATA.save("phrase add");
      } else if (action === "phraseDel") {
        data.phrases.splice(+b.i, 1);
        await DATA.save("phrase delete");
      } else if (action === "testPush") {
        note = ["🔥 تجربة", P("money", {}, data.phrases)];
      } else return send(res, 404, { error: "not found" });

      send(res, 200, data);
      if (note && b.notify !== false) notify(note[0], note[1]);
      return;
    }
    res.writeHead(404); res.end("not found");
  } catch (e) {
    console.error(e);
    DATA.val = null; // reload from GitHub next time
    send(res, 500, { error: "صار خطأ، جرّب كمان مرة" });
  }
}).listen(PORT, () => console.log("listening on " + PORT));

module.exports = { encrypt, vapid, vapidHeader };
