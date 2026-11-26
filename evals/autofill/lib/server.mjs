#!/usr/bin/env node
// Autofill eval server.
//
//  - Serves every fixture page on its own hostname (Host-header routing), over
//    HTTPS with a local CA and over plain HTTP, and injects lib/beacon.js.
//  - Collects beacon reports (/__eval/report) and scores runner results
//    (/__eval/result) into results/<runId>/results.jsonl.
//  - Runs real login backends (/api/login, /account.html) so in-core login can
//    be judged by "is the browser signed in", not by a mock.
//
// Usage: node lib/server.mjs [--https-port 8443] [--http-port 8080]
//          [--bind 0.0.0.0] [--public-port 8443] [--allow-host-actions]
import http from "node:http";
import https from "node:https";
import { execFileSync, execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from "node:fs";
import { join, extname } from "node:path";
import { ROOT, loadCorpus, fixtureScenarios, scoreScenario, scoreLive, scoreSave, resolveRef } from "./score.mjs";

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => {
  if (a.startsWith("--")) acc.push([a.slice(2), all[i + 1] && !all[i + 1].startsWith("--") ? all[i + 1] : true]);
  return acc;
}, []));
const HTTPS_PORT = Number(args["https-port"] || process.env.VELA_EVAL_HTTPS_PORT || 8443);
const HTTP_PORT = Number(args["http-port"] || process.env.VELA_EVAL_HTTP_PORT || 8080);
const BIND = args.bind || "0.0.0.0";
const PUBLIC_PORT = Number(args["public-port"] || HTTPS_PORT);
const ALLOW_HOST_ACTIONS = !!args["allow-host-actions"];

const corpus = loadCorpus();
const { manifest, vault, nativeForms, liveSites, liveApps, save } = corpus;
// Every page the server routes: the fill corpus and the save/update corpus.
const ALL_PAGES = [...manifest.pages, ...save.pages];
const PAGES_DIR = join(ROOT, "corpus/pages");
const CACHE = join(ROOT, ".cache");
const RESULTS = join(ROOT, "results");

// ── TLS: one local CA, one leaf cert naming every fixture host ──────────────

export function fixtureHosts() {
  const hosts = new Set(["localhost"]);
  for (const p of ALL_PAGES) if (p.host && p.host !== "*") hosts.add(p.host);
  return [...hosts].sort();
}

function ensureTls() {
  const dir = join(CACHE, "tls");
  mkdirSync(dir, { recursive: true });
  const ca = join(dir, "ca.pem"), caKey = join(dir, "ca-key.pem");
  if (!existsSync(ca)) {
    execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825",
      "-keyout", caKey, "-out", ca, "-subj", "/CN=VELA Autofill Eval Local CA",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], { stdio: "ignore" });
  }
  const hosts = fixtureHosts();
  const san = [...hosts.map((h) => `DNS:${h}`), "IP:127.0.0.1", "IP:10.0.2.2"].join(",");
  const tag = createHash("sha256").update(san).digest("hex").slice(0, 12);
  const cert = join(dir, `leaf-${tag}.pem`), key = join(dir, `leaf-${tag}-key.pem`);
  if (!existsSync(cert)) {
    const csr = join(dir, "leaf.csr"), ext = join(dir, "leaf.ext");
    writeFileSync(ext, `subjectAltName=${san}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n`);
    execFileSync("openssl", ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=vela-autofill-eval"], { stdio: "ignore" });
    // 397 days: the longest validity Apple platforms accept for a leaf.
    execFileSync("openssl", ["x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-days", "397", "-out", cert, "-extfile", ext], { stdio: "ignore" });
  }
  return { cert: readFileSync(cert), key: readFileSync(key), caPath: ca };
}

// ── Run state ───────────────────────────────────────────────────────────────

const runs = new Map(); // run -> Map(pageKey -> merged snapshot)

function recordReport(snap) {
  if (!snap || !snap.run || !snap.page) return;
  if (!runs.has(snap.run)) runs.set(snap.run, new Map());
  const pages = runs.get(snap.run);
  const prev = pages.get(snap.page);
  if (prev) {
    for (const [k, vals] of Object.entries(prev.history || {})) {
      const merged = new Set([...(vals || []), ...((snap.history || {})[k] || [])]);
      snap.history[k] = [...merged];
    }
    snap.firstChangeMs = { ...(prev.firstChangeMs || {}), ...(snap.firstChangeMs || {}) };
    snap.everVelaUi = prev.everVelaUi || snap.velaUi;
    snap.everDropdown = prev.everDropdown || snap.velaDropdown;
  } else {
    snap.everVelaUi = !!snap.velaUi;
    snap.everDropdown = !!snap.velaDropdown;
  }
  pages.set(snap.page, snap);
}

/** One flat field map for a scenario: its own page bare, others '<page>#'. */
export function mergedSnapshot(run, mainPage) {
  const pages = runs.get(run) || new Map();
  const fields = {};
  const valueHistory = [];
  let everVelaUi = false;
  for (const [page, snap] of pages) {
    const prefix = page === mainPage ? "" : `${page}#`;
    for (const [k, f] of Object.entries(snap.fields || {})) fields[prefix + k] = f;
    for (const vals of Object.values(snap.history || {})) valueHistory.push(...vals);
    everVelaUi ||= !!snap.everVelaUi;
  }
  return { fields, valueHistory, everVelaUi, pages: [...pages.keys()] };
}

// ── Login backends (for in-core login and for "did the fill work" checks) ──

const sessions = new Map(); // sid -> { host, loginId, username, ua, ts }
const registrable = (host) => host.split(".").slice(-2).join(".");

function loginForHost(host) {
  return vault.logins.filter((l) => registrable(new URL(l.url).hostname) === registrable(host));
}

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

function parseLoginBody(raw, type) {
  const values = [];
  try {
    if ((type || "").includes("json") || raw.trim().startsWith("{")) {
      const walk = (v) => { if (v && typeof v === "object") Object.values(v).forEach(walk); else if (v != null) values.push(String(v)); };
      walk(JSON.parse(raw));
    } else {
      for (const [, v] of new URLSearchParams(raw)) values.push(v);
    }
  } catch {}
  return values;
}

function cookieSid(req) {
  const m = /(?:^|;\s*)vela_eval_sid=([a-f0-9]+)/.exec(req.headers.cookie || "");
  return m ? m[1] : null;
}

// ── Scenario descriptions for on-device runners ─────────────────────────────

function chooseHint(choose) {
  if (!choose) return null;
  const login = vault.logins.find((l) => l.id === choose);
  if (login) return { type: "login", id: login.id, name: login.name, text: login.username };
  const card = vault.cards.find((c) => c.id === choose);
  if (card) return { type: "card", id: card.id, name: card.name, text: card.number.slice(-4) };
  const [iid, addrId] = choose.split("/");
  const idn = vault.identities.find((i) => i.id === iid);
  if (idn) {
    const addr = idn.addresses.find((a) => a.id === addrId);
    return { type: "identity", id: idn.id, addressId: addrId || null, name: idn.name, text: addr ? addr.label : idn.email };
  }
  return null;
}

function scenarioList(tier, scheme, port) {
  const portPart = (scheme === "https" && port === 443) || (scheme === "http" && port === 80) ? "" : `:${port}`;
  if (tier === "fixture") {
    return fixtureScenarios(manifest).map((p) => ({
      id: p.id, kind: p.kind, tags: p.tags || [], url: `${scheme}://${p.host}${portPart}${p.path}`,
      anchor: p.anchor, steps: p.steps || [{ fill: p.anchor }], choose: chooseHint(p.choose), expect: p.expect || {},
      settleMs: p.settleMs || 0, mustNotOffer: !!p.mustNotOffer, inCore: p.inCore || null,
    }));
  }
  if (tier === "native") {
    return nativeForms.forms.map((f) => ({ ...f, steps: f.steps || [{ fill: f.anchor }], choose: chooseHint(f.choose) }));
  }
  if (tier === "live") return liveSites.sites;
  if (tier === "live-app") return liveApps.apps;
  return [];
}

// ── Results ─────────────────────────────────────────────────────────────────

function writeResult(body) {
  const runId = String(body.runId || "adhoc").replace(/[^A-Za-z0-9._-]/g, "_");
  const dir = join(RESULTS, runId);
  mkdirSync(dir, { recursive: true });
  const rec = { ...body, recordedAt: new Date().toISOString() };
  if (body.tier === "fixture" || body.tier === "native") {
    const scenario = body.tier === "fixture"
      ? manifest.pages.find((p) => p.id === body.scenarioId)
      : nativeForms.forms.find((f) => f.id === body.scenarioId);
    if (!scenario) throw new Error(`unknown scenario ${body.scenarioId}`);
    const merged = body.fields ? { fields: body.fields, valueHistory: body.valueHistory || [], everVelaUi: false } : mergedSnapshot(body.run, scenario.id);
    const offered = body.offered ?? (merged.everVelaUi || null);
    rec.kind = scenario.kind;
    rec.tags = scenario.tags || [];
    rec.fields = merged.fields;
    rec.score = scoreScenario(scenario, merged.fields, {
      offered, error: body.error,
      inCore: body.inCore ? { ...body.inCore, valueHistory: merged.valueHistory } : undefined,
    }, vault);
  } else if (body.tier === "live" || body.tier === "live-app") {
    const site = (body.tier === "live" ? liveSites.sites : liveApps.apps).find((s) => s.id === body.scenarioId) || { kind: "login" };
    rec.kind = site.kind;
    rec.tags = site.tags || [];
    rec.score = scoreLive(site, body.frames || [], { offered: body.offered, reachable: body.reachable, optedOut: body.optedOut }, vault);
  } else if (body.tier === "save") {
    const scenario = save.scenarios.find((s) => s.id === body.scenarioId);
    if (!scenario) throw new Error(`unknown save scenario ${body.scenarioId}`);
    const page = save.pages.find((p) => p.id === (scenario.frame || scenario.page));
    rec.kind = "save";
    rec.tags = scenario.tags || [];
    rec.score = scoreSave({ ...scenario, host: page.host }, body.observed, vault);
  }
  // Never persist full field values for live sites: only what scoring used.
  if (rec.tier === "live" || rec.tier === "live-app") delete rec.frames;
  appendFileSync(join(dir, "results.jsonl"), JSON.stringify(rec) + "\n");
  return rec.score;
}

// ── HTTP handling ───────────────────────────────────────────────────────────

const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".json": "application/json", ".pem": "application/x-pem-file" };

const WELCOME = '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Welcome</title><link rel="stylesheet" href="/_style.css"></head><body><h1 id="welcome">You are signed in</h1></body></html>';

function send(res, status, body, type = "text/plain; charset=utf-8", headers = {}) {
  res.writeHead(status, { "content-type": type, "cache-control": "no-store", ...headers });
  res.end(body);
}

function originFor(host, scheme) {
  const port = scheme === "https" ? PUBLIC_PORT : HTTP_PORT;
  const def = scheme === "https" ? 443 : 80;
  return `${scheme}://${host}${port === def ? "" : ":" + port}`;
}

function renderPage(page, url, scheme, req) {
  let html = readFileSync(join(PAGES_DIR, page.path.slice(1)), "utf8");
  const run = url.searchParams.get("run") || "";
  html = html.replaceAll("{{RUN}}", encodeURIComponent(run));
  html = html.replace(/\{\{ORIGIN:([a-z0-9.-]+)\}\}/g, (_, h) => originFor(h, scheme));
  if (html.includes("{{ACCOUNT_STATUS}}")) {
    const s = sessions.get(cookieSid(req) || "");
    const host = (req.headers.host || "").split(":")[0];
    html = html.replace("{{ACCOUNT_STATUS}}", s && registrable(s.host) === registrable(host) ? `Signed in as ${s.username}` : "Not signed in");
  }
  const variant = page.variantParam ? url.searchParams.get(page.variantParam) : null;
  const pageKey = variant ? `${page.id}:${variant}` : page.id;
  const tag = `<script src="/__eval/beacon.js?page=${encodeURIComponent(pageKey)}&run=${encodeURIComponent(run)}"></script>`;
  return html.includes("</body>") ? html.replace("</body>", `${tag}</body>`) : html + tag;
}

function indexHtml(scheme) {
  const rows = fixtureScenarios(manifest).map((p) =>
    `<li><a href="${originFor(p.host, scheme)}${p.path}?run=manual">${p.id}</a> <small>${p.kind} · ${(p.tags || []).join(", ")}</small></li>`).join("");
  return `<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>VELA autofill eval</title><body style="font:15px system-ui;max-width:680px;margin:24px auto;padding:0 16px"><h1>VELA autofill eval</h1><p>CA certificate: <a href="/__eval/ca.pem">ca.pem</a></p><ol>${rows}</ol></body>`;
}

const HOST_ACTIONS = {
  // iOS Simulator: answer the pending Face ID / Touch ID prompt with a match.
  "ios-biometric-match": ["xcrun", ["simctl", "spawn", "booted", "notifyutil", "-p", "com.apple.BiometricKit_Sim.pearl.match"]],
  "ios-touchid-match": ["xcrun", ["simctl", "spawn", "booted", "notifyutil", "-p", "com.apple.BiometricKit_Sim.fingerTouch.match"]],
  // Android Emulator: touch the enrolled fingerprint.
  "android-finger": ["adb", ["-e", "emu", "finger", "touch", "1"]],
};

async function handle(req, res, scheme, tls) {
  const host = (req.headers.host || "localhost").split(":")[0].toLowerCase();
  const url = new URL(req.url, `${scheme}://${host}`);
  const path = url.pathname;
  try {
    if (path === "/__eval/beacon.js") return send(res, 200, readFileSync(join(ROOT, "lib/beacon.js")), TYPES[".js"]);
    if (path === "/__eval/ca.pem") return send(res, 200, readFileSync(tls.caPath), TYPES[".pem"], { "content-disposition": "attachment; filename=vela-eval-ca.pem" });
    if (path === "/__eval/report" && req.method === "POST") { recordReport(JSON.parse(await readBody(req))); return send(res, 204, ""); }
    if (path === "/__eval/state") {
      const run = url.searchParams.get("run") || "";
      const page = url.searchParams.get("page");
      const pages = Object.fromEntries(runs.get(run) || []);
      return send(res, 200, JSON.stringify(page ? pages[page] || null : pages), TYPES[".json"]);
    }
    if (path === "/__eval/merged") {
      return send(res, 200, JSON.stringify(mergedSnapshot(url.searchParams.get("run") || "", url.searchParams.get("page") || "")), TYPES[".json"]);
    }
    if (path === "/__eval/scenarios") {
      const sch = url.searchParams.get("scheme") || "https";
      const port = Number(url.searchParams.get("port") || (sch === "https" ? PUBLIC_PORT : HTTP_PORT));
      return send(res, 200, JSON.stringify(scenarioList(url.searchParams.get("tier") || "fixture", sch, port)), TYPES[".json"]);
    }
    if (path === "/__eval/expected") {
      // Resolved values, for on-device runners that must verify a field they
      // can read (e.g. an app's own EditText). Fixture data only.
      const ref = url.searchParams.get("ref");
      return send(res, 200, JSON.stringify(resolveRef(ref, vault)), TYPES[".json"]);
    }
    if (path === "/__eval/result" && req.method === "POST") {
      const score = writeResult(JSON.parse(await readBody(req)));
      return send(res, 200, JSON.stringify(score), TYPES[".json"]);
    }
    if (path.startsWith("/__eval/host/") && req.method === "POST") {
      const remote = req.socket.remoteAddress || "";
      if (!ALLOW_HOST_ACTIONS || !/^(::1|127\.|::ffff:127\.)/.test(remote)) return send(res, 403, "host actions disabled");
      const action = HOST_ACTIONS[path.slice("/__eval/host/".length)];
      if (!action) return send(res, 404, "unknown action");
      execFile(action[0], action[1], (err) => send(res, err ? 500 : 204, err ? String(err.message) : ""));
      return;
    }
    if (path === "/api/login" && req.method === "POST") {
      const values = parseLoginBody(await readBody(req), req.headers["content-type"]);
      const login = loginForHost(host).find((l) => values.includes(l.username) && values.includes(l.password));
      if (!login) return send(res, 401, "<!doctype html><h1 id=\"account-status\">Wrong credentials</h1>", TYPES[".html"]);
      const sid = randomBytes(16).toString("hex");
      sessions.set(sid, { host, loginId: login.id, username: login.username, ua: req.headers["user-agent"] || "", ts: Date.now() });
      const secure = scheme === "https" ? "; Secure" : "";
      return send(res, 303, "", "text/plain", { location: "/account.html", "set-cookie": `vela_eval_sid=${sid}; Path=/; HttpOnly; SameSite=Lax${secure}` });
    }
    if (path === "/__eval/sessions") {
      return send(res, 200, JSON.stringify([...sessions.values()].map(({ host: h, loginId, ua, ts }) => ({ host: h, loginId, ua, ts }))), TYPES[".json"]);
    }
    if (path === "/" && (host === "localhost" || /^[\d.]+$/.test(host))) return send(res, 200, indexHtml(scheme), TYPES[".html"]);
    if (path === "/_style.css") return send(res, 200, readFileSync(join(PAGES_DIR, "_style.css")), TYPES[".css"]);
    // A site backend for the save/update pages: `outcome=ok` signs in (form
    // posts land on a welcome page, fetch gets JSON), `outcome=fail` shows the
    // same page again with an error, as a site does after a wrong password.
    if (path === "/api/site" && req.method === "POST") {
      await readBody(req);
      const ok = url.searchParams.get("outcome") !== "fail";
      const json = (req.headers["content-type"] || "").includes("json") || !(req.headers["content-type"] || "").includes("form");
      if (json) return send(res, ok ? 200 : 401, JSON.stringify({ ok }), TYPES[".json"]);
      if (ok) return send(res, 200, WELCOME, TYPES[".html"]);
      const again = save.pages.find((p) => p.path === url.searchParams.get("page") && p.host === host);
      if (!again) return send(res, 401, "Wrong credentials");
      return send(res, 200, renderPage(again, url, scheme, req).replace("{{ERROR}}", '<p id="error" role="alert">Wrong email or password.</p>'), TYPES[".html"]);
    }
    if (path === "/landed") return send(res, 200, WELCOME, TYPES[".html"]);
    const page = ALL_PAGES.find((p) => p.path === path && (p.host === host || p.host === "*"));
    if (page) return send(res, 200, renderPage(page, url, scheme, req).replace("{{ERROR}}", ""), TYPES[".html"]);
    if (path.startsWith("/api/")) return send(res, 200, "ok");
    return send(res, 404, `no fixture at ${host}${path}`);
  } catch (e) {
    return send(res, 500, String(e && e.stack || e));
  }
}

export function start() {
  const tls = ensureTls();
  const s1 = https.createServer({ cert: tls.cert, key: tls.key }, (q, r) => handle(q, r, "https", tls)).listen(HTTPS_PORT, BIND);
  const s2 = http.createServer((q, r) => handle(q, r, "http", tls)).listen(HTTP_PORT, BIND);
  console.log(`autofill eval server: https://localhost:${HTTPS_PORT}/  http://localhost:${HTTP_PORT}/  (CA: ${tls.caPath})`);
  console.log(`fixture hosts (map them to this machine): ${fixtureHosts().join(" ")}`);
  if (ALLOW_HOST_ACTIONS) console.log("host actions enabled for loopback callers (biometric/fingerprint helpers)");
  return { close: () => { s1.close(); s2.close(); }, tls };
}

if (import.meta.url === `file://${process.argv[1]}`) start();
