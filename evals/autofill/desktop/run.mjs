#!/usr/bin/env node
// Desktop autofill eval: the real VELA extension in Chromium, driven like a
// user, against the fixture corpus and/or live sites.
//
// Modes (pick with --modes, comma separated):
//   click     focus the field, pick from VELA's inline dropdown (field icon for
//             cards/identities) — the default mouse flow
//   keyboard  focus, ArrowDown to open/move, Enter to pick — no mouse
//   shortcut  the "VELA: autofill" command (fills the page from the toolbar
//             or keyboard shortcut without touching a field)
//   onload    per-site "Auto-fill on page load" turned on, no interaction
//   in-core   in-core login from the popup: the desktop signs in and hands the
//             browser a session; the password must never reach the page.
//             Needs --host real (a running, unlocked VELA Desktop).
//
// The first four put the password into the page ("with password filling");
// in-core is the "without password filling" path.
//
// Usage:
//   node desktop/run.mjs [--tier fixture|live|all] [--modes click,keyboard,...]
//     [--host mock|real] [--only id1,id2] [--limit N] [--headless]
//     [--run-id NAME] [--browser /usr/bin/chromium] [--no-build]
import { chromium } from "playwright-core";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";
import { ROOT, loadCorpus, fixtureScenarios } from "../lib/score.mjs";
import { start as startServer } from "../lib/server.mjs";

const argv = process.argv.slice(2);
const opt = (name, def) => { const i = argv.indexOf(`--${name}`); return i < 0 ? def : (argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : true); };
const TIER = opt("tier", "fixture");
const MODES = String(opt("modes", "click,keyboard,shortcut,onload")).split(",");
const HOST = opt("host", "mock");
const ONLY = opt("only", "") ? String(opt("only")).split(",") : null;
const LIMIT = Number(opt("limit", 0)) || Infinity;
const HEADLESS = !!opt("headless", false);
const RUN_ID = String(opt("run-id", new Date().toISOString().replace(/[:.]/g, "-")));
const BROWSER = String(opt("browser", process.env.CHROMIUM_PATH || "/usr/bin/chromium"));
const HTTPS_PORT = Number(process.env.VELA_EVAL_HTTPS_PORT || 8443);
const HTTP_PORT = Number(process.env.VELA_EVAL_HTTP_PORT || 8080);
const REPO = resolve(ROOT, "../..");
const EXT_SRC = join(REPO, "extension");
const CACHE = join(ROOT, ".cache");
const OUT = join(ROOT, "results", RUN_ID);
const SERVER = `http://127.0.0.1:${HTTP_PORT}`;
// Mock host state for the save tier: logins saved/updated, and every save payload.
const HOST_STATE = join(OUT, "host-state.json");
const HOST_SAVES = join(OUT, "host-saves.jsonl");

if (MODES.includes("in-core") && HOST !== "real") {
  console.error("in-core needs --host real: the mock host cannot sign in to a site. Dropping in-core from this run.");
  MODES.splice(MODES.indexOf("in-core"), 1);
}

const { manifest, vault, liveSites, save } = loadCorpus();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Extension + native host setup ───────────────────────────────────────────

function buildExtension() {
  if (!opt("no-build", false)) execFileSync("node", ["build.js", "--chrome"], { cwd: EXT_SRC, stdio: "inherit" });
  const dir = join(CACHE, "ext-chrome");
  rmSync(dir, { recursive: true, force: true });
  cpSync(join(EXT_SRC, "dist/chrome"), dir, { recursive: true });
  if (MODES.includes("in-core")) {
    // In-core login sets cookies, which the popup normally asks the user to
    // allow per site. Pre-grant it in the eval copy only.
    const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
    m.permissions = [...new Set([...(m.permissions || []), "cookies"])];
    m.host_permissions = ["<all_urls>"];
    writeFileSync(join(dir, "manifest.json"), JSON.stringify(m, null, 2));
  }
  return dir;
}

function installNativeHost(userDataDir, extensionId) {
  const dir = join(userDataDir, "NativeMessagingHosts");
  mkdirSync(dir, { recursive: true });
  let path;
  if (HOST === "real") {
    path = process.env.VELA_NM_HOST || join(REPO, "target/release/vela-native-messaging-host");
    if (!existsSync(path)) throw new Error(`real host not found at ${path}; build it (cargo build -p vela-nm-host --release) or set VELA_NM_HOST`);
  } else {
    path = join(CACHE, "mock-host.sh");
    writeFileSync(path, `#!/bin/sh\nexport VELA_EVAL_VAULT='${join(ROOT, "corpus/vault.json")}'\nexport VELA_EVAL_LOG='${join(OUT, "native-requests.jsonl")}'\nexport VELA_EVAL_LIVE='${TIER === "live" || TIER === "all" ? 1 : 0}'\nexport VELA_EVAL_STATE='${HOST_STATE}'\nexport VELA_EVAL_SAVES='${HOST_SAVES}'\nexec '${process.execPath}' '${join(ROOT, "desktop/mock-host.mjs")}' "$@"\n`);
    chmodSync(path, 0o755);
  }
  writeFileSync(join(dir, "com.vela.desktop.json"), JSON.stringify({
    name: "com.vela.desktop", description: "VELA eval host", path, type: "stdio",
    allowed_origins: [`chrome-extension://${extensionId}/`],
  }, null, 2));
}

async function launch(extDir) {
  const userDataDir = join(CACHE, `chromium-profile-${RUN_ID}`);
  rmSync(userDataDir, { recursive: true, force: true });
  mkdirSync(userDataDir, { recursive: true });
  const args = [
    `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`,
    // Every fixture host resolves to this machine; live sites resolve normally.
    "--host-resolver-rules=MAP *.test 127.0.0.1",
    "--ignore-certificate-errors", "--no-first-run", "--no-default-browser-check",
    "--disable-features=AutofillServerCommunication,PasswordManagerOnboarding",
    "--password-store=basic",
  ];
  if (HEADLESS) args.push("--headless=new");
  const ctx = await chromium.launchPersistentContext(userDataDir, {
    executablePath: BROWSER, headless: false, args, ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 900 },
  });
  let [worker] = ctx.serviceWorkers();
  if (!worker) worker = await ctx.waitForEvent("serviceworker", { timeout: 15000 });
  const extensionId = new URL(worker.url()).host;
  installNativeHost(userDataDir, extensionId);
  // Chrome's built-in password manager and address autofill would compete
  // with VELA for the same fields; turn them off so we measure VELA alone.
  const prefs = join(userDataDir, "Default/Preferences");
  if (existsSync(prefs)) {
    try {
      const p = JSON.parse(readFileSync(prefs, "utf8"));
      p.credentials_enable_service = false;
      p.autofill = { ...(p.autofill || {}), profile_enabled: false, credit_card_enabled: false };
      writeFileSync(prefs, JSON.stringify(p));
    } catch {}
  }
  return { ctx, worker, extensionId };
}

// ── Locating fields across frames and shadow roots ──────────────────────────

function frameForPage(page, pageKey, mainId) {
  if (pageKey === mainId) return page.mainFrame();
  const [id, variant] = pageKey.split(":");
  const def = manifest.pages.find((p) => p.id === id);
  return page.frames().find((f) => {
    try {
      const u = new URL(f.url());
      return u.pathname === def.path && (!variant || u.searchParams.get(def.variantParam) === variant);
    } catch { return false; }
  });
}

/** 'id' | 'shadowHost/id' | 'page#id' | 'page:variant#id' → { frame, locator } */
function locate(page, key, mainId) {
  let pageKey = mainId, rest = key;
  if (key.includes("#")) [pageKey, rest] = key.split("#");
  const frame = frameForPage(page, pageKey, mainId);
  if (!frame) return null;
  // Playwright CSS pierces open shadow roots, so '#host #id' reaches inside.
  const css = rest.split("/").map((p) => `#${CSS.escape(p)}`).join(" ");
  return { frame, locator: frame.locator(css).first() };
}
const CSS = { escape: (s) => s.replace(/([^a-zA-Z0-9_-])/g, "\\$1") };

// ── Gestures ────────────────────────────────────────────────────────────────

const DROPDOWN = ".vela-inline-dropdown";

async function waitDropdownItems(frame, timeout = 4000) {
  try {
    await frame.locator(`${DROPDOWN} .vela-dd-item`).first().waitFor({ state: "visible", timeout });
    return true;
  } catch { return false; }
}

function itemMatcher(frame, choose) {
  const items = frame.locator(`${DROPDOWN} .vela-dd-item`);
  if (!choose) return items.first();
  if (choose.type === "login") {
    // Mock host ids equal vault ids; the real host uses its own, so fall back
    // to the username text the dropdown shows.
    return frame.locator(`${DROPDOWN} .vela-dd-item[data-vela-login-id="${choose.id}"], ${DROPDOWN} .vela-dd-item:has-text("${choose.text}")`).first();
  }
  return items.filter({ hasText: choose.text }).first();
}

async function pick(frame, choose, counter) {
  let item = itemMatcher(frame, choose);
  // A real vault names items its own way (an imported identity is one item
  // per address, say); take the first offer rather than score a non-pick.
  if (!(await item.count())) item = frame.locator(`${DROPDOWN} .vela-dd-item`).first();
  if (!(await item.count())) return false;
  await item.click();
  counter.n++;
  return true;
}

async function gestureClick(page, target, choose, counter) {
  const { frame, locator } = target;
  await locator.click(); counter.n++;
  let offered = await waitDropdownItems(frame, 2500);
  if (!offered) {
    // Cards and identities show only a field icon on focus; clicking it is
    // the user's next move.
    const icon = frame.locator(".vela-field-icon");
    if (await icon.count()) { await icon.first().click(); counter.n++; offered = await waitDropdownItems(frame, 3000); }
  }
  if (!offered) return { offered: false };
  return { offered: true, picked: await pick(frame, choose, counter) };
}

async function gestureKeyboard(page, target, choose, counter) {
  const { frame, locator } = target;
  await locator.focus(); counter.n++;
  let offered = await waitDropdownItems(frame, 2500);
  if (!offered) { await page.keyboard.press("ArrowDown"); counter.n++; offered = await waitDropdownItems(frame, 3000); }
  if (!offered) return { offered: false };
  const index = await frame.locator(`${DROPDOWN} .vela-dd-item`).evaluateAll((els, ch) => els.findIndex((el) =>
    !ch || (ch.type === "login" && el.dataset.velaLoginId === ch.id) || el.textContent.includes(ch.text)), choose);
  if (index < 0) return { offered: true, picked: false };
  for (let i = 0; i <= index; i++) { await page.keyboard.press("ArrowDown"); counter.n++; }
  await page.keyboard.press("Enter"); counter.n++;
  return { offered: true, picked: true };
}

async function gestureShortcut(page, worker, choose, counter) {
  // Same message the background sends for the autofill command/context menu.
  const url = page.url();
  await worker.evaluate(async (u) => {
    const [tab] = await chrome.tabs.query({ url: u.split("#")[0] });
    if (tab) await chrome.tabs.sendMessage(tab.id, { command: "triggerAutofill" }).catch(() => {});
  }, url);
  counter.n++;
  // Several logins → an account picker modal.
  const modal = page.locator(".vela-modal .vela-account-item");
  try {
    await modal.first().waitFor({ state: "visible", timeout: 1500 });
    const want = choose ? page.locator(`.vela-modal :is(.vela-account-item[data-vela-login-id="${choose.id}"], .vela-account-item:has-text("${choose.text}"))`).first() : modal.first();
    if (await want.count()) { await want.click(); counter.n++; }
  } catch {}
  return { offered: null };
}

async function gestureGenerate(target, counter) {
  const { frame, locator } = target;
  await locator.click(); counter.n++;
  const gen = frame.locator(`[data-vela-action="generate-password"]`);
  try { await gen.first().waitFor({ state: "visible", timeout: 3000 }); } catch { return { offered: false }; }
  await gen.first().click(); counter.n++;
  const use = frame.locator(`#vela-gen-modal [data-vela-action="use"]`);
  try { await use.waitFor({ state: "visible", timeout: 3000 }); } catch { return { offered: true, picked: false }; }
  await use.click(); counter.n++;
  return { offered: true, picked: true };
}

async function setAutoFillOnLoad(ctx, extensionId, host, on) {
  const p = await ctx.newPage();
  await p.goto(`chrome-extension://${extensionId}/popup/popup.html`);
  await p.evaluate(async ([h, v]) => {
    const key = h.replace(/^www\./, "");
    const data = await chrome.storage.local.get("velaSiteSettings");
    const all = data.velaSiteSettings || {};
    if (v) all[key] = { ...(all[key] || {}), autoFillOnLoad: true }; else delete all[key];
    await chrome.storage.local.set({ velaSiteSettings: all });
  }, [host, on]);
  await p.close();
}

// ── In-core login (real host only) ──────────────────────────────────────────

async function inCoreLogin(ctx, worker, extensionId, page, scenario, choose) {
  const t0 = Date.now();
  await page.bringToFront();
  const popupP = ctx.waitForEvent("page", { timeout: 5000, predicate: (p) => p.url().includes("/popup/popup.html") }).catch(() => null);
  await worker.evaluate(() => chrome.action.openPopup().catch(() => {}));
  const popup = await popupP;
  if (!popup) return { error: "could not open the extension popup" };
  const buttons = popup.locator(".in-core-login-btn");
  try { await buttons.first().waitFor({ state: "visible", timeout: 6000 }); } catch {}
  const candidates = await buttons.count();
  if (!candidates) { await popup.close().catch(() => {}); return { candidates: 0, durationMs: Date.now() - t0 }; }
  const btn = choose ? buttons.filter({ hasText: choose.text }).first() : buttons.first();
  await ((await btn.count()) ? btn : buttons.first()).click();
  // The popup reports completion; then the session cookie is in the jar.
  await popup.waitForEvent("close", { timeout: 60000 }).catch(() => {});
  const acct = new URL("/account.html", page.url()).toString();
  await page.goto(acct);
  const status = (await page.locator("#account-status").textContent().catch(() => "")) || "";
  return { candidates, signedIn: status.startsWith("Signed in"), status, durationMs: Date.now() - t0 };
}

// ── Scenario execution ──────────────────────────────────────────────────────

function chooseFor(p) {
  if (!p.choose) return null;
  const l = vault.logins.find((x) => x.id === p.choose);
  if (l) return { type: "login", id: l.id, text: l.username };
  const c = vault.cards.find((x) => x.id === p.choose);
  if (c) return { type: "card", id: c.id, text: c.number.slice(-4) };
  const [iid, aid] = p.choose.split("/");
  const i = vault.identities.find((x) => x.id === iid);
  if (i) return { type: "identity", id: i.id, text: aid ? i.addresses.find((a) => a.id === aid).label : i.name };
  return null;
}

async function flushBeacons(page) {
  for (const f of page.frames()) await f.evaluate(() => globalThis.__velaEval && globalThis.__velaEval.report()).catch(() => {});
  await sleep(300);
}

async function post(path, body) {
  const r = await fetch(SERVER + path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
  return r.json();
}

async function runFixture(env, scenario, mode) {
  const { ctx, worker, extensionId } = env;
  const run = `${RUN_ID}.desktop-chromium.${mode}.${scenario.id}`;
  const url = `https://${scenario.host}:${HTTPS_PORT}${scenario.path}?run=${encodeURIComponent(run)}`;
  const choose = chooseFor(scenario);
  const steps = scenario.steps || [{ fill: scenario.anchor }];
  const counter = { n: 0 };
  let offered = null, error = null, inCore;
  if (mode === "onload") await setAutoFillOnLoad(ctx, extensionId, scenario.host, true);
  const page = await ctx.newPage();
  const t0 = Date.now();
  try {
    await page.goto(url, { waitUntil: "load" });
    await sleep(500 + (scenario.settleMs || 0));
    if (mode === "in-core") {
      inCore = await inCoreLogin(ctx, worker, extensionId, page, scenario, choose);
      offered = (inCore.candidates || 0) > 0;
    } else if (mode === "onload") {
      await sleep(2500);
      for (const s of steps) if (s.click) { const t = locate(page, s.click, scenario.id); if (t) { await t.locator.click(); await sleep(1500); } }
    } else {
      for (const s of steps) {
        if (s.wait) { await sleep(s.wait); continue; }
        if (s.click) { const t = locate(page, s.click, scenario.id); if (!t) throw new Error(`no element ${s.click}`); await t.locator.click(); counter.n++; continue; }
        const key = s.fill || s.generate;
        const t = locate(page, key, scenario.id);
        if (!t) throw new Error(`frame for ${key} not found`);
        await t.locator.waitFor({ state: "attached", timeout: 5000 });
        let r;
        if (s.generate) r = mode === "shortcut" ? { offered: null } : await gestureGenerate(t, counter);
        else if (mode === "click") r = await gestureClick(page, t, choose, counter);
        else if (mode === "keyboard") r = await gestureKeyboard(page, t, choose, counter);
        else if (mode === "shortcut") r = await gestureShortcut(page, worker, choose, counter);
        if (r.offered != null) offered = offered === true ? true : r.offered;
        await sleep(400);
      }
    }
    await sleep(700);
  } catch (e) {
    error = String(e.message || e).split("\n")[0];
  }
  await flushBeacons(page);
  const score = await post("/__eval/result", {
    runId: RUN_ID, run, tier: "fixture", scenarioId: scenario.id,
    surface: "desktop-chromium", platform: "desktop", client: "chromium", mode, host: HOST,
    offered, interactions: counter.n, durationMs: Date.now() - t0, error, inCore,
  });
  if (mode === "onload") await setAutoFillOnLoad(ctx, extensionId, scenario.host, false);
  if (!score.pass) {
    mkdirSync(join(OUT, "shots"), { recursive: true });
    await page.screenshot({ path: join(OUT, "shots", `desktop-${mode}-${scenario.id}.png`), fullPage: true }).catch(() => {});
  }
  await page.close();
  return score;
}

// Field snapshot for live pages: evaluated in every frame, never posts.
function liveSnapshot() {
  const out = [];
  const walk = (root) => {
    for (const el of root.querySelectorAll("input,select,textarea")) {
      if (el.closest("[data-vela-ui]")) continue;
      if (el.tagName === "INPUT" && ["hidden", "submit", "button", "checkbox", "radio", "image", "reset", "file"].includes(el.type)) continue;
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      out.push({
        value: el.value, type: el.tagName === "INPUT" ? el.type : el.tagName.toLowerCase(), name: el.name || "", id: el.id || "",
        autocomplete: el.getAttribute("autocomplete") || "", placeholder: el.placeholder || "",
        label: (el.labels && el.labels[0] ? el.labels[0].textContent : el.getAttribute("aria-label") || "").trim().slice(0, 60),
        visible: r.width > 1 && r.height > 1 && cs.visibility !== "hidden" && cs.display !== "none",
      });
    }
    for (const n of root.querySelectorAll("*")) if (n.shadowRoot) walk(n.shadowRoot);
  };
  walk(document);
  return out;
}

const LIVE_ANCHOR = {
  login: ["input[autocomplete~=username]", "input[type=email]", "input[name*=user i]", "input[name*=login i]", "input[id*=user i]", "input[name*=email i]", "input[type=password]"],
  signup: ["input[autocomplete=new-password]", "input[type=password]"],
  email: ["input[type=email]", "input[autocomplete~=email]", "input[name*=email i]"],
  identity: ["input[autocomplete~=given-name]", "input[autocomplete~=address-line1]", "input[name*=first i]", "input[name*=address i]", "input[name*=zip i]", "input[name*=postal i]"],
  card: ["input[autocomplete=cc-number]", "input[name*=cardnumber i]", "input[name*=card i][name*=number i]", "input[placeholder*='1234']"],
};

async function findLiveAnchor(page, kind) {
  // A footer newsletter box is not the sign-in form, even when it is the only
  // email field on the page; leaving it out sends the runner to discovery.
  const isNewsletter = (loc) => loc.evaluate((el) => {
    if (el.closest("footer")) return true;
    const box = el.closest("form") || el.parentElement?.parentElement || el.parentElement;
    return /newsletter|subscribe|s.abonner|abonnez|inscri(?:s|vez)[- ]vous à|stay (?:up to date|in the loop)/i.test((box?.textContent || "").slice(0, 600));
  }).catch(() => false);
  for (const sel of LIVE_ANCHOR[kind] || LIVE_ANCHOR.login) {
    for (const f of page.frames()) {
      const all = f.locator(sel).filter({ visible: true });
      const n = Math.min(await all.count().catch(() => 0), 6);
      for (let i = 0; i < n; i++) {
        const loc = all.nth(i);
        if ((kind === "login" || kind === "signup") && (await isNewsletter(loc))) continue;
        return { frame: f, locator: loc };
      }
    }
  }
  return null;
}

// Vault entries store a homepage, not the sign-in page. Find it the way a
// person would: a visible "Sign in" link or button, then common paths.
const SIGN_IN = /^\s*(sign ?in|log ?in|login|se connecter|connexion|identifiez-vous|mon compte|anmelden|iniciar sesi[oó]n|accedi|my account|account)\s*$/i;
async function discoverLogin(page, kind) {
  const link = page.locator("a, button, [role=button]").filter({ hasText: SIGN_IN, visible: true }).first();
  if (await link.count().catch(() => 0)) {
    await link.click({ timeout: 5000 }).catch(() => {});
    await page.waitForLoadState("domcontentloaded").catch(() => {});
    await sleep(3000);
    const t = await findLiveAnchor(page, kind);
    if (t) return t;
  }
  const origin = new URL(page.url()).origin;
  for (const path of ["/login", "/signin", "/sign-in", "/account/login", "/users/sign_in", "/connexion", "/user/login"]) {
    const r = await page.goto(origin + path, { waitUntil: "domcontentloaded", timeout: 15000 }).catch(() => null);
    if (!r || r.status() >= 400) continue;
    await sleep(2500);
    const t = await findLiveAnchor(page, kind);
    if (t) return t;
  }
  return null;
}

// Sites open pop-unders and new tabs; a real user is looking at the page
// they are filling, so it must be the active tab the background checks.
async function focusOnly(ctx, page) {
  for (const other of ctx.pages()) if (other !== page && !other.url().startsWith("chrome-extension://")) await other.close().catch(() => {});
  await page.bringToFront().catch(() => {});
}

async function runLive(env, site, mode) {
  const { ctx, worker } = env;
  const page = await ctx.newPage();
  if (process.env.VELA_EVAL_DEBUG) page.on("console", (m) => { if (m.type() === "error" || /vela/i.test(m.text())) console.log(`  console.${m.type()}: ${m.text().slice(0, 300)}`); });
  if (process.env.VELA_EVAL_DEBUG) page.on("pageerror", (e) => console.log(`  pageerror: ${e.message.slice(0, 300)}`));
  const counter = { n: 0 };
  let offered = null, reachable = true, error = null, before = new Map(), optedOut = false;
  const t0 = Date.now();
  try {
    await page.goto(site.url, { waitUntil: "domcontentloaded", timeout: 30000 });
    await sleep(3500);
    let target = await findLiveAnchor(page, site.kind);
    // A homepage's only field is often a newsletter or search box: when the
    // page shows no password field, look for the real sign-in page first.
    const hasPassword = async () => { for (const f of page.frames()) if (await f.locator("input[type=password]").filter({ visible: true }).count().catch(() => 0)) return true; return false; };
    if ((site.tags || []).includes("discover-login") && (!target || !(await hasPassword()))) {
      const found = await discoverLogin(page, site.kind);
      if (found) target = found;
      else if (target) {
        // Discovery navigated away and found nothing: back to the homepage field.
        await page.goto(site.url, { waitUntil: "domcontentloaded", timeout: 30000 });
        await sleep(3000);
        target = await findLiveAnchor(page, site.kind);
      }
    }
    await focusOnly(ctx, page);
    // Values present before VELA acts are the page's own, not a fill.
    for (const f of page.frames()) before.set(f, await f.evaluate(liveSnapshot).catch(() => []));
    const probe = () => target.locator.evaluate((el) => {
      let a = document.activeElement; while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement;
      return { bwignore: el.hasAttribute("data-bwignore"), p1ignore: el.hasAttribute("data-1p-ignore"), lpignore: el.getAttribute("data-lpignore"), tag: el.tagName, type: el.type, ro: el.readOnly, dis: el.disabled, ac: el.autocomplete, autofocus: el.autofocus, focused: a === el,
        inShadow: el.getRootNode() !== document, dd: !!document.querySelector(".vela-inline-dropdown"), items: document.querySelectorAll(".vela-inline-dropdown .vela-dd-item").length,
        icon: !!document.querySelector(".vela-field-icon"), ddText: (document.querySelector(".vela-inline-dropdown")?.innerText || "").replace(/\s+/g, " ").slice(0, 60) };
    }).catch((e) => String(e).slice(0, 80));
    if (process.env.VELA_EVAL_DEBUG && target) console.log("  anchor frame:", target.frame === page.mainFrame() ? "main" : new URL(target.frame.url()).host, "· page:", new URL(page.url()).host, "· before:", JSON.stringify(await probe()));
    // The site asked password managers to keep out of this field.
    if (target) optedOut = await target.locator.evaluate((el) => el.hasAttribute("data-bwignore") || el.hasAttribute("data-1p-ignore") || el.getAttribute("data-lpignore") === "true").catch(() => false);
    if (!target) reachable = false;
    else if (site.kind === "signup") offered = (await gestureGenerate(target, counter)).offered;
    else if (mode === "click") offered = (await gestureClick(page, target, null, counter)).offered;
    else if (mode === "keyboard") offered = (await gestureKeyboard(page, target, null, counter)).offered;
    else if (mode === "shortcut") await gestureShortcut(page, worker, null, counter);
    if (process.env.VELA_EVAL_DEBUG && target) console.log("  after:", JSON.stringify(await probe()));
    if (process.env.VELA_EVAL_DEBUG) {
      const seen = await worker.evaluate(async () => {
        const [cur] = await chrome.tabs.query({ active: true, currentWindow: true });
        const all = await chrome.tabs.query({});
        const wins = await chrome.windows.getAll();
        let native = null;
        try { const r = await chrome.runtime.sendNativeMessage("com.vela.desktop", { action: "getAvailableLogins", url: new URL(cur.url).hostname }); native = r ? (r.logins || []).length : "no reply"; } catch (e) { native = "error " + e.message; }
        return { activeCurrent: cur ? cur.url : null, tabs: all.length, windows: wins.length, nativeLogins: native };
      }).catch((e) => String(e));
      console.log(`  page ${new URL(page.url()).host} · background sees`, JSON.stringify(seen).replace(/https?:\/\/([^/"]+)[^"]*/g, "$1"));
    }
    if (process.env.VELA_EVAL_DEBUG && target) {
      for (const t of [50, 300, 1000]) {
        await sleep(t);
        console.log(`  anchor after ${t}ms:`, JSON.stringify(await target.locator.evaluate((el) => ({ name: el.name, id: el.id, type: el.type, len: el.value.length, opid: el.getAttribute("data-opid"), connected: el.isConnected })).catch((e) => String(e).slice(0, 80))));
      }
    }
    await sleep(1000);
  } catch (e) {
    error = String(e.message || e).split("\n")[0];
    reachable = false;
  }
  const frames = [];
  for (const f of page.frames()) {
    const fields = await f.evaluate(liveSnapshot).catch(() => []);
    const prior = before.get(f) || [];
    // Prefilled = the same non-empty value sat in that field before the
    // gesture (React mirrors value into the attribute, so defaultValue lies).
    const mark = (x, i) => ({ ...x, prefilled: !!x.value && prior.some((p) => p.name === x.name && p.id === x.id && p.value === x.value), frame: f === page.mainFrame() ? "main" : new URL(f.url()).hostname });
    if (fields.length) frames.push({ url: f.url(), fields: fields.map(mark) });
    if (process.env.VELA_EVAL_DEBUG) for (const x of fields.map(mark)) if (x.value || x.type === "password") console.log(`  field ${x.type} name=${x.name} id=${x.id} visible=${x.visible} prefilled=${x.prefilled} len=${x.value.length}`);
  }
  mkdirSync(join(OUT, "shots"), { recursive: true });
  await page.screenshot({ path: join(OUT, "shots", `desktop-live-${mode}-${site.id}.png`) }).catch(() => {});
  const score = await post("/__eval/result", {
    runId: RUN_ID, tier: "live", scenarioId: site.id, surface: "desktop-chromium", platform: "desktop", client: "chromium",
    mode, host: HOST, offered, reachable, optedOut, interactions: counter.n, durationMs: Date.now() - t0, error, frames,
  });
  await page.close();
  return score;
}

// ── Save / update capture ───────────────────────────────────────────────────
//
// Types like a person (trusted key events), submits, then reads which bar
// VELA shows on whatever page the submit lands on, opens the review dialog,
// confirms, and reads what reached the host. Nothing here fills: capture of
// VELA's own fills is out of scope (synthetic events are ignored by design).

const SAVE_BAR = ".vela-save-bar";
const lines = (f) => (existsSync(f) ? readFileSync(f, "utf8").split("\n").filter(Boolean) : []);

async function fieldFrame(page, id, timeout = 5000) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    for (const f of page.frames()) if (await f.locator(`#${CSS.escape(id)}`).count().catch(() => 0)) return f;
    await sleep(150);
  }
  return null;
}

async function typeAndSubmit(page, s) {
  for (const [id, value] of s.type) {
    const f = await fieldFrame(page, id);
    if (!f) throw new Error(`no field #${id}`);
    await f.locator(`#${CSS.escape(id)}`).click();
    await page.keyboard.type(value, { delay: 12 });
    // Close VELA's dropdown the way a person would before moving on.
    await page.keyboard.press("Escape");
  }
  if (s.enter) {
    const f = await fieldFrame(page, s.enter);
    await f.locator(`#${CSS.escape(s.enter)}`).click();
    await page.keyboard.press("Enter");
  } else {
    const f = await fieldFrame(page, s.submit);
    if (!f) throw new Error(`no submit #${s.submit}`);
    await f.locator(`#${CSS.escape(s.submit)}`).click();
  }
}

/** The bar VELA shows after a submit, in any frame, or null within `ms`. */
async function waitSaveBar(page, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    for (const f of page.frames()) {
      const bar = f.locator(SAVE_BAR);
      if (await bar.count().catch(() => 0)) {
        const text = (await bar.first().innerText().catch(() => "")) || "";
        return { frame: f, bar: bar.first(), prompt: /same account/i.test(text) ? "update" : "save" };
      }
    }
    await sleep(150);
  }
  return null;
}

async function runSave(env, scenario) {
  const { ctx } = env;
  const pageDef = save.pages.find((p) => p.id === scenario.page);
  const run = `${RUN_ID}.desktop-chromium.save.${scenario.id}`;
  const url = `https://${pageDef.host}:${HTTPS_PORT}${pageDef.path}?run=${encodeURIComponent(run)}`;
  writeFileSync(HOST_STATE, JSON.stringify({ added: [], updated: {} }));
  const page = await ctx.newPage();
  const t0 = Date.now();
  const observed = { prompt: "none" };
  try {
    if (scenario.neverFirst) {
      // First visit: the person answers "Never for this site".
      await page.goto(url, { waitUntil: "load" });
      await sleep(400);
      await typeAndSubmit(page, scenario);
      const first = await waitSaveBar(page, 6000);
      if (!first) throw new Error("no prompt on the first login, so 'Never' could not be chosen");
      await first.bar.locator("[data-vela-action='never']").click();
      await first.frame.locator(".vela-overlay [data-confirm]").click();
      await sleep(600);
    }
    await page.goto(url, { waitUntil: "load" });
    await sleep(400);
    const nativeBefore = lines(join(OUT, "native-requests.jsonl")).length;
    const savesBefore = lines(HOST_SAVES).length;
    await typeAndSubmit(page, scenario);
    await page.waitForLoadState("load").catch(() => {});
    const shown = await waitSaveBar(page, 5000);
    // Secrets the host handed out after the submit, before the person chose
    // anything: what capture itself costs.
    observed.releases = lines(join(OUT, "native-requests.jsonl")).slice(nativeBefore)
      .map((l) => JSON.parse(l)).filter((r) => r.releasedSecrets && /getLogins|getAvailableLogins/.test(r.action)).length;
    if (shown) {
      observed.prompt = shown.prompt;
      await shown.bar.locator(`[data-vela-action='${shown.prompt === "update" ? "update" : "save"}']`).click();
      const modal = shown.frame.locator("#vela-save-modal");
      await modal.waitFor({ timeout: 3000 });
      observed.dialog = {
        username: await modal.locator("#vela-save-username").inputValue(),
        password: await modal.locator("#vela-save-password").inputValue(),
      };
      await modal.locator(".vela-modal-actions [data-vela-action='save']").click();
      const end = Date.now() + 4000;
      while (Date.now() < end && lines(HOST_SAVES).length === savesBefore) await sleep(150);
      const saved = lines(HOST_SAVES).slice(savesBefore);
      observed.payload = saved.length ? JSON.parse(saved[saved.length - 1]) : null;
      if (saved.length > 1) observed.error = `${saved.length} saves for one submit`;
    }
  } catch (e) {
    observed.error = String(e.message || e).split("\n")[0];
  }
  const score = await post("/__eval/result", {
    runId: RUN_ID, run, tier: "save", scenarioId: scenario.id,
    surface: "desktop-chromium", platform: "desktop", client: "chromium", mode: "save", host: HOST,
    durationMs: Date.now() - t0, observed: { ...observed, payload: observed.payload && { ...observed.payload, ts: undefined } },
  });
  if (!score.pass) {
    mkdirSync(join(OUT, "shots"), { recursive: true });
    await page.screenshot({ path: join(OUT, "shots", `desktop-save-${scenario.id}.png`), fullPage: true }).catch(() => {});
  }
  await page.close();
  return score;
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  mkdirSync(OUT, { recursive: true });
  const server = startServer();
  const extDir = buildExtension();
  const env = await launch(extDir);
  if (process.env.VELA_EVAL_DEBUG) env.worker.on("console", (m) => console.log(`  sw.${m.type()}: ${m.text().slice(0, 200)}`));
  console.log(`extension ${env.extensionId} · host ${HOST} · modes ${MODES.join(",")} · run ${RUN_ID}`);
  const tally = { pass: 0, fail: 0 };
  const log = (mode, id, s) => {
    const skipped = s.reachable === false;
    if (!skipped) s.pass ? tally.pass++ : tally.fail++;
    const bits = s.inCore ? `in-core ${s.inCore.outcome}${s.inCore.passwordTouchedPage ? " PASSWORD-IN-PAGE" : ""}`
      : s.expected != null ? `${s.correct}/${s.expected} fields${s.critical ? ` · ${s.critical} CRITICAL` : ""}${s.falseOffer ? " · false offer" : ""}`
      : `offered=${s.offered} core=${s.coreFilled} misfills=${(s.misfills || []).length}${s.critical ? ` · ${s.critical} CRITICAL` : ""}${s.reachable === false ? " · unreachable" : ""}`;
    console.log(`${skipped ? "SKIP" : s.pass ? "PASS" : "FAIL"}  ${mode.padEnd(8)} ${id.padEnd(34)} ${bits}${s.error ? ` · ${s.error}` : ""}`);
  };
  try {
    if (TIER === "fixture" || TIER === "all") {
      const scenarios = fixtureScenarios(manifest).filter((p) => !ONLY || ONLY.includes(p.id)).slice(0, LIMIT);
      // Page-load auto-fill and the autofill command only ever fill logins;
      // running them on card/identity pages would score a non-feature.
      const applies = (mode, s) => s.skipModes?.[mode] ? false : mode === "in-core" ? !!s.inCore
        : mode === "onload" || mode === "shortcut" ? s.kind === "login" || s.kind === "negative" : true;
      for (const mode of MODES) for (const s of scenarios) {
        if (!applies(mode, s)) continue;
        log(mode, s.id, await runFixture(env, s, mode));
      }
    }
    if (TIER === "save" || TIER === "all") {
      for (const s of save.scenarios.filter((x) => !ONLY || ONLY.includes(x.id)).slice(0, LIMIT)) {
        const r = await runSave(env, s);
        if (r.pass) tally.pass++; else tally.fail++;
        console.log(`${r.pass ? "PASS" : "FAIL"}  save     ${s.id.padEnd(34)} prompt=${r.prompt} (want ${r.expectedPrompt})${r.releases ? ` · ${r.releases} secret release(s) during capture` : ""}${r.problems.length ? " · " + r.problems.join("; ") : ""}`);
      }
    }
    if (TIER === "live" || TIER === "all") {
      const sites = liveSites.sites.filter((s) => !ONLY || ONLY.includes(s.id)).slice(0, LIMIT);
      for (const mode of MODES.filter((m) => m === "click" || m === "keyboard" || m === "shortcut")) for (const s of sites) log(mode, s.id, await runLive(env, s, mode));
    }
  } finally {
    await env.ctx.close();
    server.close();
    rmSync(join(CACHE, `chromium-profile-${RUN_ID}`), { recursive: true, force: true });
  }
  console.log(`\n${tally.pass} pass · ${tally.fail} fail · results in ${OUT}\nreport: node lib/report.mjs ${RUN_ID}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
