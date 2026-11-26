#!/usr/bin/env node
// Stand-in for vela-nm-host + an unlocked VELA Desktop, speaking the same
// extension-facing protocol (see desktopVELA/vela-nm-host/src/lib.rs):
// getLogins/getAvailableLogins, getCards, getIdentities, ping, plus logging of
// every request so the eval can check "metadata until the user chooses".
//
// What it does NOT reproduce: the desktop's own domain matching, biometric
// gating, and in-core login. Run the desktop runner with --host real to test
// those against the production binaries.
//
// Env: VELA_EVAL_VAULT (path to corpus/vault.json), VELA_EVAL_LOG (jsonl),
//      VELA_EVAL_LIVE=1 (answer any non-fixture site with the synthetic login),
//      VELA_EVAL_STATE (json: logins saved or updated through saveCredentials;
//      the browser may start a new host per message, so state lives on disk),
//      VELA_EVAL_SAVES (jsonl: every saveCredentials payload, for scoring).
import { readFileSync, appendFileSync, existsSync, writeFileSync } from "node:fs";

const base = JSON.parse(readFileSync(process.env.VELA_EVAL_VAULT, "utf8"));
const LOG = process.env.VELA_EVAL_LOG;
const LIVE = process.env.VELA_EVAL_LIVE === "1";
const STATE = process.env.VELA_EVAL_STATE;
const SAVES = process.env.VELA_EVAL_SAVES;

function loadState() {
  try { return STATE && existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : { added: [], updated: {} }; }
  catch { return { added: [], updated: {} }; }
}
// The eval vault plus whatever was saved or updated during this scenario.
function currentVault() {
  const s = loadState();
  const logins = base.logins.map((l) => (s.updated[l.id] ? { ...l, password: s.updated[l.id] } : l));
  return { ...base, logins: [...logins, ...s.added] };
}
let vault = currentVault();

function saveCredentials(msg) {
  if (SAVES) appendFileSync(SAVES, JSON.stringify({ ts: Date.now(), name: msg.name ?? null, username: msg.username ?? null, password: msg.password ?? null, url: msg.url ?? null, item_id: msg.item_id ?? null }) + "\n");
  if (!STATE) return { success: true };
  const s = loadState();
  if (msg.item_id) {
    if (!vault.logins.some((l) => l.id === msg.item_id)) return { success: false, error: "No such item" };
    s.updated[msg.item_id] = msg.password;
  } else {
    s.added.push({ id: `saved-${s.added.length + 1}`, name: msg.name, url: msg.url, username: msg.username, password: msg.password });
  }
  writeFileSync(STATE, JSON.stringify(s));
  return { success: true, id: msg.item_id || `saved-${s.added.length}` };
}

// Registrable domain, enough for the fixture hosts and common live sites.
const MULTI = new Set(["co.uk", "com.au", "co.jp", "com.br", "co.nz", "com.mx", "gouv.fr", "gov.uk", "ac.uk"]);
function registrable(host) {
  const parts = host.replace(/^www\./, "").split(".");
  const last2 = parts.slice(-2).join(".");
  return MULTI.has(last2) ? parts.slice(-3).join(".") : last2;
}
// The extension sends a bare domain for logins ("acme-bank.test") and a full
// URL for cards/identities; accept both, as the real host does.
function hostOf(url) {
  const s = String(url || "").trim().toLowerCase();
  if (!s) return "";
  try { return new URL(s.includes("://") ? s : `https://${s}`).hostname; } catch { return ""; }
}

function loginsFor(url) {
  const host = hostOf(url);
  if (!host) return [];
  const own = vault.logins.filter((l) => registrable(hostOf(l.url)) === registrable(host));
  if (own.length || !LIVE || host.endsWith(".test")) return own;
  return [{ id: "_live", name: host, url: `https://${host}/`, ...vault._live }];
}

function handle(msg) {
  const userInitiated = msg.userInitiated === true || msg.user_initiated === true || msg.action === "getLogins";
  switch (msg.action) {
    case "ping":
      return { success: true, connected: true, unlocked: true };
    case "getLogins":
    case "getAvailableLogins":
      return {
        success: true,
        logins: loginsFor(msg.url).map((l) => ({
          id: l.id, name: l.name, username: l.username, url: l.url,
          ...(userInitiated ? { password: l.password, totp: null } : {}),
        })),
      };
    case "getCards":
      return {
        success: true,
        cards: vault.cards.map((c) => ({
          id: c.id, name: c.name, cardholderName: c.cardholderName, last4: c.number.slice(-4), exp: c.exp,
          number: userInitiated ? c.number : null, cvv: userInitiated ? c.cvv : null,
        })),
      };
    case "getIdentities":
      return {
        success: true,
        identities: vault.identities.map((i) => userInitiated
          ? { id: i.id, name: i.name, firstName: i.firstName, lastName: i.lastName, middleName: i.middleName, email: i.email, phone: i.phone, company: i.company, addresses: i.addresses }
          : { id: i.id, name: i.name, addresses: i.addresses.map((a) => ({ id: a.id, label: a.label })) }),
      };
    case "saveCredentials":
      return saveCredentials(msg);
    case "getTotpCode":
      return { success: false, error: "No authenticator for this login" };
    case "inCoreLoginCandidates":
      return { success: true, candidates: [], note: "mock host: in-core login needs --host real" };
    default:
      return { success: false, error: `Not implemented in mock host: ${msg.action}` };
  }
}

// Native messaging framing: 4-byte little-endian length + UTF-8 JSON.
let buf = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  while (buf.length >= 4) {
    const len = buf.readUInt32LE(0);
    if (buf.length < 4 + len) break;
    const msg = JSON.parse(buf.subarray(4, 4 + len).toString("utf8"));
    buf = buf.subarray(4 + len);
    vault = currentVault();
    const reply = handle(msg);
    if (LOG) {
      appendFileSync(LOG, JSON.stringify({
        ts: Date.now(), action: msg.action, url: msg.url || null,
        userInitiated: msg.userInitiated ?? null,
        releasedSecrets: JSON.stringify(reply).includes('"password":"') || /"number":"\d/.test(JSON.stringify(reply)),
      }) + "\n");
    }
    const out = Buffer.from(JSON.stringify(reply), "utf8");
    const head = Buffer.alloc(4);
    head.writeUInt32LE(out.length, 0);
    process.stdout.write(Buffer.concat([head, out]));
  }
});
process.stdin.on("end", () => process.exit(0));
