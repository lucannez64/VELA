// Scoring for the autofill eval. Pure functions over (scenario, snapshot,
// observation) so every runner — desktop Playwright, Android UiAutomator, iOS
// XCUITest — is judged by the same rules. See README.md "Scoring".
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const readJson = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

export function loadCorpus() {
  const manifest = readJson("corpus/manifest.json");
  const vault = readJson("corpus/vault.json");
  const nativeForms = readJson("corpus/native-forms.json");
  const liveSites = readJson("corpus/live-sites.json");
  // Optional, gitignored: sites from the user's own vault (lib/vault-sites.mjs).
  // Merged after the shared list; same ids are not repeated.
  const local = join(ROOT, "corpus/live-sites.local.json");
  if (existsSync(local)) {
    const ids = new Set(liveSites.sites.map((s) => s.id));
    liveSites.sites.push(...JSON.parse(readFileSync(local, "utf8")).sites.filter((s) => !ids.has(s.id)));
  }
  const liveApps = readJson("corpus/live-apps.json");
  const save = readJson("corpus/save.json");
  return { manifest, vault, nativeForms, liveSites, liveApps, save };
}

/** Scenarios a runner executes: every page that is not a frame/support page. */
export function fixtureScenarios(manifest) {
  return manifest.pages.filter((p) => !p.role);
}

// ── Reference resolution ────────────────────────────────────────────────────

/**
 * Resolve 'login:acme.password', 'card:visa.expMonth',
 * 'identity:alice.address.home.city', 'card:visa.number[0:4]'.
 * Returns { value, field } where field drives normalization.
 */
export function resolveRef(ref, vault) {
  const m = /^(login|card|identity):([^.]+)\.(.+?)(?:\[(\d+):(\d+)\])?$/.exec(ref);
  if (!m) throw new Error(`bad value ref: ${ref}`);
  const [, type, id, path, from, to] = m;
  const list = { login: vault.logins, card: vault.cards, identity: vault.identities }[type];
  const item = list.find((x) => x.id === id);
  if (!item) throw new Error(`unknown ${type} '${id}' in ${ref}`);
  let field = path;
  let value;
  if (type === "card") {
    const exp = parseExpiry(item.exp);
    value = {
      expMonth: exp && String(exp.month).padStart(2, "0"),
      expYear: exp && String(exp.year),
      exp: item.exp,
    }[path] ?? item[path];
  } else if (type === "identity") {
    const am = /^address\.([^.]+)\.(.+)$/.exec(path);
    if (am) {
      const addr = item.addresses.find((a) => a.id === am[1]);
      if (!addr) throw new Error(`unknown address in ${ref}`);
      field = am[2];
      value = field === "street" ? [addr.line1, addr.line2].filter(Boolean).join("\n") : addr[field];
    } else if (path === "fullName") {
      value = [item.firstName, item.middleName, item.lastName].filter(Boolean).join(" ");
    } else {
      value = item[path];
    }
  } else {
    value = item[path];
  }
  if (value == null) throw new Error(`empty value for ${ref}`);
  value = String(value);
  if (from != null) value = value.slice(Number(from), Number(to));
  return { type, id, field, value };
}

/** Every secret the vault holds; used for leak detection. */
export function vaultSecrets(vault) {
  const out = [];
  for (const l of vault.logins) out.push({ kind: "password", value: l.password, owner: `login:${l.id}` });
  for (const c of vault.cards) {
    out.push({ kind: "card-number", value: c.number, owner: `card:${c.id}` });
    out.push({ kind: "card-cvv", value: c.cvv, owner: `card:${c.id}`, short: true });
  }
  if (vault._live) out.push({ kind: "password", value: vault._live.password, owner: "login:_live" });
  return out;
}

// ── Normalization ───────────────────────────────────────────────────────────

export function parseExpiry(raw) {
  const s = String(raw ?? "").trim();
  if (!s) return null;
  let m = /^(\d{4})-(\d{1,2})$/.exec(s); // <input type=month>
  if (m) return { month: Number(m[2]), year: Number(m[1]) };
  m = /^(\d{1,2})\s*[/\-. ]\s*(\d{2}|\d{4})$/.exec(s);
  if (m) return { month: Number(m[1]), year: Number(m[2].length === 2 ? "20" + m[2] : m[2]) };
  m = /^(\d{2})(\d{2})$/.exec(s); // MMYY typed into a masked field
  if (m) return { month: Number(m[1]), year: Number("20" + m[2]) };
  return null;
}

const digits = (s) => String(s ?? "").replace(/\D/g, "");
const squash = (s) => String(s ?? "").replace(/\s+/g, " ").trim().toLowerCase();

function countryNames(code) {
  const names = new Set([code.toLowerCase()]);
  for (const lang of ["en", "fr", "de", "es"]) {
    try { names.add(new Intl.DisplayNames([lang], { type: "region" }).of(code).toLowerCase()); } catch {}
  }
  return names;
}

/**
 * Does an observed field (value, plus option text for a select) carry the
 * expected value? Lenient only where the web is legitimately varied (expiry
 * formats, phone prefixes, card spacing), strict everywhere else.
 */
export function valueMatches(expected, observed) {
  const { field, value } = expected;
  const seen = [observed?.value, observed?.text].filter((v) => v != null && v !== "");
  if (!seen.length) return false;
  return seen.some((raw) => {
    switch (field) {
      case "number":
        return digits(raw) === digits(value) && digits(value).length > 0;
      case "cvv":
        return digits(raw) === digits(value);
      case "exp": {
        const a = parseExpiry(raw), b = parseExpiry(value);
        return !!a && !!b && a.month === b.month && a.year % 100 === b.year % 100;
      }
      case "expMonth":
        return digits(raw) !== "" && Number(digits(raw)) === Number(value);
      case "expYear":
        return digits(raw) !== "" && Number(digits(raw)) % 100 === Number(value) % 100;
      case "phone": {
        const a = digits(raw), b = digits(value);
        if (a.length < 9 || b.length < 9) return a === b;
        return a === b || a.endsWith(b) || b.endsWith(a) || a.slice(-9) === b.slice(-9);
      }
      case "countryCode":
        return countryNames(value).has(squash(raw));
      case "street":
      case "fullName":
        return squash(raw) === squash(value) || squash(raw) === squash(value.split("\n")[0]);
      case "email":
      case "username":
        return squash(raw) === squash(value);
      default:
        return String(raw) === String(value);
    }
  });
}

// ── Scenario scoring (fixtures and native forms) ────────────────────────────

const isEmpty = (f) => !f || f.value == null || f.value === "" || (f.tag === "select" && f.defaultSelected);

/**
 * Score one scenario run.
 *  scenario:    manifest page or native form
 *  snapshot:    { [fieldKey]: { value, text?, type, tag, visible, defaultSelected? } }
 *  observation: { offered, error, inCore? }
 */
export function scoreScenario(scenario, snapshot, observation, vault) {
  const expect = scenario.expect || {};
  const result = {
    expected: 0, correct: 0, wrong: [], missed: [], negativesTouched: [], leaks: [],
    spuriousFills: [], generatedOk: null, offered: observation.offered ?? null,
  };
  const secrets = vaultSecrets(vault);
  const expectedKeys = new Set(Object.keys(expect));

  for (const [key, spec] of Object.entries(expect)) {
    result.expected++;
    const observed = snapshot[key];
    if (spec === "@generated") {
      const v = observed?.value || "";
      const ok = v.length >= 8 && !secrets.some((s) => s.value === v);
      result.generatedOk = ok;
      if (ok) result.correct++; else (isEmpty(observed) ? result.missed : result.wrong).push({ key, expected: "@generated", got: redact(v) });
      continue;
    }
    if (typeof spec === "string" && spec.startsWith("@same:")) {
      const other = snapshot[spec.slice(6)]?.value || "";
      const v = observed?.value || "";
      if (v && v === other) result.correct++;
      else (isEmpty(observed) ? result.missed : result.wrong).push({ key, expected: spec, got: redact(v) });
      continue;
    }
    const alts = (Array.isArray(spec) ? spec : [spec]).map((r) => resolveRef(r, vault));
    if (alts.some((e) => valueMatches(e, observed))) result.correct++;
    else if (isEmpty(observed)) result.missed.push({ key, expected: spec });
    else result.wrong.push({ key, expected: spec, got: redact(observed.value) });
  }

  for (const key of scenario.mustStayEmpty || []) {
    if (!isEmpty(snapshot[key])) result.negativesTouched.push({ key, got: redact(snapshot[key].value) });
  }

  // Anything filled that the scenario did not ask for (and that the page did
  // not prefill) is spurious. Not fatal on its own, but it is reported.
  for (const [key, f] of Object.entries(snapshot)) {
    if (expectedKeys.has(key) || isEmpty(f) || f.prefilled) continue;
    if ((scenario.mustStayEmpty || []).includes(key)) continue;
    result.spuriousFills.push({ key });
  }

  // Leaks: a stored secret anywhere it was not expected. A password in a
  // visible non-password field, or any secret in a field the scenario said to
  // keep clean, is critical.
  const expectedSecretKeys = new Set();
  for (const [key, spec] of Object.entries(expect)) {
    for (const r of (Array.isArray(spec) ? spec : [spec])) {
      if (/^login:.*\.password$/.test(r) || /^card:.*\.(number|cvv)/.test(r)) expectedSecretKeys.add(key);
    }
  }
  const mustNotHold = new Set(scenario.mustNotHoldSecrets || []);
  const keepClean = new Set([...mustNotHold, ...(scenario.mustStayEmpty || [])]);
  for (const [key, f] of Object.entries(snapshot)) {
    if (!f || !f.value) continue;
    for (const s of secrets) {
      // A 3-digit CVV is indistinguishable from ordinary input, so it only
      // counts as a leak in a field the scenario said to keep clean.
      if (s.short && !keepClean.has(key)) continue;
      const hit = s.short ? digits(f.value) === s.value
        : f.value.includes(s.value) || (s.kind === "card-number" && digits(f.value) === s.value);
      if (!hit) continue;
      if (expectedSecretKeys.has(key) && !mustNotHold.has(key)) continue;
      const exposedAsText = s.kind === "password" && f.type !== "password" && f.visible !== false;
      result.leaks.push({ key, secret: s.kind, owner: s.owner, critical: exposedAsText || mustNotHold.has(key) || s.kind !== "password" || (scenario.mustStayEmpty || []).includes(key) });
    }
  }

  const critical = result.leaks.filter((l) => l.critical).length + result.negativesTouched.length;
  result.critical = critical;
  result.fieldRecall = result.expected ? result.correct / result.expected : null;
  const filledCount = result.correct + result.wrong.length + result.negativesTouched.length;
  result.fieldPrecision = filledCount ? result.correct / filledCount : null;

  if (scenario.mustNotOffer) {
    result.falseOffer = observation.offered === true;
    result.pass = !result.falseOffer && critical === 0 && result.wrong.length === 0;
  } else {
    result.pass = result.expected > 0 && result.correct === result.expected && result.wrong.length === 0 && critical === 0;
  }

  if (observation.inCore) result.inCore = scoreInCore(scenario, observation.inCore, snapshot, vault);
  if (observation.error) result.error = observation.error;
  return result;
}

/**
 * In-core login: the desktop signs in and hands the browser a session; the
 * password must never reach the page. Pass = expected outcome reached AND no
 * stored password ever seen in any field the beacon reported (including the
 * history it kept, not just the final state).
 */
export function scoreInCore(scenario, inCore, snapshot, vault) {
  const want = scenario.inCore?.expect || "signed-in";
  const passwords = vault.logins.map((l) => l.password);
  const everSeen = [...Object.values(snapshot).map((f) => f?.value || ""), ...(inCore.valueHistory || [])];
  const passwordTouchedPage = everSeen.some((v) => passwords.some((p) => v && v.includes(p)));
  let outcome;
  if (inCore.candidates === 0) outcome = "no-candidates";
  else if (inCore.signedIn) outcome = "signed-in";
  else outcome = inCore.error ? "error" : "not-signed-in";
  return {
    want, outcome, passwordTouchedPage,
    pass: outcome === want && !passwordTouchedPage,
    durationMs: inCore.durationMs ?? null,
    error: inCore.error || null,
  };
}

// ── Live tier: role oracle ──────────────────────────────────────────────────

/**
 * What a field on an unlabelled live page most likely is. Only strong
 * signals: autocomplete tokens, input type, and unambiguous name/id words.
 * 'unknown' fields are not scored for correctness, only for leaks.
 */
export function oracleRole(f) {
  const ac = (f.autocomplete || "").toLowerCase();
  const words = `${f.name || ""} ${f.id || ""} ${f.placeholder || ""} ${f.label || ""}`.toLowerCase();
  // Tokens split on anything non-alphanumeric, so 'login_field' → login, field.
  const tokens = new Set(words.split(/[^a-z0-9]+/).filter(Boolean));
  const any = (...t) => t.some((x) => tokens.has(x));
  if (f.type === "password" || /current-password|new-password/.test(ac)) return /new-password/.test(ac) ? "new-password" : "password";
  if (/cc-number/.test(ac) || /card.?number|cardnumber|ccnum/.test(words)) return "cc-number";
  if (/cc-csc/.test(ac) || any("cvc", "cvv", "csc")) return "cc-csc";
  if (/cc-exp/.test(ac)) return "cc-exp";
  if (/\busername\b/.test(ac)) return "username";
  if (f.type === "email" || /\bemail\b/.test(ac)) return "email";
  if (f.type === "search" || any("search", "query") || words.trim() === "q") return "search";
  if (any("user", "username", "login", "identifier", "userid")) return "username";
  if (/e-?mail/.test(words)) return "email";
  if (/given-name|family-name|address-line|postal-code|address-level/.test(ac)) return "identity";
  return "unknown";
}

/**
 * Score a live-site run. There is no ground truth per field, so:
 *  - 'offered': did VELA surface anything when the anchor was focused
 *  - 'filledRoles': which oracle roles received the synthetic live values
 *  - 'misfills': a value of one kind in a field of a clearly different role
 *  - leaks: the synthetic password anywhere but a password field (critical)
 */
export function scoreLive(site, frames, observation, vault) {
  const live = vault._live;
  const card = vault.cards[0];
  const identity = vault.identities[0];
  const res = { offered: observation.offered ?? null, filled: [], misfills: [], leaks: [], reachable: observation.reachable !== false };
  for (const f of frames.flatMap((fr) => fr.fields)) {
    if (!f.value || f.prefilled) continue;
    const role = oracleRole(f);
    const kindOf = (v) =>
      v === live.password ? "password" :
      squash(v) === squash(live.username) ? "username" :
      digits(v) === card.number ? "cc-number" :
      squash(v) === squash(identity.email) ? "email" :
      v === card.cvv ? "cc-csc" : null;
    const k = kindOf(f.value);
    if (!k) continue;
    res.filled.push({ role, value: k, frame: f.frame });
    const compatible = {
      password: ["password", "new-password"], username: ["username", "email", "unknown"], email: ["email", "username", "unknown"],
      "cc-number": ["cc-number", "unknown"], "cc-csc": ["cc-csc", "password", "unknown"],
    }[k];
    if (!compatible.includes(role)) res.misfills.push({ role, value: k, name: f.name || f.id || "" });
    if (k === "password" && f.type !== "password") res.leaks.push({ role, name: f.name || f.id || "", critical: true });
    if (k === "cc-number" && role === "search") res.leaks.push({ role, name: f.name || f.id || "", critical: true });
  }
  const wanted = { login: ["password"], signup: [], email: ["username", "email"], identity: ["email"], card: ["cc-number"] }[site.kind] || [];
  res.coreFilled = wanted.length === 0 ? null : wanted.some((w) => res.filled.some((x) => x.value === w || (w === "email" && x.value === "username")));
  // Identifier-first sign-in: step one shows no password field, so the
  // username is all there is to fill.
  const visiblePassword = frames.some((fr) => fr.fields.some((f) => f.type === "password" && f.visible !== false));
  if (site.kind === "login" && !res.coreFilled && !visiblePassword && res.filled.some((x) => x.value === "username")) res.coreFilled = true;
  res.critical = res.leaks.filter((l) => l.critical).length;
  // The site marked the field data-bwignore / data-1p-ignore / data-lpignore:
  // the right behaviour is to stay out of it.
  if (observation.optedOut) {
    res.optedOut = true;
    res.pass = res.reachable && res.filled.length === 0 && res.critical === 0;
    return res;
  }
  res.pass = res.reachable && res.offered !== false && (res.coreFilled !== false) && res.misfills.length === 0 && res.critical === 0;
  return res;
}

function redact(v) {
  if (v == null) return v;
  const s = String(v);
  return s.length <= 4 ? s : `${s.slice(0, 2)}…(${s.length})`;
}

/**
 * Save/update capture. `observed`:
 *   prompt     "save" | "update" | "none" (which bar VELA showed after submit)
 *   dialog     { username, password } prefilled in the review dialog
 *   payload    the saveCredentials message the host received after confirming
 *   releases   secret-bearing login lookups the host answered between submit
 *              and the prompt, with no fill chosen by the person
 *
 * Pass: the right prompt, and for save/update the dialog and the stored
 * login both carry the typed username and the NEW password, for the right
 * site, as an update of the right item (or a new item for save).
 */
export function scoreSave(scenario, observed, vault) {
  const e = scenario.expect;
  const o = observed || {};
  const prompt = o.prompt || "none";
  const r = {
    prompt, expectedPrompt: e.prompt,
    promptCorrect: prompt === e.prompt,
    falsePrompt: e.prompt === "none" && prompt !== "none",
    missedPrompt: e.prompt !== "none" && prompt === "none",
    releases: o.releases || 0,
    problems: [],
  };
  if (!r.promptCorrect) r.problems.push(`prompt ${prompt}, expected ${e.prompt}`);
  if (e.prompt !== "none" && prompt !== "none") {
    const d = o.dialog || {};
    const p = o.payload;
    r.dialogUsername = d.username === e.username;
    r.dialogPassword = d.password === e.password;
    if (!r.dialogUsername) r.problems.push(`dialog username ${JSON.stringify(redact(d.username))}`);
    if (!r.dialogPassword) r.problems.push(`dialog password ${redact(d.password)}`);
    if (!p) r.problems.push("nothing reached the vault");
    else {
      r.storedUsername = p.username === e.username;
      r.storedPassword = p.password === e.password;
      let host = "";
      try { host = new URL(p.url).hostname; } catch {}
      r.storedHost = host === (e.host || scenario.host);
      r.storedAs = p.item_id ? "update" : "new";
      r.rightItem = e.prompt === "update" ? p.item_id === e.item : !p.item_id;
      if (!r.storedUsername) r.problems.push(`stored username ${JSON.stringify(redact(p.username))}`);
      if (!r.storedPassword) {
        // Storing the password the person just replaced loses the change.
        const old = e.item && vault.logins.find((l) => l.id === e.item)?.password;
        r.storedStalePassword = !!old && p.password === old;
        r.problems.push(r.storedStalePassword ? "stored the OLD password" : `stored password ${redact(p.password)}`);
      }
      if (!r.storedHost) r.problems.push(`stored for ${host || "?"}`);
      if (!r.rightItem) r.problems.push(e.prompt === "update" ? `stored as ${p.item_id ? "update of " + p.item_id : "a new item (duplicate)"}` : `overwrote ${p.item_id}`);
    }
  }
  if (o.error) r.problems.push(o.error);
  r.pass = r.problems.length === 0;
  return r;
}
