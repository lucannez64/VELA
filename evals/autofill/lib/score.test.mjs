// Unit tests for the scoring rules: the eval is only as good as its judge.
import test from "node:test";
import assert from "node:assert/strict";
import { loadCorpus, resolveRef, valueMatches, scoreScenario, scoreLive, oracleRole, parseExpiry, fixtureScenarios } from "./score.mjs";

const { manifest, vault, nativeForms } = loadCorpus();
const f = (value, extra = {}) => ({ value, type: "text", tag: "input", visible: true, ...extra });

test("every manifest and native-form reference resolves", () => {
  const all = [...fixtureScenarios(manifest), ...nativeForms.forms];
  for (const s of all) for (const spec of Object.values(s.expect || {}))
    for (const r of [spec].flat()) if (!r.startsWith("@")) assert.doesNotThrow(() => resolveRef(r, vault), `${s.id}: ${r}`);
});

test("every fixture page file exists and every anchor is an expected or step field", async () => {
  const { existsSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { ROOT } = await import("./score.mjs");
  for (const p of manifest.pages) assert.ok(existsSync(join(ROOT, "corpus/pages", p.path)), p.path);
  for (const p of fixtureScenarios(manifest)) assert.ok(p.anchor, `${p.id} has an anchor`);
});

test("expiry formats are accepted however the site formats them", () => {
  const exp = resolveRef("card:visa.exp", vault);
  for (const v of ["12/29", "12 / 29", "12/2029", "2029-12", "1229", "12-29"]) assert.ok(valueMatches(exp, f(v)), v);
  for (const v of ["11/29", "12/28", ""]) assert.ok(!valueMatches(exp, f(v)), v);
  assert.deepEqual(parseExpiry("2029-12"), { month: 12, year: 2029 });
  assert.ok(valueMatches(resolveRef("card:visa.expMonth", vault), f("12", { tag: "select" })));
  assert.ok(valueMatches(resolveRef("card:visa.expYear", vault), f("2029")));
  assert.ok(valueMatches(resolveRef("card:visa.expYear", vault), f("29")));
});

test("card numbers ignore spacing, phones ignore the country prefix, countries accept names", () => {
  assert.ok(valueMatches(resolveRef("card:visa.number", vault), f("4111 1111 1111 1111")));
  assert.ok(valueMatches(resolveRef("card:visa.number[4:8]", vault), f("1111")));
  assert.ok(valueMatches(resolveRef("identity:alice.phone", vault), f("(415) 555-0100")));
  const country = resolveRef("identity:alice.address.home.countryCode", vault);
  assert.ok(valueMatches(country, f("US", { tag: "select", text: "United States" })));
  assert.ok(valueMatches(country, f("United States", { tag: "select", text: "United States" })));
  assert.ok(!valueMatches(country, f("FR", { tag: "select", text: "France" })));
});

test("a perfect login fill passes; a password in the username field is a critical leak", () => {
  const page = manifest.pages.find((p) => p.id === "login-classic");
  const good = scoreScenario(page, { username: f("alice@acme-bank.test", { type: "email" }), password: f("Acme-Eval-7q!pass", { type: "password" }) }, { offered: true }, vault);
  assert.equal(good.pass, true);
  assert.equal(good.fieldRecall, 1);
  const swapped = scoreScenario(page, { username: f("Acme-Eval-7q!pass", { type: "email" }), password: f("alice@acme-bank.test", { type: "password" }) }, { offered: true }, vault);
  assert.equal(swapped.pass, false);
  assert.ok(swapped.critical >= 1, "password shown as text is critical");
});

test("decoys and honeypots must stay empty", () => {
  const page = manifest.pages.find((p) => p.id === "login-honeypot");
  const s = scoreScenario(page, {
    "real-user": f("alice.honey"), "real-pass": f("Honey-Eval-0a_pw", { type: "password" }),
    "hp-username": f("alice.honey", { visible: false }),
  }, { offered: true }, vault);
  assert.equal(s.pass, false);
  assert.equal(s.negativesTouched.length, 1);
});

test("negative pages fail on an offer even when nothing is filled", () => {
  const page = manifest.pages.find((p) => p.id === "login-lookalike");
  assert.equal(scoreScenario(page, {}, { offered: false }, vault).pass, true);
  assert.equal(scoreScenario(page, {}, { offered: true }, vault).pass, false);
});

test("generated passwords must be fresh and confirmed", () => {
  const page = manifest.pages.find((p) => p.id === "signup-new-password");
  const ok = scoreScenario(page, { "new-password": f("x9!Fresh-Generated-Pw", { type: "password" }), "confirm-password": f("x9!Fresh-Generated-Pw", { type: "password" }) }, { offered: true }, vault);
  assert.equal(ok.pass, true);
  const reused = scoreScenario(page, { "new-password": f("Acme-Eval-7q!pass", { type: "password" }), "confirm-password": f("Acme-Eval-7q!pass", { type: "password" }) }, { offered: true }, vault);
  assert.equal(reused.pass, false);
  assert.ok(reused.critical >= 1, "a stored password in a new-password field is critical");
});

test("in-core login fails if the password ever reached the page", () => {
  const page = manifest.pages.find((p) => p.id === "login-classic");
  const clean = scoreScenario(page, {}, { inCore: { candidates: 1, signedIn: true, valueHistory: [] } }, vault);
  assert.equal(clean.inCore.pass, true);
  const leaked = scoreScenario(page, {}, { inCore: { candidates: 1, signedIn: true, valueHistory: ["Acme-Eval-7q!pass"] } }, vault);
  assert.equal(leaked.inCore.pass, false);
  assert.equal(leaked.inCore.passwordTouchedPage, true);
});

test("live oracle: password in a search box is critical, username in email field is fine", () => {
  assert.equal(oracleRole({ type: "search", name: "q" }), "search");
  assert.equal(oracleRole({ type: "text", name: "login_field" }), "username");
  const site = { kind: "login" };
  const ok = scoreLive(site, [{ fields: [f(vault._live.username, { type: "email" }), f(vault._live.password, { type: "password" })] }], { offered: true }, vault);
  assert.equal(ok.pass, true);
  const bad = scoreLive(site, [{ fields: [f(vault._live.password, { type: "text", name: "q" })] }], { offered: true }, vault);
  assert.equal(bad.pass, false);
  assert.ok(bad.critical >= 1);
});

test("live: a site that opts out of password managers passes only if VELA stays out", () => {
  const site = { kind: "login" };
  assert.equal(scoreLive(site, [{ fields: [f("", { type: "email" })] }], { offered: false, optedOut: true }, vault).pass, true);
  assert.equal(scoreLive(site, [{ fields: [f(vault._live.username, { type: "email" })] }], { offered: true, optedOut: true }, vault).pass, false);
});
