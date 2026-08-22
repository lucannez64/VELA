/**
 * Jazzer fuzz harness for VELA's extension JavaScript.
 *
 * Surfaces (all attacker-influenced, all exercised synchronously):
 *   - background.js `base32ToBytes` — vault-stored TOTP secrets arrive from
 *     sync; pure function, must be total and deterministic.
 *   - webauthn-shim.js base64url round trip (`toBase64Url`/`fromBase64Url`)
 *     — page-controlled strings feed these on every WebAuthn ceremony.
 *
 * The shim is a strict arrow-IIFE that installs itself onto `window` and
 * bails early without browser plumbing, so instead of fighting its scope the
 * harness extracts the two helper functions by brace matching and evaluates
 * them standalone. `generateTOTP` (async, WebCrypto) keeps its coverage in
 * scripts/totp-test.cjs; its only fuzzable input transform is the
 * `base32ToBytes` driven here.
 */

const fs = require("fs");
const path = require("path");

// background.js reads `browser.*` at module scope; stub it the same way
// scripts/totp-test.cjs does.
(function stubBrowser() {
  const on = { addListener() {} };
  globalThis.browser = {
    runtime: {
      onConnect: on,
      onMessage: on,
      onInstalled: on,
      onStartup: on,
      connect() {},
      sendMessage() {},
      onMessageExternal: on,
      id: "test",
    },
    tabs: { onUpdated: on, sendMessage() {} },
    contextMenus: { onClicked: on, create() {}, removeAll() {} },
    commands: { onCommand: on },
    action: {},
  };
})();

const { base32ToBytes } = require(path.join("..", "src", "background", "background.js"));

/** Pull one top-level `function NAME(...) {...}` out of a source string. */
function extractFunction(source, name) {
  const marker = "function " + name + "(";
  const start = source.indexOf(marker);
  if (start === -1) {
    throw new Error(`function ${name} not found in shim source`);
  }
  let i = source.indexOf("{", start);
  let depth = 0;
  for (; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") {
      depth--;
      if (depth === 0) break;
    }
  }
  return source.slice(start, i + 1);
}

const shimSource = fs.readFileSync(
  path.join(__dirname, "..", "src", "content", "webauthn-shim.js"),
  "utf8"
);
globalThis.btoa = (b) => Buffer.from(b, "binary").toString("base64");
globalThis.atob = (s) => Buffer.from(s, "base64").toString("binary");
const shimCode =
  extractFunction(shimSource, "toBase64Url") +
  "\n" +
  extractFunction(shimSource, "fromBase64Url") +
  "\nglobalThis.__velaShimHelpers = { toBase64Url, fromBase64Url };";
// Evaluate inside a function scope so the extracted declarations don't
// collide with this module's own bindings.
new Function(shimCode)();
const { toBase64Url, fromBase64Url } = globalThis.__velaShimHelpers;

/** Jazzer entry: arbitrary bytes each iteration. */
module.exports.fuzz = function (data) {
  if (data.length === 0 || data.length > 8192) return;

  const text = data.toString("latin1");

  // ── base32 decode ──────────────────────────────────────────────────────
  const first = base32ToBytes(text);
  const second = base32ToBytes(text);
  for (let i = 0; i < first.length; i++) {
    if (first[i] !== second[i]) {
      throw new Error(`base32ToBytes nondeterministic for ${JSON.stringify(text)}`);
    }
  }
  // Output can only be whole bytes derived from valid chars. Count AFTER the
  // same normalization the implementation applies — `.toUpperCase()` can
  // expand one code point into several ASCII letters (ß → SS, ﬀ → FF), so
  // counting the raw string under-reports.
  const normalized = text.replace(/[\s=]/g, "").toUpperCase();
  const validChars = normalized.replace(/[^A-Z2-7]/g, "").length;
  if (first.length > Math.ceil((validChars * 5) / 8)) {
    throw new Error(
      `base32ToBytes produced ${first.length} bytes from ${validChars} chars`
    );
  }

  // ── base64url round trip ───────────────────────────────────────────────
  const b64url = toBase64Url(data);
  if (!/^[A-Za-z0-9_-]*$/.test(b64url)) {
    throw new Error(`toBase64Url emitted non-url-safe chars: ${b64url}`);
  }
  const back = new Uint8Array(fromBase64Url(b64url));
  if (back.length !== data.length) {
    throw new Error(`round trip length ${back.length} != ${data.length}`);
  }
  for (let i = 0; i < data.length; i++) {
    if (back[i] !== data[i]) {
      throw new Error(`round trip changed byte ${i}`);
    }
  }
};
