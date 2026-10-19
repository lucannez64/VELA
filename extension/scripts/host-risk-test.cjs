// Regression test for the IDN/homograph detector used to warn on lookalike
// domains. Requires `src/shared/autofill-utils.js` (an IIFE that publishes
// `globalThis.VelaAutofill`) and checks the punycode decoder, mixed-script
// detection, and per-site key normalization.
"use strict";
const path = require("path");

require(path.join(__dirname, "..", "src", "shared", "autofill-utils.js"));
const { hostRisk, siteKey } = globalThis.VelaAutofill;

let failures = 0;
function check(label, actual, expected) {
  const ok = actual === expected;
  console.log(`${ok ? "ok  " : "FAIL"}  ${label} => ${JSON.stringify(actual)} (expected ${JSON.stringify(expected)})`);
  if (!ok) failures++;
}

// `xn--pple-43d` is Cyrillic-а + "pple" — the canonical homograph.
const homograph = hostRisk("xn--pple-43d.com");
check("homograph level", homograph.level, "warn");
check("homograph decodes", homograph.unicode, "аpple.com");
check("homograph reason", homograph.reasons.includes("mixed-script"), true);

// A legitimate single-script internationalized domain must not warn.
check("legit IDN (münchen.de)", hostRisk("xn--mnchen-3ya.de").level, "none");
check("legit IDN (中国)", hostRisk("xn--fiqs8s").level, "none");

check("plain ascii", hostRisk("example.com").level, "none");
check("ascii subdomain", hostRisk("sub.example.co.uk").level, "none");
check("empty host", hostRisk("").level, "none");

check("siteKey strips www and lowercases", siteKey("https://www.Example.com/login"), "example.com");
check("siteKey keeps subdomains", siteKey("https://app.example.com/x"), "app.example.com");
check("siteKey handles localhost", siteKey("http://localhost:3000/x"), "localhost");

console.log(failures === 0 ? "\nALL HOST-RISK CHECKS PASSED" : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
