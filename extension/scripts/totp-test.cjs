// Regression test for RT-8: `generateTOTP` must actually produce a code. It was
// inert because `const time` then `time >>>= 8` threw (assignment to a const)
// and the catch returned "". Checks the fixed function against the RFC 6238
// SHA-1 test vectors.
"use strict";
const path = require("path");

// `background.js` needs a `browser` global (it reads `browser.runtime` etc. at
// module scope). Stub the namespaces it touches with no-op `addListener`s.
function stub() {
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
  globalThis.document = undefined;
}

stub();
const { generateTOTP } = require(path.join(
  __dirname,
  "..",
  "src",
  "background",
  "background.js"
));

// RFC 6238 SHA-1 vectors (8 digits), key = ASCII of "12345678901234567890".
// First column is EPOCH time in seconds; generateTOTP derives the counter as
// floor(epoch / period).
const SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32 of the ASCII key
const VECTORS = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

let failures = 0;
async function run() {
  for (const [epochSeconds, expected] of VECTORS) {
    const period = 30;
    const realNow = Date.now;
    Date.now = () => epochSeconds * 1000; // so counter = floor(epoch/period)
    let got;
    try {
      got = await generateTOTP(SECRET, "SHA-1", 8, period);
    } finally {
      Date.now = realNow;
    }
    const ok = got === expected;
    console.log(`${ok ? "ok  " : "FAIL"}  epoch=${epochSeconds} (counter=${Math.floor(epochSeconds / period)}) => ${got} (expected ${expected})`);
    if (!ok) failures++;
  }
  console.log(failures === 0 ? "\nALL RFC6238 VECTORS PASSED" : `\n${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}
run().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
