// Verification harness: run the VELA WebAuthn shim in a stubbed page world and
// assert the returned object is `instanceof PublicKeyCredential` (and its
// `response` the matching Authenticator*Response), which is the compatibility
// gap being fixed. Requires Node 18+ (globals: crypto.subtle, btoa, atob,
// TextEncoder, DOMException).
"use strict";
const fs = require("fs");

const SRC = process.argv[2];
const src = fs.readFileSync(SRC, "utf8");

// Fake WebAuthn interfaces (empty classes — instanceof only needs the chain).
// Registered on globalThis, because the shim executes via `new Function(...)`
// where free identifiers resolve to the global scope, not this module scope.
globalThis.Credential = class Credential {};
globalThis.PublicKeyCredential = class PublicKeyCredential extends globalThis.Credential {};
globalThis.AuthenticatorResponse = class AuthenticatorResponse {};
globalThis.AuthenticatorAssertionResponse =
  class AuthenticatorAssertionResponse extends globalThis.AuthenticatorResponse {};
globalThis.AuthenticatorAttestationResponse =
  class AuthenticatorAttestationResponse extends globalThis.AuthenticatorResponse {};
const { PublicKeyCredential, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse } =
  globalThis;

const b64 = (buf) => Buffer.from(buf).toString("base64url");

// Fake results the "content script" returns, by bridge message type.
function fakeFor(type) {
  if (type === "passkeyList")
    return { credentials: [{ credential_id: b64([1, 2, 3]) }] };
  if (type === "passkeyGet")
    return {
      success: true,
      credential_id: b64([1, 2, 3]),
      authenticator_data: b64([0x81, 0x00, 0x00, 0x00]),
      signature: b64([0x30, 0x01, 0x02]),
      user_handle: b64([9, 9]),
    };
  if (type === "passkeyCreate")
    return {
      success: true,
      credential_id: b64([7, 8, 9]),
      attestation_object: b64([0xa0]),
      authenticator_data: b64([0x81, 0x00, 0x00, 0x00]),
    };
  return { success: false };
}

// A stub page world: window + navigator.credentials + location, with a
// postMessage bus that answers VELA requests as the content script would.
function makeWorld() {
  const listeners = [];
  const w = {
    location: { hostname: "example.com", origin: "https://example.com" },
    addEventListener(type, fn) {
      if (type === "message") listeners.push(fn);
    },
    postMessage(data) {
      if (data && data.__velaPasskey === true && data.direction === "request") {
        setTimeout(() => {
          const result = fakeFor(data.type);
          for (const fn of listeners)
            fn({ source: w, data: { __velaPasskey: true, direction: "response", id: data.id, result } });
        }, 0);
      }
    },
  };
  const nativeStub = async () => {
    throw new Error("native path should not be reached in these assertions");
  };
  const navigator = {
    credentials: { get: nativeStub, create: nativeStub },
  };
  return { w, navigator };
}

let failures = 0;
function check(name, cond) {
  console.log((cond ? "ok  " : "FAIL") + "  " + name);
  if (!cond) failures++;
}

async function run() {
  const { w, navigator } = makeWorld();
  // Execute the shim in the page world.
  new Function("window", "navigator", "crypto", src)(w, navigator, globalThis.crypto);

  // ── get (assertion) ──
  const cred = await navigator.credentials.get({
    publicKey: {
      rpId: "example.com",
      challenge: new Uint8Array([1, 2, 3, 4]),
      userVerification: "preferred",
    },
  });
  console.log("── get ──");
  check("instanceof PublicKeyCredential", cred instanceof PublicKeyCredential);
  check("instanceof Credential", cred instanceof Credential);
  check("type === 'public-key'", cred.type === "public-key");
  check("rawId instanceof ArrayBuffer", cred.rawId instanceof ArrayBuffer);
  check("typeof getClientExtensionResults === 'function'", typeof cred.getClientExtensionResults === "function");
  check("response instanceof AuthenticatorAssertionResponse", cred.response instanceof AuthenticatorAssertionResponse);
  check("response instanceof AuthenticatorResponse", cred.response instanceof AuthenticatorResponse);

  // ── create (registration) ──
  const made = await navigator.credentials.create({
    publicKey: {
      rp: { id: "example.com", name: "Example" },
      user: { id: new Uint8Array([9]), name: "ada", displayName: "Ada" },
      challenge: new Uint8Array([1, 2, 3, 4]),
      pubKeyCredParams: [{ alg: -7 }],
    },
  });
  console.log("── create ──");
  check("instanceof PublicKeyCredential", made instanceof PublicKeyCredential);
  check("response instanceof AuthenticatorAttestationResponse", made.response instanceof AuthenticatorAttestationResponse);
  check("response instanceof AuthenticatorResponse", made.response instanceof AuthenticatorResponse);
  check("getAuthenticatorData is callable", typeof made.response.getAuthenticatorData === "function");

  console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

run().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
