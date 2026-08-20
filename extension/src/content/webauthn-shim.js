/**
 * VELA's WebAuthn shim — runs in the PAGE's world, not the extension's.
 *
 * `navigator.credentials.create` and `.get` are overridden so a VELA passkey
 * can answer a relying party that has never heard of VELA. The credential key
 * itself lives in the desktop core and is never sent here: this file builds the
 * clientDataJSON envelope, asks the desktop for a signature over its hash, and
 * assembles the response the page expects. Only signatures cross the boundary,
 * which is the whole point of the M7 design
 * (`security/formal/m7_oneshot_assertion.spthy`).
 *
 * Why the page's world and not the content script's: `navigator.credentials`
 * in an isolated world is a different object from the one the page's own
 * JavaScript calls. Overriding it there would change nothing the relying party
 * ever sees.
 *
 * Deliberate restraint about when to intercept:
 *
 *  * `.get` is only intercepted when VELA actually holds a passkey for the
 *    relying party. Otherwise the real implementation runs, so security keys,
 *    platform authenticators and phone-as-authenticator keep working exactly as
 *    before. A password manager that breaks every login it cannot serve is
 *    worse than one that is not installed.
 *  * `.create` offers VELA first, but a refusal falls through to the real
 *    implementation rather than failing the ceremony — "not in VELA" must not
 *    mean "cannot register a passkey at all".
 *  * conditional mediation (the autofill-style UI) is always delegated: it
 *    needs browser UI this shim has no way to draw.
 *
 * Compatibility: the returned object is built with
 * `Object.create(PublicKeyCredential.prototype)` (and its `response` with the
 * matching `Authenticator*Response` prototype), so `instanceof
 * PublicKeyCredential` and the response-type checks that break a naive shim
 * both hold. The remaining wrapper is unresolved by any shim: an extension
 * cannot hand a binary `PublicKeyCredential` through the internal CDP event
 * boundary the way a native OS provider can, and some anti-fraud checks look
 * exactly there. The desktop-side ceremony API is transport-agnostic precisely
 * so a native provider can take that last step without touching this file.
 */
(() => {
  "use strict";

  if (window.__velaWebAuthnShimInstalled) return;
  window.__velaWebAuthnShimInstalled = true;

  const credentials = navigator.credentials;
  if (!credentials || typeof credentials.get !== "function") return;

  const nativeCreate =
    typeof credentials.create === "function" ? credentials.create.bind(credentials) : null;
  const nativeGet = credentials.get.bind(credentials);

  // ── Bridge to the content script ────────────────────────────────────────────

  const pending = new Map();
  let sequence = 0;

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.__velaPasskey !== true || data.direction !== "response") return;
    const settle = pending.get(data.id);
    if (!settle) return;
    pending.delete(data.id);
    settle(data.result || { success: false, error: "No response from VELA" });
  });

  function askVela(type, payload, timeoutMs) {
    return new Promise((resolve) => {
      const id = `vela-pk-${++sequence}-${Math.random().toString(36).slice(2)}`;
      const timer = setTimeout(() => {
        pending.delete(id);
        resolve({ success: false, error: "VELA did not respond" });
      }, timeoutMs);
      pending.set(id, (result) => {
        clearTimeout(timer);
        resolve(result);
      });
      window.postMessage({ __velaPasskey: true, direction: "request", id, type, payload }, "*");
    });
  }

  // ── Encoding helpers ────────────────────────────────────────────────────────

  function toBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function fromBase64Url(value) {
    if (typeof value !== "string") return new ArrayBuffer(0);
    const padded = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function asBuffer(value) {
    if (value instanceof ArrayBuffer) return value;
    if (ArrayBuffer.isView(value)) return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
    return null;
  }

  // A shimmed credential has to pass `instanceof PublicKeyCredential` — a
  // growing number of relying parties type-check before they will use the
  // result. A real credential cannot be constructed from script, but an object
  // whose prototype chain runs through `PublicKeyCredential.prototype` *is* an
  // instance of it; the own properties assigned below shadow the interface's
  // internal-slot accessors (rawId, response, id, …) with the real values, and
  // `getClientExtensionResults` is supplied on the instance, so the shape a
  // relying party reads is indistinguishable in the ways that matter.
  function publicKeyCredential(properties) {
    if (typeof PublicKeyCredential === "undefined") return properties;
    return Object.assign(Object.create(PublicKeyCredential.prototype), properties);
  }

  // Same trick for the `response` members, so `response instanceof
  // AuthenticatorAssertionResponse` (or `AuthenticatorAttestationResponse`)
  // also holds — some sites check those too.
  function assertionResponse(properties) {
    const proto =
      typeof AuthenticatorAssertionResponse !== "undefined"
        ? AuthenticatorAssertionResponse.prototype
        : Object.prototype;
    return Object.assign(Object.create(proto), properties);
  }
  function attestationResponse(properties) {
    const proto =
      typeof AuthenticatorAttestationResponse !== "undefined"
        ? AuthenticatorAttestationResponse.prototype
        : Object.prototype;
    return Object.assign(Object.create(proto), properties);
  }

  /**
   * The relying party ID for this ceremony.
   *
   * When the page names one, it must be the page's own domain or a parent of
   * it — that check is the browser's job and it is not optional here either,
   * because a page that could name any RP ID could ask VELA to sign for a site
   * it has nothing to do with.
   */
  function resolveRpId(requested) {
    const host = window.location.hostname;
    if (!requested) return host;
    if (requested === host) return requested;
    if (host.endsWith(`.${requested}`)) return requested;
    return null;
  }

  async function clientData(type, challenge) {
    const json = JSON.stringify({
      type,
      challenge: toBase64Url(challenge),
      origin: window.location.origin,
      crossOrigin: false,
    });
    const encoded = new TextEncoder().encode(json);
    const hash = await crypto.subtle.digest("SHA-256", encoded);
    return { bytes: encoded, hash };
  }

  function credentialIdList(descriptors) {
    if (!Array.isArray(descriptors)) return [];
    return descriptors
      .map((descriptor) => asBuffer(descriptor && descriptor.id))
      .filter(Boolean)
      .map(toBase64Url);
  }

  function requiresUserVerification(selection) {
    return Boolean(selection && selection.userVerification === "required");
  }

  function notAllowed(message) {
    return new DOMException(message || "The passkey request was refused.", "NotAllowedError");
  }

  // A ceremony waits for a person to read a dialog and decide. The browser's
  // own WebAuthn timeouts are minutes for the same reason.
  const CEREMONY_TIMEOUT_MS = 125000;
  const LOOKUP_TIMEOUT_MS = 5000;

  // ── navigator.credentials.get ───────────────────────────────────────────────

  credentials.get = async function get(options) {
    const publicKey = options && options.publicKey;
    if (!publicKey || options.mediation === "conditional") {
      return nativeGet(options);
    }

    const rpId = resolveRpId(publicKey.rpId);
    const challenge = asBuffer(publicKey.challenge);
    if (!rpId || !challenge) return nativeGet(options);

    // Silent: does VELA have anything for this site at all? If not, get out of
    // the way entirely rather than prompting about a login we cannot serve.
    const available = await askVela("passkeyList", { rp_id: rpId }, LOOKUP_TIMEOUT_MS);
    const stored = (available && available.credentials) || [];
    if (!stored.length) return nativeGet(options);

    // If the relying party named specific credentials, only proceed when one of
    // ours is among them.
    const allowed = credentialIdList(publicKey.allowCredentials);
    if (allowed.length && !stored.some((entry) => allowed.includes(entry.credential_id))) {
      return nativeGet(options);
    }

    if (options.signal && options.signal.aborted) throw notAllowed("Request aborted.");

    const { bytes, hash } = await clientData("webauthn.get", challenge);
    const result = await askVela(
      "passkeyGet",
      {
        rp_id: rpId,
        client_data_hash: toBase64Url(hash),
        allow_credentials: allowed,
        require_user_verification: publicKey.userVerification === "required",
      },
      CEREMONY_TIMEOUT_MS
    );

    if (!result || !result.success) throw notAllowed(result && result.error);

    return publicKeyCredential({
      id: result.credential_id,
      rawId: fromBase64Url(result.credential_id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: assertionResponse({
        clientDataJSON: bytes.buffer,
        authenticatorData: fromBase64Url(result.authenticator_data),
        signature: fromBase64Url(result.signature),
        userHandle: result.user_handle ? fromBase64Url(result.user_handle) : null,
      }),
      getClientExtensionResults: () => ({}),
    });
  };

  // ── navigator.credentials.create ────────────────────────────────────────────

  if (nativeCreate) {
    credentials.create = async function create(options) {
      const publicKey = options && options.publicKey;
      if (!publicKey) return nativeCreate(options);

      const rpId = resolveRpId(publicKey.rp && publicKey.rp.id);
      const challenge = asBuffer(publicKey.challenge);
      const userId = asBuffer(publicKey.user && publicKey.user.id);
      if (!rpId || !challenge || !userId) return nativeCreate(options);

      const algorithms = Array.isArray(publicKey.pubKeyCredParams)
        ? publicKey.pubKeyCredParams.map((param) => param && param.alg).filter((alg) => typeof alg === "number")
        : [];
      // ES256 is all this authenticator implements; if the site will not take
      // it, the platform authenticator may still have something it will.
      if (algorithms.length && !algorithms.includes(-7)) return nativeCreate(options);

      if (options.signal && options.signal.aborted) throw notAllowed("Request aborted.");

      const { bytes, hash } = await clientData("webauthn.create", challenge);
      const result = await askVela(
        "passkeyCreate",
        {
          rp_id: rpId,
          rp_name: (publicKey.rp && publicKey.rp.name) || rpId,
          user_handle: toBase64Url(userId),
          user_name: (publicKey.user && publicKey.user.name) || "",
          user_display_name: (publicKey.user && publicKey.user.displayName) || "",
          client_data_hash: toBase64Url(hash),
          algorithms,
          exclude_credentials: credentialIdList(publicKey.excludeCredentials),
          require_user_verification: requiresUserVerification(publicKey.authenticatorSelection),
        },
        CEREMONY_TIMEOUT_MS
      );

      // Declined, locked, or unreachable: let the browser do what it would have
      // done without VELA installed.
      if (!result || !result.success) return nativeCreate(options);

      return publicKeyCredential({
        id: result.credential_id,
        rawId: fromBase64Url(result.credential_id),
        type: "public-key",
        authenticatorAttachment: "platform",
        response: attestationResponse({
          clientDataJSON: bytes.buffer,
          attestationObject: fromBase64Url(result.attestation_object),
          getAuthenticatorData: () => fromBase64Url(result.authenticator_data),
          getPublicKeyAlgorithm: () => -7,
          getTransports: () => ["internal"],
          getPublicKey: () => null,
        }),
        getClientExtensionResults: () => ({}),
      });
    };
  }
})();
