/**
 * Relay between the page-world WebAuthn shim and the extension background.
 *
 * Runs in the content script's isolated world, which is the only place that can
 * see both `window.postMessage` traffic from the page and `runtime.sendMessage`
 * to the background. Two jobs:
 *
 *  1. inject `webauthn-shim.js` into the page's own world, early enough that a
 *     relying party calling `navigator.credentials.get()` on load sees the
 *     override rather than the original;
 *  2. forward the shim's requests to the background and post the answers back.
 *
 * Nothing secret passes through here. The requests carry a relying party ID and
 * a client-data hash; the responses carry a signature and public metadata. The
 * credential key never leaves the desktop core, so a compromised page — or a
 * compromised content script — gains no material it could reuse.
 */
(() => {
  "use strict";

  if (window.__velaPasskeyBridgeInstalled) return;
  window.__velaPasskeyBridgeInstalled = true;

  const runtime = (globalThis.browser && globalThis.browser.runtime) || globalThis.chrome?.runtime;
  if (!runtime) return;

  // The build flattens `src/content/` to `content/`, but the repo's own
  // manifest loads unpacked with the `src/` prefix intact. Try both rather than
  // making the shim's availability depend on how the extension was loaded.
  const SHIM_PATHS = ["content/webauthn-shim.js", "src/content/webauthn-shim.js"];

  // Inject into the page's world. `document_start` means `document.head` may
  // not exist yet, hence the fallback to whatever root element is there.
  function injectShim(index) {
    if (index >= SHIM_PATHS.length) return;
    let script;
    try {
      script = document.createElement("script");
      script.src = runtime.getURL(SHIM_PATHS[index]);
      script.async = false;
      // Remove the tag once it has run; the override it installed persists.
      script.onload = () => script.remove();
      script.onerror = () => {
        script.remove();
        injectShim(index + 1);
      };
      (document.head || document.documentElement).prepend(script);
    } catch {
      // A page whose CSP forbids the injection keeps the browser's own
      // WebAuthn. That is a degraded experience, not a broken one, so there is
      // nothing to report here.
    }
  }

  injectShim(0);

  const FORWARDED = new Set(["passkeyCreate", "passkeyGet", "passkeyList"]);

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.__velaPasskey !== true || data.direction !== "request") return;
    if (!FORWARDED.has(data.type)) return;

    const reply = (result) => {
      window.postMessage(
        { __velaPasskey: true, direction: "response", id: data.id, result },
        window.location.origin === "null" ? "*" : window.location.origin
      );
    };

    try {
      const sending = runtime.sendMessage({ command: data.type, ...(data.payload || {}) });
      // Chrome's callback form and Firefox's promise form both exist in the
      // wild depending on the polyfill; handle whichever this browser gave us.
      if (sending && typeof sending.then === "function") {
        sending.then(reply, (error) => reply({ success: false, error: String(error && error.message) }));
      } else {
        reply({ success: false, error: "VELA could not reach its background worker" });
      }
    } catch (error) {
      reply({ success: false, error: String(error && error.message) });
    }
  });
})();
