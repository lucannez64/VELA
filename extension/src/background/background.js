if (typeof browser === "undefined") {
  try { importScripts("../shared/browser-polyfill.js"); } catch (e) {}
}

const AUTOFILL_PORT = "injected-script";
const NATIVEMessaging_PORT = "com.vela.desktop";
const LOGIN_REQUEST_DEDUP_MS = 1500;

const { runtime, tabs, contextMenus, commands, action } = browser;

let desktopConnection = null;
let activeTabId = null;
const loginRequestCache = new Map();

function base32ToBytes(base32) {
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  base32 = base32.replace(/[\s=]/g, "").toUpperCase();
  const bytes = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (const char of base32) {
    const value = base32Chars.indexOf(char);
    if (value === -1) continue;
    buffer = (buffer << 5) | value;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bytes.push((buffer >>> (bitsLeft - 8)) & 0xff);
      bitsLeft -= 8;
    }
  }
  return new Uint8Array(bytes);
}

async function generateTOTP(secret, algorithm = "SHA-1", digits = 6, period = 30) {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      base32ToBytes(secret),
      { name: "HMAC", hash: { name: algorithm } },
      false,
      ["sign"]
    );
    const time = Math.floor(Date.now() / 1000 / period);
    const timeBytes = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) {
      timeBytes[i] = time & 0xff;
      time >>>= 8;
    }
    const hmac = await crypto.subtle.sign("HMAC", key, timeBytes);
    const hash = new Uint8Array(hmac);
    const offset = hash[hash.length - 1] & 0x0f;
    const code =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);
    return String(code % Math.pow(10, digits)).padStart(digits, "0");
  } catch (e) {
    return "";
  }
}

function parseOtpauthUri(uri) {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "otpauth:") return null;
    const type = parsed.hostname;
    if (type !== "totp") return null;
    const secret = parsed.searchParams.get("secret");
    if (!secret) return null;
    const alg = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase();
    const algMap = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };
    // Clamp to sane ranges: an unbounded `digits` feeds Math.pow(10, digits)
    // and String.padStart(digits, ...) below, so a malicious/corrupt
    // otpauth:// URI (from imported/synced/shared vault data, processed
    // automatically with no user interaction) could allocate a
    // hundreds-of-megabytes string. An unbounded/zero `period` divides by
    // zero in generateTOTP's time-step calculation.
    const rawDigits = parseInt(parsed.searchParams.get("digits") || "6", 10);
    const rawPeriod = parseInt(parsed.searchParams.get("period") || "30", 10);
    const digits = Number.isFinite(rawDigits) ? Math.min(Math.max(rawDigits, 6), 10) : 6;
    const period = Number.isFinite(rawPeriod) ? Math.min(Math.max(rawPeriod, 5), 300) : 30;
    return {
      secret,
      algorithm: algMap[alg] || "SHA-1",
      digits,
      period
    };
  } catch (e) {
    return null;
  }
}

async function computeLoginTOTP(item) {
  if (item.totp_code) return item.totp_code;
  if (item.totp) {
    const otp = parseOtpauthUri(item.totp);
    if (otp) {
      return await generateTOTP(otp.secret, otp.algorithm, otp.digits, otp.period);
    }
    return await generateTOTP(item.totp);
  }
  return "";
}

function init() {
  setupConnectionListeners();
  setupContextMenus();
  setupMessageListeners();
  setupCommandListeners();
}

function setupConnectionListeners() {
  runtime.onConnect.addListener((port) => {
    if (port.name === AUTOFILL_PORT) {
      setupAutofillPortListeners(port);
    }
  });
}

function setupAutofillPortListeners(port) {
  port.onMessage.addListener((message) => {
    handleAutofillMessage(message, port);
  });

  port.onDisconnect.addListener(() => {
  });
}

async function setupContextMenus() {
  await contextMenus.removeAll();

  await contextMenus.create({
    id: "vela-autofill",
    title: "Auto-fill with VELA",
    contexts: ["all"]
  });

  await contextMenus.create({
    id: "vela-copy-username",
    title: "Copy Username",
    contexts: ["all"]
  });

  await contextMenus.create({
    id: "vela-copy-password",
    title: "Copy Password",
    contexts: ["all"]
  });

  await contextMenus.create({
    id: "vela-open-vault",
    title: "Open VELA Vault",
    contexts: ["all"]
  });

  contextMenus.onClicked.addListener((info, tab) => {
    handleContextMenuClick(info, tab);
  });
}

function handleContextMenuClick(info, tab) {
  switch (info.menuItemId) {
    case "vela-autofill":
      triggerAutofill(tab.id);
      break;
    case "vela-copy-username":
      copyUsername(tab.id);
      break;
    case "vela-copy-password":
      copyPassword(tab.id);
      break;
    case "vela-open-vault":
      openVault();
      break;
  }
}

function setupMessageListeners() {
  runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleExtensionMessage(message, sender, sendResponse);
    return true;
  });
}

function handleExtensionMessage(message, sender, sendResponse) {
  const { command, ...data } = message;

  switch (command) {
    case "collectPageDetails":
      handleCollectPageDetails(data, sender, sendResponse);
      break;
    case "fillForm":
      handleFillForm(data, sender, sendResponse);
      break;
    case "getLogins":
      handleGetLogins(data, sender, sendResponse);
      break;
    case "getAvailableLogins":
      handleGetAvailableLogins(data, sender, sendResponse);
      break;
    case "checkDesktopConnection":
      checkDesktopConnection(sendResponse);
      return true;
    case "saveCredentials":
      handleSaveCredentials(data, sender, sendResponse);
      break;
    case "passkeyList":
      handlePasskeyList(data, sender, sendResponse);
      return true;
    case "passkeyGet":
      handlePasskeyCeremony("passkeyGet", data, sender, sendResponse);
      return true;
    case "passkeyCreate":
      handlePasskeyCeremony("passkeyCreate", data, sender, sendResponse);
      return true;
    case "inCoreLoginCandidates":
      handleInCoreLoginCandidates(sendResponse);
      return true;
    case "inCoreLogin":
      handleInCoreLogin(data, sendResponse);
      return true;
    case "openVault":
    case "openSettings":
      handleOpenDesktop(command, sendResponse);
      return true;
    case "triggerAutofillWithLogin":
      handleTriggerAutofillWithLogin(data, sender, sendResponse);
      return true;
    default:
      sendResponse({ success: false, error: "Unknown command" });
  }
}

function setupCommandListeners() {
  commands.onCommand.addListener((command, tab) => {
    switch (command) {
      case "_execute_action":
        openPopup();
        break;
    }
  });
}

async function handleCollectPageDetails(data, sender, sendResponse) {
  try {
    const tabId = sender.tab?.id || activeTabId;
    if (!tabId) {
      sendResponse({ success: false, error: "No tab found" });
      return;
    }

    sendResponse({ success: true });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

async function handleFillForm(data, sender, sendResponse) {
  try {
    const { fillScript, url } = data;
    const tabId = sender.tab?.id || activeTabId;

    if (tabId) {
      try {
        const response = await tabs.sendMessage(tabId, {
          command: "performFill",
          fillScript
        });
        sendResponse(response || { success: false });
      } catch {
        sendResponse({ success: false });
      }
    } else {
      sendResponse({ success: false, error: "No tab found" });
    }
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

async function handleGetLogins(data, sender, sendResponse) {
  try {
    const auth = await authorizeCredentialRequest(data, sender);
    if (!auth.ok) {
      sendResponse({ success: false, error: auth.error, logins: [] });
      return;
    }
    const { url } = data;
    const domain = getHttpDomain(url);
    if (!domain) {
      sendResponse({ success: false, ignored: true, logins: [] });
      return;
    }
    // Honor the caller's userInitiated flag (default passive). A passive
    // request (page-load / form-detection dropdown) must NOT receive
    // passwords — the desktop returns metadata-only until the user explicitly
    // picks an entry, at which point the content script re-requests with
    // userInitiated=true. Mirrors handleGetAvailableLogins.
    const userInitiated = data.userInitiated === true;
    const response = await requestLogins(domain, userInitiated);

    if (response && response.success && Array.isArray(response.logins)) {
      const logins = await Promise.all(
        response.logins.map(async item => ({
          ...item,
          totp: await computeLoginTOTP(item)
        }))
      );
      console.log("[VELA] handleGetLogins found logins:", logins.length);
      sendResponse({ success: true, logins });
    } else if (response && response.requires_biometric) {
      sendResponse({ success: false, requires_biometric: true, logins: [] });
    } else {
      sendResponse({ success: false, logins: [] });
    }
  } catch (error) {
    console.log("[VELA] handleGetLogins error:", error.message);
    sendResponse({ success: false, error: error.message, logins: [] });
  }
}

async function handleGetAvailableLogins(data, sender, sendResponse) {
  try {
    const auth = await authorizeCredentialRequest(data, sender);
    if (!auth.ok) {
      sendResponse({ success: false, error: auth.error, logins: [] });
      return;
    }
    const { url } = data;
    const userInitiated = data.userInitiated === true;
    const domain = getHttpDomain(url);
    if (!domain) {
      sendResponse({ success: false, ignored: true, logins: [] });
      return;
    }
    const response = await requestLogins(domain, userInitiated);

    if (response && response.success && Array.isArray(response.logins)) {
      const logins = await Promise.all(
        response.logins.map(async item => ({
          ...item,
          totp: await computeLoginTOTP(item)
        }))
      );
      console.log("[VELA] Found logins:", logins.length);
      sendResponse({ success: true, logins });
    } else if (response && response.requires_biometric) {
      sendResponse({ success: false, requires_biometric: true, logins: [] });
    } else {
      sendResponse({ success: false, logins: [] });
    }
  } catch (error) {
    console.log("[VELA] handleGetAvailableLogins error:", error.message);
    sendResponse({ success: false, error: error.message, logins: [] });
  }
}

function getHttpDomain(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    return parsed.hostname.replace(/^www\./, "");
  } catch (_) {
    return null;
  }
}

// ── Passkeys ─────────────────────────────────────────────────────────────────
//
// A ceremony waits for the desktop to put a confirmation in front of a person,
// so it gets a far longer budget than an ordinary request.
const PASSKEY_CEREMONY_TIMEOUT_MS = 121000;

/**
 * Is this sender allowed to ask about this relying party?
 *
 * The shim checks the RP ID against the page's own location, but the shim runs
 * in the page's world and anything there is under the page's control. This is
 * the check that counts, because `sender.url` and `sender.frameId` come from
 * the browser rather than from the content it is rendering.
 *
 * Top frame only. Cross-origin iframe WebAuthn exists and is gated on a
 * permissions policy the extension cannot read from here; refusing is the
 * conservative answer, and it matches how `authorizeCredentialRequest` already
 * treats credential requests from subframes.
 */
async function authorizePasskeyRequest(rpId, sender) {
  if (typeof rpId !== "string" || !rpId) {
    return { ok: false, error: "Missing relying party" };
  }
  if (!sender?.tab) {
    return { ok: false, error: "Passkey requests must come from a page" };
  }
  if (sender.frameId !== undefined && sender.frameId !== 0) {
    return { ok: false, error: "Passkey requests must come from the top frame" };
  }

  const senderDomain = getHttpDomain(sender.url || "");
  if (!senderDomain) {
    return { ok: false, error: "Unsupported URL" };
  }

  const wanted = rpId.replace(/^www\./, "").toLowerCase();
  const host = senderDomain.toLowerCase();
  // The relying party ID must be the sender's own domain or a parent of it —
  // the same rule the browser applies, restated where it cannot be spoofed.
  if (host !== wanted && !host.endsWith(`.${wanted}`)) {
    return { ok: false, error: "Relying party does not match the requesting page" };
  }

  const active = await getActiveTab();
  if (!active || active.id !== sender.tab.id) {
    return { ok: false, error: "Sender tab is not active" };
  }

  return { ok: true };
}

async function handlePasskeyList(data, sender, sendResponse) {
  try {
    const auth = await authorizePasskeyRequest(data?.rp_id, sender);
    if (!auth.ok) {
      sendResponse({ success: false, credentials: [], error: auth.error });
      return;
    }
    const response = await sendNativeMessage({ action: "passkeyList", rp_id: data.rp_id });
    sendResponse(response || { success: false, credentials: [] });
  } catch (error) {
    sendResponse({ success: false, credentials: [], error: error.message });
  }
}

async function handlePasskeyCeremony(action, data, sender, sendResponse) {
  try {
    const auth = await authorizePasskeyRequest(data?.rp_id, sender);
    if (!auth.ok) {
      sendResponse({ success: false, error: auth.error });
      return;
    }
    const response = await sendNativeMessage(
      { action, ...data },
      PASSKEY_CEREMONY_TIMEOUT_MS
    );
    sendResponse(response || { success: false, error: "No response from VELA Desktop" });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

// ── In-core login (M9a) ──────────────────────────────────────────────────────
//
// The autofill path puts a password into the page. This one never has the
// password at all: the desktop signs in over its own connection and sends back
// the cookies the site issued, which get installed here.
//
// Two consequences worth being explicit about. The extension needs the
// `cookies` permission and host access to write them, which is a real increase
// in what it can do — so both are *optional* permissions, requested at the
// moment of use and for one origin, rather than held over every site forever.
// And the session that lands in the browser is a genuine credential for that
// site: better than a password because it expires and can be revoked, but not
// nothing. `residualNote` from the desktop says which of those two cases the
// site is in, and the popup shows it.

/// Only ever act on the tab the user is looking at.
async function resolveActiveHttpTab() {
  const active = await getActiveTab();
  if (!active?.id) {
    return { ok: false, error: "No active tab" };
  }
  const domain = getHttpDomain(active.url || "");
  if (!domain) {
    return { ok: false, error: "This page is not a website VELA can sign in to" };
  }
  return { ok: true, tab: active, domain };
}

async function handleInCoreLoginCandidates(sendResponse) {
  try {
    const active = await resolveActiveHttpTab();
    if (!active.ok) {
      sendResponse({ success: false, candidates: [], error: active.error });
      return;
    }
    const response = await sendNativeMessage({
      action: "inCoreLoginCandidates",
      url: active.tab.url
    });
    sendResponse(response || { success: false, candidates: [] });
  } catch (error) {
    sendResponse({ success: false, candidates: [], error: error.message });
  }
}

async function handleInCoreLogin(data, sendResponse) {
  try {
    const active = await resolveActiveHttpTab();
    if (!active.ok) {
      sendResponse({ success: false, error: active.error });
      return;
    }
    if (!data?.itemId) {
      sendResponse({ success: false, error: "No login chosen" });
      return;
    }

    const origin = new URL(active.tab.url).origin + "/*";
    const granted = await browser.permissions.contains({
      permissions: ["cookies"],
      origins: [origin]
    });
    if (!granted) {
      // Requesting from here would fail anyway: `permissions.request` needs a
      // user gesture, and a service worker has none. The popup asks.
      sendResponse({
        success: false,
        needsPermission: true,
        origin,
        error: "VELA needs permission to set cookies for this site"
      });
      return;
    }

    const response = await sendNativeMessage(
      { action: "inCoreLogin", itemId: data.itemId, url: active.tab.url },
      PASSKEY_CEREMONY_TIMEOUT_MS
    );
    if (!response?.success) {
      sendResponse(response || { success: false, error: "No response from VELA Desktop" });
      return;
    }

    const installed = await installSessionCookies(response.cookies || [], active.tab.url);
    if (installed === 0) {
      sendResponse({
        success: false,
        error: "The site did not issue a session VELA could install"
      });
      return;
    }

    // Navigate only within the site we just signed in to. The desktop already
    // refuses to follow a redirect off the site, so a landing URL elsewhere
    // means something is wrong, not that the user should be sent there.
    let target = active.tab.url;
    if (response.landingUrl && getHttpDomain(response.landingUrl) === active.domain) {
      target = response.landingUrl;
    }
    await tabs.update(active.tab.id, { url: target });

    sendResponse({
      success: true,
      cookiesInstalled: installed,
      looksAuthenticated: Boolean(response.looksAuthenticated),
      siteMode: response.siteMode,
      residualNote: response.residualNote,
      usedSecondFactor: Boolean(response.usedSecondFactor)
    });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

/**
 * Install the session the desktop brought back.
 *
 * Every cookie is written relative to the *tab's* origin rather than to
 * whatever domain the response named. That matters: it means the browser's own
 * rules — a cookie cannot be set for a domain the URL is not under, and never
 * for a public suffix — are applied to the origin the user is actually on. A
 * response asking us to plant a cookie on another site fails the domain check
 * below and never reaches `cookies.set`.
 */
async function installSessionCookies(cookies, tabUrl) {
  const tab = new URL(tabUrl);
  const host = tab.hostname.toLowerCase();
  let installed = 0;

  for (const cookie of cookies) {
    if (!cookie?.name) {
      continue;
    }
    const domain = String(cookie.domain || "").toLowerCase();
    const scoped = cookie.host_only
      ? host === domain
      : host === domain || host.endsWith(`.${domain}`);
    if (!scoped) {
      console.warn(`VELA: refused a session cookie scoped to ${domain}`);
      continue;
    }

    const details = {
      url: `${tab.protocol}//${host}${cookie.path || "/"}`,
      name: cookie.name,
      value: cookie.value ?? "",
      path: cookie.path || "/",
      secure: Boolean(cookie.secure),
      httpOnly: Boolean(cookie.http_only),
      sameSite: mapSameSite(cookie.same_site)
    };
    // Omitting `domain` is what makes a cookie host-only; sending the host
    // explicitly would widen it to every subdomain.
    if (!cookie.host_only) {
      details.domain = domain;
    }
    if (typeof cookie.expires_at === "number") {
      details.expirationDate = cookie.expires_at;
    }

    try {
      await browser.cookies.set(details);
      installed += 1;
    } catch (error) {
      console.warn(`VELA: could not install cookie ${cookie.name}: ${error.message}`);
    }
  }

  return installed;
}

function mapSameSite(value) {
  switch (String(value || "").toLowerCase()) {
    case "strict":
      return "strict";
    case "lax":
      return "lax";
    // The site said `SameSite=None`, which Chrome spells differently.
    case "none":
      return "no_restriction";
    default:
      return "unspecified";
  }
}

async function authorizeCredentialRequest(data, sender) {
  const requestedUrl = data?.url || "";
  const requestedDomain = getHttpDomain(requestedUrl);
  if (!requestedDomain) {
    return { ok: false, error: "Unsupported URL" };
  }

  const active = await getActiveTab();
  if (!active || !active.id || !active.url) {
    return { ok: false, error: "No active tab" };
  }

  if (!sameHttpDomain(active.url, requestedUrl)) {
    return { ok: false, error: "Requested URL does not match active tab" };
  }

  if (sender?.tab) {
    if (sender.tab.id !== active.id) {
      return { ok: false, error: "Sender tab is not active" };
    }
    if (sender.frameId !== undefined && sender.frameId !== 0) {
      return { ok: false, error: "Credential requests must come from the top frame" };
    }
    if (sender.url && !sameHttpDomain(sender.url, requestedUrl)) {
      return { ok: false, error: "Sender URL does not match requested URL" };
    }
    return { ok: true, tabId: active.id };
  }

  const extensionOrigin = runtime.getURL("");
  if (!sender?.url?.startsWith(extensionOrigin)) {
    return { ok: false, error: "Credential requests require extension UI or top-frame content" };
  }
  return { ok: true, tabId: active.id };
}

function sameHttpDomain(left, right) {
  const leftDomain = getHttpDomain(left);
  const rightDomain = getHttpDomain(right);
  return !!leftDomain && leftDomain === rightDomain;
}

async function getActiveTab() {
  try {
    const queryTabs = await tabs.query({ active: true, currentWindow: true });
    return queryTabs && queryTabs.length ? queryTabs[0] : null;
  } catch {
    return null;
  }
}

function requestLogins(domain, userInitiated) {
  const key = `${domain}:${userInitiated ? "explicit" : "passive"}`;
  const now = Date.now();
  const cached = loginRequestCache.get(key);
  if (cached && now - cached.startedAt < LOGIN_REQUEST_DEDUP_MS) {
    return cached.promise;
  }

  const promise = sendNativeMessage({
    action: userInitiated ? "getLogins" : "getAvailableLogins",
    url: domain,
    userInitiated
  }).finally(() => {
    const current = loginRequestCache.get(key);
    if (current && current.promise === promise) {
      setTimeout(() => {
        const latest = loginRequestCache.get(key);
        if (latest && latest.promise === promise) {
          loginRequestCache.delete(key);
        }
      }, LOGIN_REQUEST_DEDUP_MS);
    }
  });

  loginRequestCache.set(key, { startedAt: now, promise });
  return promise;
}

// `nativeMessage` / `getNativeMessage` used to live here: they forwarded an
// arbitrary caller-supplied payload straight to the native messaging host,
// skipping `authorizeCredentialRequest` that every other credential path goes
// through — so anything able to reach the extension's message API could ask the
// desktop app for whatever those handlers would carry (audit E-1). Nothing in
// this extension sent them. If a future feature needs a native call, give it a
// named command that authorizes like `handleGetLogins` does, rather than a
// general-purpose passthrough.

async function handleOpenDesktop(command, sendResponse) {
  try {
    const response = await sendNativeMessage({ action: command });
    sendResponse(response || { success: false });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

async function handleTriggerAutofillWithLogin(data, sender, sendResponse) {
  const { login } = data;
  if (!login) { sendResponse({ success: false }); return; }

  const active = await getActiveTab();
  const tabId = sender?.tab?.id || active?.id;

  if (!tabId) { sendResponse({ success: false, error: "No tab found" }); return; }
  if (active?.url && login.url && !sameHttpDomain(active.url, login.url)) {
    sendResponse({ success: false, error: "Login does not match active tab" });
    return;
  }
  if (sender?.tab && sender.frameId !== undefined && sender.frameId !== 0) {
    sendResponse({ success: false, error: "Autofill must be triggered from the top frame" });
    return;
  }

  try {
    const response = await tabs.sendMessage(tabId, { command: "fillWithLogin", login });
    sendResponse(response || { success: true });
  } catch {
    sendResponse({ success: false });
  }
}

async function handleSaveCredentials(data, sender, sendResponse) {
  try {
    // Content-script (page-originated) saves must be authorized against the
    // active tab URL, exactly like getLogins — otherwise a malicious page can
    // pollute the vault or overwrite an entry's URL (phishing / credential
    // confusion). Saves originating from the popup/extension UI (no
    // sender.tab) are user-driven and need no origin check.
    if (sender && sender.tab) {
      const auth = await authorizeCredentialRequest(data, sender);
      if (!auth.ok) {
        sendResponse({ success: false, error: auth.error });
        return;
      }
    }
    const response = await sendNativeMessage({ action: "saveCredentials", ...data });
    if (response && response.success) {
      sendResponse({ success: true });
    } else {
      sendResponse(response || { success: false });
    }
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

function checkDesktopConnection(sendResponse) {
  // Trust a recent successful ping for a few seconds (avoids a native
  // round-trip on rapid successive calls), but never cache "connected"
  // indefinitely — the desktop may have been closed since the last check.
  if (
    desktopConnection &&
    desktopConnection.disconnected === false &&
    desktopConnection.checkedAt &&
    Date.now() - desktopConnection.checkedAt < 5000
  ) {
    sendResponse({ connected: true });
    return true;
  }

  console.log("[VELA] Checking desktop connection...");

  let resultReceived = false;

  const checkResult = (response) => {
    if (resultReceived) return;

    const connected = isConnectedResponse(response);
    console.log("[VELA] Connection check response:", JSON.stringify(response), "connected:", connected);

    if (connected) {
      resultReceived = true;
      desktopConnection = { disconnected: false, checkedAt: Date.now() };
      sendResponse({ connected: true });
    }
  };

  sendNativeMessage({ action: "ping" }).then(checkResult);

  setTimeout(() => {
    if (!resultReceived) {
      resultReceived = true;
      console.log("[VELA] Connection check timeout, assuming disconnected");
      desktopConnection = { disconnected: true };
      sendResponse({ connected: false });
    }
  }, 3000);

  return true;
}

function isConnectedResponse(response) {
  if (!response) return false;
  if (response.success === true) return true;
  if (response.msg_type === "Pong") return true;
  if (response.connected === true) return true;
  return false;
}

function sendNativeMessage(message, timeoutMs = 10000) {
  console.log("[VELA] Trying native messaging...");
  return new Promise((resolve) => {
    const timeoutId = setTimeout(() => {
      console.log("[VELA] Native messaging timeout");
      resolve({ success: false, error: "Native messaging timeout" });
    }, timeoutMs);

    runtime.sendNativeMessage(NATIVEMessaging_PORT, message)
      .then((response) => {
        clearTimeout(timeoutId);
        console.log("[VELA] Native messaging response received");
        resolve(response || { success: false });
      })
      .catch((error) => {
        clearTimeout(timeoutId);
        console.log("[VELA] Native messaging error:", error.message);
        resolve({ success: false, error: error.message });
      });
  });
}

function handleAutofillMessage(message, port) {
  const { command, ...data } = message;

  switch (command) {
    case "collectPageDetails":
      port.postMessage({ command: "collectPageDetailsResponse", ...data });
      break;
    case "fillForm":
      port.postMessage({ command: "fillFormResponse", ...data });
      break;
  }
}

async function triggerAutofill(tabId) {
  try {
    await tabs.sendMessage(tabId, { command: "triggerAutofill" });
  } catch {}
}

async function copyUsername(tabId) {
  try {
    await tabs.sendMessage(tabId, { command: "copyUsername" });
  } catch {}
}

async function copyPassword(tabId) {
  try {
    await tabs.sendMessage(tabId, { command: "copyPassword" });
  } catch {}
}

async function openVault() {
  try {
    await action.openPopup();
  } catch {
    await tabs.create({ url: "popup/popup.html" });
  }
}

async function openPopup() {
  try {
    await action.openPopup();
  } catch {
    await tabs.create({ url: "popup/popup.html" });
  }
}

runtime.onInstalled.addListener(() => {
  init();
});

runtime.onStartup.addListener(() => {
  init();
});

init();
