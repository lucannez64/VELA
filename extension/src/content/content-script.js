(function () {
  "use strict";

  const BITWARDEN_AUTOFILL_INIT = "bitwardenAutofillInit";

  if (globalThis[BITWARDEN_AUTOFILL_INIT]) {
    return;
  }

  const VelaAutofill = globalThis.VelaAutofill || {};
  const {
    AutoFillConstants,
    CreditCardAutoFillConstants,
    IdentityAutoFillConstants,
    SubmitLoginButtonNames,
    SubmitChangePasswordButtonNames,
    fieldIsFuzzyMatch,
    isFieldMatch,
    nodeIsElement,
    elementIsInputElement,
    elementIsSelectElement,
    elementIsTextAreaElement,
    elementIsFormElement,
    elementIsSpanElement,
    elementIsLabelElement,
    nodeIsFormElement,
    getPropertyOrAttribute,
    getAttributeBoolean,
    getSubmitButtonKeywordsSet,
    throttle,
    debounce,
    sendExtensionMessage,
    generateRandomCustomElementName,
    siteKey,
    hostRisk
  } = VelaAutofill;

  const MAX_DEEP_QUERY_RECURSION_DEPTH = 15;
  const AUTOFILL_ATTRIBUTES = {
    NAME: "name",
    CLASS: "class",
    ID: "id",
    TITLE: "title",
    TYPE: "type",
    ACTION: "action",
    METHOD: "method",
    AUTOCOMPLETE: "autocomplete",
    PLACEHOLDER: "placeholder",
    DISABLED: "disabled",
    READONLY: "readonly",
    TABINDEX: "tabindex",
    CHECKED: "checked",
    DATA_LABEL: "data-label",
    ARIA_LABEL: "aria-label",
    ARIA_HIDDEN: "aria-hidden",
    ARIA_DISABLED: "aria-disabled",
    ARIA_HASPOPUP: "aria-haspopup",
    AUTOCOMPLETE_TYPE: "x-autocomplete",
    X_AUTOCOMPLETE_TYPE: "x-webkit-autocomplete",
    DATA_STRIPE: "data-stripe",
    REL: "rel"
  };

  const ignoredInputTypes = new Set([
    "hidden", "submit", "reset", "button", "image", "file",
    "search", "url", "date", "time", "datetime", "datetime-local",
    "week", "color", "range"
  ]);

  const nonInputFormFieldTags = new Set(["textarea", "select"]);
  const ignoredTreeWalkerNodes = new Set([
    "svg", "script", "noscript", "head", "style", "link", "meta",
    "title", "base", "img", "picture", "video", "audio", "object",
    "source", "track", "param", "map", "area"
  ]);

  let pageDetails = null;
  let mutationObserver = null;
  let observedShadowRoots = new WeakSet();
  let lastLocationHref = globalThis.location.href;

  let velaActiveField = null;
  let velaDropdownEl = null;
  let velaTotpTimer = null;
  let velaFieldIconEl = null;
  let velaSaveBarEl = null;
  let velaCurrentLogins = null;
  let velaRequiresBiometric = false;
  // Cards are fetched only when the user clicks the shield on a payment field
  // (never on passive focus), so this holds secrets only for the dropdown that
  // is already on screen.
  let velaCurrentCards = null;
  let velaLoginRequestPromise = null;
  let velaLoginRequestKey = "";
  let velaCapturedCredentials = null;
  let velaGenModal = null;
  let velaSaveModal = null;
  let velaGenIconEl = null;
  let velaGenOptions = { length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true };
  // Per-site autofill preferences, read from `storage.local`. Defaults allow
  // the ordinary click-to-fill behavior.
  let velaSiteSettings = { autoFillOnLoad: false, neverAutofill: false };
  // Lookalike/homograph assessment for this document's hostname.
  let velaHostRisk = { level: "none", reasons: [], unicode: "" };
  let velaSelectedIndex = -1;
  let velaHoveredField = null;
  // Credentials typed into password fields but not yet offered to the user.
  // Lets us still capture SPA logins that never fire a `submit` event.
  let velaPendingCreds = null;
  // Key of the credentials the capture bar is (or was just) showing, so the
  // submit path and the SPA heuristics do not prompt twice for one login.
  let velaPromptedCredsKey = "";

  function getBrowserAPI() {
    if (typeof browser !== "undefined" && browser.runtime) return browser;
    if (typeof chrome !== "undefined" && chrome.runtime) return chrome;
    return null;
  }

  function init() {
    setupMutationObserver();
    setupMessageListeners();
    setupDisconnectAction();
    initInlineAutofill();
    velaLoadHostRisk();
    velaLoadSiteSettings().then(() => velaAutoFillOnLoad());
    velaStartTotpAutofillWatch();
  }

  function setupMutationObserver() {
    if (mutationObserver) return;
    mutationObserver = new MutationObserver(handleMutations);
    mutationObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: Object.values(AUTOFILL_ATTRIBUTES),
      childList: true,
      subtree: true
    });
  }

  function handleMutations(mutations) {
    if (lastLocationHref !== globalThis.location.href) {
      lastLocationHref = globalThis.location.href;
      pageDetails = null;
      velaCurrentLogins = null;
      velaCurrentCards = null;
      velaHideDropdown();
      velaLoadHostRisk();
      velaLoadSiteSettings();
    }
  }

  function setupMessageListeners() {
    const api = getBrowserAPI();
    if (!api) return;

    const handleMessage = (message, sender, sendResponse) => {
      const { command } = message;
      switch (command) {
        case "triggerAutofill":
          triggerAutofill();
          sendResponse({ success: true });
          break;
        case "collectPageDetails":
          collectPageDetails().then((details) => sendResponse({ success: true, details }));
          return true;
        case "performFill":
          performFill(message.fillScript);
          sendResponse({ success: true });
          break;
        case "fillForm":
          handleFillForm(message);
          sendResponse({ success: true });
          break;
        case "fillVaultItem": {
          if (message.url !== location.href) { sendResponse({success:false, error:"The page changed."}); break; }
          const kind = message.itemType === "card" ? velaIsCardField : velaIsIdentityField;
          const fields = Array.from(document.querySelectorAll("input,select,textarea")).filter(el => kind(el) && velaVisibleField(el));
          const anchor = fields.includes(document.activeElement) ? document.activeElement : fields[0];
          const count = anchor ? (message.itemType === "card" ? velaFillCard(message.item, anchor) : velaFillIdentity(message.item, anchor, message.addressId)) : 0;
          sendResponse({success:count > 0, error:count ? undefined : "No matching form fields on this page."});
          break;
        }
        case "fillWithLogin":
          fillWithLogin(message.login);
          sendResponse({ success: true });
          break;
        case "getLogins":
          getLoginsForPage(message.url).then((logins) => sendResponse({ success: true, logins }));
          return true;
        case "copyUsername":
          copyUsername();
          sendResponse({ success: true });
          break;
        case "copyPassword":
          copyPassword();
          sendResponse({ success: true });
          break;
        case "showSaveDialog":
          velaShowSaveDialog(message.username || "", message.password || "");
          sendResponse({ success: true });
          break;
        case "writeLocalSession":
          // A token-session site (Firebase Auth — monkeytype): the login ran
          // in VELA's disposable browser, which captured the site's storage.
          // Replicate the keys into THIS page's own origin so the session
          // carries over. Keys are written to BOTH storages: the auth SDK
          // decides on load which one it reads (monkeytype uses sessionStorage
          // when "remember me" is off, localStorage/IndexedDB when on), and the
          // captured keys carry whichever the disposable session used.
          if (message.entries && typeof message.entries === "object") {
            let written = 0;
            for (const [key, value] of Object.entries(message.entries)) {
              try {
                localStorage.setItem(key, String(value));
                sessionStorage.setItem(key, String(value));
                written += 1;
              } catch (e) {}
            }
            console.log(`[VELA] Wrote ${written} keys to localStorage+sessionStorage at ${location.origin}`);
          }
          sendResponse({ success: true });
          break;
        case "writeStoredDb":
          // Replicate an auth SDK's IndexedDB records (Firebase's
          // indexedDBLocalPersistence — monkeytype with "remember me") into
          // THIS page's own IndexedDB. Async: IndexedDB writes are async.
          // The store must be created if the SDK hasn't initialised it yet in
          // this tab — `indexedDB.open` on a missing database fires onsuccess
          // with one that has no object store, and skipping the write would
          // silently drop the session.
          if (message.records && typeof message.records === "object") {
            const records = message.records;
            (async () => {
              const write = () => new Promise((resolve) => {
                const req = indexedDB.open("firebaseLocalStorageDb", 1);
                req.onupgradeneeded = () => {
                  const db = req.result;
                  if (!db.objectStoreNames.contains("firebaseLocalStorage")) {
                    db.createObjectStore("firebaseLocalStorage", { keyPath: "fbase_key" });
                  }
                };
                req.onerror = () => resolve();
                req.onsuccess = () => {
                  const db = req.result;
                  try {
                    const tx = db.transaction("firebaseLocalStorage", "readwrite");
                    const store = tx.objectStore("firebaseLocalStorage");
                    for (const [key, value] of Object.entries(records)) {
                      store.put({ fbase_key: key, value });
                    }
                    tx.oncomplete = () => { db.close(); resolve(); };
                    tx.onerror = () => { db.close(); resolve(); };
                  } catch (e) {
                    db.close();
                    resolve();
                  }
                };
              });
              try {
                await write();
                console.log(`[VELA] Wrote ${Object.keys(records).length} IndexedDB records at ${location.origin}`);
              } catch (e) {}
            })();
          }
          sendResponse({ success: true });
          break;
        case "siteSettingsChanged":
          // The popup changed this site's preferences; drop any open inline
          // UI and re-read them.
          velaLoadSiteSettings().then(() => {
            velaHideDropdown();
            velaRemoveFieldIcon();
          });
          sendResponse({ success: true });
          break;
        case "watchLoginArtifacts":
          // Tier A recipe login: the human solves the site's captcha in this
          // tab, and we lift the resulting token out of the DOM. If it is
          // already there, report it now; otherwise poll for it to appear
          // (the solve writes it into the response textarea), then tell the
          // background to finish the sign-in.
          startCaptchaWatch();
          sendResponse({ success: true });
          break;
      }
    };

    api.runtime.onMessage.addListener(handleMessage);
  }

  // ── Tier A captcha harvest ──────────────────────────────────────────────
  //
  // A recipe login asks the browser to mint the one thing only a browser can:
  // a solved captcha. The token is written into a response textarea when the
  // widget completes. We read it out and hand it to the background, which
  // carries it to the core. It is single-use and short-lived, so the watch
  // gives up after the token's typical lifetime.

  const CAPTCHA_WATCH_TIMEOUT_MS = 180000;

  function readCaptchaToken() {
    const selectors = [
      '[name="h-captcha-response"]',
      '[name="g-recaptcha-response"]',
      '[name="cf-turnstile-response"]',
      'textarea.h-captcha-response',
      'textarea.g-recaptcha-response'
    ];
    for (const selector of selectors) {
      try {
        const element = document.querySelector(selector);
        if (element && element.value && element.value.trim()) {
          return element.value.trim();
        }
      } catch (e) {}
    }
    // Some sites keep it in an input whose name merely suggests what it is.
    try {
      const element = document.querySelector(
        'input[name*="captcha" i], textarea[name*="captcha" i]'
      );
      if (element && element.value && element.value.trim()) {
        return element.value.trim();
      }
    } catch (e) {}
    return null;
  }

  function startCaptchaWatch() {
    const token = readCaptchaToken();
    if (token) {
      sendExtensionMessage("loginArtifactsReady", { captchaToken: token });
      return;
    }
    const started = Date.now();
    const timer = setInterval(() => {
      const current = readCaptchaToken();
      if (current) {
        clearInterval(timer);
        sendExtensionMessage("loginArtifactsReady", { captchaToken: current });
      } else if (Date.now() - started > CAPTCHA_WATCH_TIMEOUT_MS) {
        clearInterval(timer);
        sendExtensionMessage("loginArtifactsReady", { captchaToken: null });
      }
    }, 300);
  }

  function setupDisconnectAction() {
    try {
      const api = getBrowserAPI();
      if (!api) return;
      const port = api.runtime.connect({ name: "injected-script" });
      port.onDisconnect.addListener(() => destroy());
    } catch (e) {}
  }

  function destroy() {
    if (mutationObserver) {
      mutationObserver.disconnect();
      mutationObserver = null;
    }
    observedShadowRoots = new WeakSet();
    pageDetails = null;
    velaHideDropdown();
    velaHideSaveBar();
  }

  globalThis[BITWARDEN_AUTOFILL_INIT] = { destroy };

  // =========================================================
  // CORE AUTOFILL FUNCTIONS
  // =========================================================

  async function triggerAutofill() {
    const details = await collectPageDetails();
    if (!details || !details.fields || !details.fields.length) return;
    const logins = await getLoginsForPage(details.url);
    if (!logins || !logins.length) return;
    if (logins.length === 1) {
      const fillScript = generateFillScript(details, logins[0]);
      if (fillScript) {
        performFill(fillScript);
        velaRecordTotpPending(logins[0], details);
      }
    } else {
      velaShowAccountPickerModal(logins);
    }
  }

  async function fillWithLogin(login) {
    const details = await collectPageDetails();
    if (!details) return;
    const fillScript = generateFillScript(details, login);
    if (fillScript) {
      performFill(fillScript);
      velaRecordTotpPending(login, details);
    }
  }

  // Park "this tab just filled login X" so the site's next page (the OTP step)
  // can offer to fill a code even though this script's context is gone by
  // then. Only for logins that actually carry an authenticator seed; the code
  // itself is fetched fresh from the desktop when it is needed.
  function velaRecordTotpPending(login, details) {
    if (!login || !login.id || !login.totp) return;
    sendExtensionMessage("setTotpPending", {
      loginId: login.id,
      url: (details && details.url) || globalThis.location.href
    }).catch(() => {});
  }

  // ── Auto TOTP on the second step ─────────────────────────────────────────
  //
  // Explicit autofill puts the password (and, when the login form already
  // shows a code field, the code) into the page. A multi-step site then
  // navigates to a page that asks only for the one-time code. If this tab just
  // filled a login with an authenticator seed, fetch a fresh code from the
  // desktop and fill it — but only on a page with a code field and no password
  // field, so a password form is never mistaken for the OTP step.

  let velaTotpAutofillDone = false;
  let velaTotpWatchObserver = null;
  let velaTotpWatchTimer = null;

  async function velaStartTotpAutofillWatch() {
    // Only watch pages where this tab actually just filled a login with an
    // authenticator seed. Most pages have no pending context, and they should
    // not pay for a mutation observer.
    let pending = null;
    try {
      pending = await sendExtensionMessage("getTotpPending", { url: location.href });
    } catch (e) {}
    if (!pending || !pending.success) return;
    velaMaybeAutofillTotp(pending);
    try {
      if (!velaTotpWatchObserver && document.documentElement) {
        velaTotpWatchObserver = new MutationObserver(() => {
          if (velaTotpWatchTimer) return;
          velaTotpWatchTimer = setTimeout(() => {
            velaTotpWatchTimer = null;
            velaMaybeAutofillTotp();
          }, 400);
        });
        velaTotpWatchObserver.observe(document.documentElement, {
          childList: true,
          subtree: true
        });
      }
    } catch (e) {}
    // Stop watching after the plausible window: a stale tab should not keep
    // asking the desktop forever.
    setTimeout(velaStopTotpAutofillWatch, 120000);
  }

  function velaStopTotpAutofillWatch() {
    if (velaTotpWatchObserver) {
      try { velaTotpWatchObserver.disconnect(); } catch (e) {}
      velaTotpWatchObserver = null;
    }
    if (velaTotpWatchTimer) {
      clearTimeout(velaTotpWatchTimer);
      velaTotpWatchTimer = null;
    }
  }

  async function velaMaybeAutofillTotp(pendingArg) {
    if (velaTotpAutofillDone) return;
    try {
      const pending =
        pendingArg || (await sendExtensionMessage("getTotpPending", { url: location.href }));
      if (!pending || !pending.success || !pending.loginId) return;
      // Force a fresh scan: an OTP form can be client-rendered without the
      // document URL changing, and the cached details predate it.
      pageDetails = null;
      const details = await collectPageDetails();
      if (!details || !details.fields) return;
      const hasPassword = details.fields.some((f) => f.viewable && f.type === "password");
      if (hasPassword) return;
      const totpField = details.fields.find((f) => f.viewable && velaIsTotpField(f) && !f.value);
      if (!totpField) return;
      const code = await sendExtensionMessage("getTotpCode", {
        loginId: pending.loginId,
        url: location.href
      });
      if (!code || !code.success || !code.code) return;
      velaTotpAutofillDone = true;
      velaStopTotpAutofillWatch();
      performFill({ script: [{ opid: totpField.opid, action: "fill", value: code.code }] });
      sendExtensionMessage("clearTotpPending", {}).catch(() => {});
    } catch (e) {}
  }

  async function collectPageDetails() {
    if (pageDetails && lastLocationHref === globalThis.location.href) return pageDetails;
    const forms = await queryAutofillForms();
    const fields = await queryAutofillFields();
    pageDetails = {
      title: document.title,
      url: globalThis.location.href,
      documentUrl: document.location.href,
      forms: buildFormsData(forms),
      fields: buildFieldsData(fields),
      collectedTimestamp: Date.now()
    };
    lastLocationHref = globalThis.location.href;
    return pageDetails;
  }

  async function velaRequestLogins(userInitiated = false) {
    const key = `${location.href}:${userInitiated ? "explicit" : "passive"}`;
    if (velaLoginRequestPromise && velaLoginRequestKey === key) {
      return velaLoginRequestPromise;
    }

    velaLoginRequestKey = key;
    velaLoginRequestPromise = sendExtensionMessage("getAvailableLogins", {
      url: location.href,
      userInitiated
    }).then((resp) => ({
      logins: resp && resp.logins ? resp.logins : [],
      requiresBiometric: resp && resp.requires_biometric === true
    })).catch(() => ({
      logins: [],
      requiresBiometric: false
    })).finally(() => {
      setTimeout(() => {
        if (velaLoginRequestKey === key) {
          velaLoginRequestPromise = null;
          velaLoginRequestKey = "";
        }
      }, 1000);
    });

    return velaLoginRequestPromise;
  }

  // ── Per-site preferences and lookalike risk ──────────────────────────────

  function velaLoadHostRisk() {
    try {
      velaHostRisk = hostRisk(globalThis.location.hostname) || {
        level: "none",
        reasons: [],
        unicode: ""
      };
    } catch (e) {
      velaHostRisk = { level: "none", reasons: [], unicode: "" };
    }
  }

  async function velaLoadSiteSettings() {
    try {
      const api = getBrowserAPI();
      const key = siteKey(globalThis.location.href);
      if (!api || !api.storage?.local || !key) return;
      const data = await api.storage.local.get("velaSiteSettings");
      const all = (data && data.velaSiteSettings) || {};
      const site = all[key] || {};
      velaSiteSettings = {
        autoFillOnLoad: site.autoFillOnLoad === true,
        neverAutofill: site.neverAutofill === true
      };
    } catch (e) {
      velaSiteSettings = { autoFillOnLoad: false, neverAutofill: false };
    }
  }

  // Opt-in, per-site: fill the single matching login as soon as a password
  // field is present, with no click. Never on a lookalike domain, never when
  // the match is ambiguous, and never when the site is set to never autofill.
  async function velaAutoFillOnLoad() {
    if (!velaSiteSettings.autoFillOnLoad || velaSiteSettings.neverAutofill) return;
    if (velaHostRisk.level === "warn") return;
    try {
      const details = await collectPageDetails();
      if (!details || !details.fields) return;
      const passwordField = details.fields.find(
        (f) => f.viewable && f.type === "password" && !f.value
      );
      if (!passwordField) return;
      // Metadata first: auto-fill must be unambiguous.
      const passive = await velaRequestLogins(false);
      if (passive.requiresBiometric) return;
      if (!passive.logins || passive.logins.length !== 1) return;
      const full = await getLoginsForPage(globalThis.location.href, true);
      if (!full || full.length !== 1) return;
      if (passwordField.value) return;
      const fillScript = generateFillScript(details, full[0]);
      if (fillScript) {
        performFill(fillScript);
        velaRecordTotpPending(full[0], details);
      }
    } catch (e) {}
  }

  function velaPhishingWarningHtml() {
    if (velaHostRisk.level !== "warn") return "";
    const detail = "It mixes writing systems to imitate another site's address.";
    const shown =
      velaHostRisk.unicode && velaHostRisk.unicode !== globalThis.location.hostname
        ? ` It decodes to <strong>${velaEscapeHtml(velaHostRisk.unicode)}</strong>.`
        : "";
    return `
      <div class="vela-dd-warning" data-vela-ui="true">
        <span class="vela-dd-warning-icon">⚠</span>
        <span>This site's address may be impersonating another site. ${detail}${shown} VELA did not autofill.</span>
      </div>`;
  }

  function queryAutofillForms() {
    return new Promise((resolve) => {
      const forms = [];
      const elements = queryAllElements("form", (node) => nodeIsFormElement(node));
      for (let i = 0; i < elements.length; i++) {
        elements[i].opid = `__form__${i}`;
        forms.push(elements[i]);
      }
      resolve(forms);
    });
  }

  function queryAutofillFields() {
    return new Promise((resolve) => {
      const fields = [];
      let inputQuery = "input:not([data-bwignore]):not([data-vela-ui])";
      for (const type of ignoredInputTypes) {
        inputQuery += `:not([type="${type}"])`;
      }
      const queryString = `${inputQuery}, textarea:not([data-bwignore]):not([data-vela-ui]), select:not([data-bwignore]):not([data-vela-ui]), span[data-bwautofill]`;
      const elements = queryAllElements(queryString, (node) => isNodeFormFieldElement(node));
      for (let i = 0; i < elements.length; i++) {
        elements[i].opid = `__${i}`;
        fields.push(elements[i]);
      }
      resolve(fields);
    });
  }

  function queryAllElements(queryString, filterCallback, rootNode = document) {
    const results = [];
    try {
      const elements = rootNode.querySelectorAll(queryString);
      for (let i = 0; i < elements.length; i++) {
        if (!filterCallback || filterCallback(elements[i])) results.push(elements[i]);
      }
    } catch (e) {}
    const shadowRoots = recursivelyQueryShadowRoots(rootNode);
    for (const shadowRoot of shadowRoots) {
      try {
        const elements = shadowRoot.querySelectorAll(queryString);
        for (let i = 0; i < elements.length; i++) {
          if (!filterCallback || filterCallback(elements[i])) results.push(elements[i]);
        }
      } catch (e) {}
    }
    return results;
  }

  function recursivelyQueryShadowRoots(root, depth = 0) {
    if (depth >= MAX_DEEP_QUERY_RECURSION_DEPTH) return [];
    const shadowRoots = [];
    const potentialShadowRoots = root.querySelectorAll(":defined");
    for (let i = 0; i < potentialShadowRoots.length; i++) {
      const shadowRoot = getShadowRoot(potentialShadowRoots[i]);
      if (shadowRoot) {
        shadowRoots.push(shadowRoot);
        shadowRoots.push(...recursivelyQueryShadowRoots(shadowRoot, depth + 1));
      }
    }
    return shadowRoots;
  }

  function getShadowRoot(node) {
    if (!nodeIsElement(node)) return null;
    if (node.shadowRoot) return node.shadowRoot;
    if (typeof chrome !== "undefined" && chrome.dom?.openOrClosedShadowRoot) {
      try { return chrome.dom.openOrClosedShadowRoot(node); } catch (e) { return null; }
    }
    return null;
  }

  function isNodeFormFieldElement(node) {
    if (!nodeIsElement(node)) return false;
    const tagName = node.tagName.toLowerCase();
    if (tagName === "span" && node.hasAttribute("data-bwautofill")) return true;
    if (node.hasAttribute("data-bwignore") || node.hasAttribute("data-vela-ui")) return false;
    if (tagName === "input") {
      const type = (node.type || "text").toLowerCase();
      return !ignoredInputTypes.has(type);
    }
    return nonInputFormFieldTags.has(tagName);
  }

  function buildFormsData(formElements) {
    const formsData = {};
    for (let i = 0; i < formElements.length; i++) {
      const form = formElements[i];
      const opid = form.opid;
      formsData[opid] = {
        opid,
        htmlAction: getFormActionAttribute(form),
        htmlName: getPropertyOrAttribute(form, AUTOFILL_ATTRIBUTES.NAME),
        htmlClass: getPropertyOrAttribute(form, AUTOFILL_ATTRIBUTES.CLASS),
        htmlID: getPropertyOrAttribute(form, AUTOFILL_ATTRIBUTES.ID),
        htmlMethod: getPropertyOrAttribute(form, AUTOFILL_ATTRIBUTES.METHOD)
      };
    }
    return formsData;
  }

  function getFormActionAttribute(element) {
    const action = getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.ACTION);
    if (action === null) return null;
    try { return new URL(action, globalThis.location.href).href; } catch (e) { return action; }
  }

  function buildFieldsData(fieldElements) {
    const fieldsData = [];
    for (let i = 0; i < fieldElements.length; i++) {
      const field = buildFieldData(fieldElements[i], i);
      if (field) fieldsData.push(field);
    }
    return fieldsData;
  }

  function buildFieldData(element, index) {
    if (element.closest("button[type='submit']")) return null;
    const opid = `__${index}`;
    element.opid = opid;
    element.setAttribute("data-opid", opid);
    const tagName = element.tagName.toLowerCase();
    const type = getAttributeLowerCase(element, AUTOFILL_ATTRIBUTES.TYPE) || "text";
    const fieldData = {
      opid, elementNumber: index,
      maxLength: getFieldMaxLength(element),
      viewable: isElementViewable(element),
      htmlID: getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.ID),
      htmlName: getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.NAME),
      htmlClass: getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.CLASS),
      tabindex: getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.TABINDEX),
      title: getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.TITLE),
      tagName, type
    };
    if (elementIsSpanElement(element)) {
      fieldData.value = element.textContent || element.innerText || "";
      return fieldData;
    }
    if (type !== "hidden") {
      fieldData["label-tag"] = createLabelTag(element);
      fieldData["label-data"] = getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.DATA_LABEL);
      fieldData["label-aria"] = getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.ARIA_LABEL);
      fieldData["label-top"] = createTopLabel(element);
      fieldData["label-right"] = createRightLabel(element);
      fieldData["label-left"] = createLeftLabel(element);
      fieldData.placeholder = getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.PLACEHOLDER);
    }
    if (element.form) fieldData.form = element.form.opid || null;
    fieldData.rel = getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.REL);
    fieldData.value = getElementValue(element);
    fieldData.checked = getAttributeBoolean(element, AUTOFILL_ATTRIBUTES.CHECKED);
    fieldData.autoCompleteType = getAutoCompleteAttribute(element);
    fieldData.disabled = getAttributeBoolean(element, AUTOFILL_ATTRIBUTES.DISABLED);
    fieldData.readonly = getAttributeBoolean(element, AUTOFILL_ATTRIBUTES.READONLY);
    fieldData["aria-hidden"] = getAttributeBoolean(element, AUTOFILL_ATTRIBUTES.ARIA_HIDDEN, true);
    fieldData["aria-disabled"] = getAttributeBoolean(element, AUTOFILL_ATTRIBUTES.ARIA_DISABLED, true);
    fieldData["aria-haspopup"] = getAttributeBoolean(element, AUTOFILL_ATTRIBUTES.ARIA_HASPOPUP, true);
    fieldData["data-stripe"] = getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.DATA_STRIPE);
    if (elementIsSelectElement(element)) fieldData.selectInfo = getSelectElementOptions(element);
    return fieldData;
  }

  function getFieldMaxLength(element) {
    if (elementIsInputElement(element) || elementIsTextAreaElement(element)) {
      const maxLength = element.maxLength > -1 ? element.maxLength : 999;
      return Math.min(maxLength, 999);
    }
    return null;
  }

  function isElementViewable(element) {
    if (!element) return false;
    const style = globalThis.getComputedStyle(element);
    if (!style) return true;
    if (style.display === "none" || style.visibility === "hidden") return false;
    const rect = element.getBoundingClientRect();
    return !(rect.width === 0 && rect.height === 0);
  }

  function getAttributeLowerCase(element, attributeName) {
    const value = getPropertyOrAttribute(element, attributeName);
    return value ? value.toLowerCase() : undefined;
  }

  function createLabelTag(element) {
    const labels = element.labels;
    if (labels && labels.length > 0) {
      return Array.from(labels).map((label) => (label.textContent || label.innerText || "").trim()).join("");
    }
    const id = element.id;
    if (id) {
      const label = document.querySelector(`label[for="${id}"]`);
      if (label) return (label.textContent || label.innerText || "").trim();
    }
    const parentLabel = element.closest("label");
    if (parentLabel) return (parentLabel.textContent || parentLabel.innerText || "").trim();
    return "";
  }

  function createTopLabel(element) {
    const td = element.closest("td");
    if (!td) return null;
    const cellIndex = td.cellIndex;
    if (cellIndex < 0) return null;
    const row = td.closest("tr");
    if (!row || !row.previousElementSibling) return null;
    const prevRow = row.previousElementSibling;
    if (prevRow.cells && prevRow.cells.length > cellIndex) {
      const cell = prevRow.cells[cellIndex];
      return (cell.textContent || cell.innerText || "").trim();
    }
    return null;
  }

  function createRightLabel(element) {
    const labelParts = [];
    let sibling = element.nextSibling;
    while (sibling) {
      if (sibling.nodeType === Node.TEXT_NODE) {
        const text = sibling.nodeValue?.trim();
        if (text) labelParts.push(text);
      } else if (sibling.nodeType === Node.ELEMENT_NODE) {
        if (["input", "select", "textarea", "button", "form"].includes(sibling.tagName.toLowerCase())) break;
        const text = sibling.textContent?.trim();
        if (text) labelParts.push(text);
      }
      sibling = sibling.nextSibling;
    }
    return labelParts.join("");
  }

  function createLeftLabel(element) {
    const labelParts = [];
    let sibling = element.previousSibling;
    while (sibling) {
      if (sibling.nodeType === Node.TEXT_NODE) {
        const text = sibling.nodeValue?.trim();
        if (text) labelParts.unshift(text);
      } else if (sibling.nodeType === Node.ELEMENT_NODE) {
        if (["input", "select", "textarea", "button", "form"].includes(sibling.tagName.toLowerCase())) break;
        const text = sibling.textContent?.trim();
        if (text) labelParts.unshift(text);
      }
      sibling = sibling.previousSibling;
    }
    return labelParts.join("");
  }

  function getAutoCompleteAttribute(element) {
    return (
      getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.AUTOCOMPLETE) ||
      getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.X_AUTOCOMPLETE_TYPE) ||
      getPropertyOrAttribute(element, AUTOFILL_ATTRIBUTES.AUTOCOMPLETE_TYPE)
    );
  }

  function getElementValue(element) {
    if (elementIsSpanElement(element)) return element.textContent || element.innerText || "";
    const type = (element.type || "text").toLowerCase();
    if ("checked" in element && type === "checkbox") return element.checked ? "✓" : "";
    if (type === "hidden") {
      const value = element.value || "";
      return value.length > 254 ? value.substring(0, 254) + "...SNIPPED" : value;
    }
    return element.value || "";
  }

  function getSelectElementOptions(element) {
    const options = Array.from(element.options).map((option) => {
      const optionText = option.text
        ? option.text.toLowerCase().replace(/[\s~`!@$%^&#*()\-_+=:;'"[\]|\\,<.>?]/gm, "")
        : null;
      return [optionText, option.value];
    });
    return { options };
  }

  function generateFillScript(pageDetails, login) {
    if (!pageDetails || !login) return null;
    const filledFields = {};
    const script = { script: [], properties: {} };
    const passwordFields = loadPasswordFields(pageDetails, false);

    if (!passwordFields || !passwordFields.length) {
      if (login.totp) {
        const totpField = pageDetails.fields.find((f) => f.viewable && velaIsTotpField(f));
        if (totpField) {
          script.script.push({ opid: totpField.opid, action: "fill", value: login.totp });
          return script;
        }
      }
      if (login.username) {
        const textField = pageDetails.fields.find((f) =>
          f.viewable && ["text", "email", "tel", "url"].includes(f.type || "text")
        );
        if (textField) {
          script.script.push({ opid: textField.opid, action: "fill", value: login.username });
          return script;
        }
      }
      return null;
    }

    const usernameField = findUsernameField(pageDetails, passwordFields[0]);
    if (usernameField && login.username) {
      filledFields[usernameField.opid] = usernameField;
      script.script.push({ opid: usernameField.opid, action: "fill", value: login.username });
    }
    if (login.password) {
      filledFields[passwordFields[0].opid] = passwordFields[0];
      script.script.push({ opid: passwordFields[0].opid, action: "fill", value: login.password });
    }
    if (login.totp) {
      const totpField = pageDetails.fields.find(
        (f) => f.viewable && velaIsTotpField(f) && !filledFields[f.opid]
      );
      if (totpField) {
        script.script.push({ opid: totpField.opid, action: "fill", value: login.totp });
      }
    }
    return script;
  }

  function velaIsTotpField(field) {
    if (field.autoCompleteType && field.autoCompleteType.includes("one-time-code")) return true;
    const toCheck = [field.htmlName, field.htmlID, field.placeholder, field["label-tag"], field["label-aria"], field["label-left"], field["label-top"]]
      .filter(Boolean).join(" ").toLowerCase().replace(/[^a-z0-9]/g, "");
    const totpPatterns = ["totp", "otp", "2fa", "mfa", "twofactor", "onetime", "verif", "authenticat", "approvalcode", "securitycode"];
    return totpPatterns.some((p) => toCheck.includes(p));
  }

  function loadPasswordFields(pageDetails, isGettingFromForms, onlyEmptyFields = false) {
    const passwordFields = [];
    for (const field of pageDetails.fields) {
      if (!field.viewable) continue;
      if (field.type === "password") {
        if (onlyEmptyFields && field.value) continue;
        passwordFields.push(field);
      }
    }
    return passwordFields;
  }

  function findUsernameField(pageDetails, passwordField) {
    const usernameFields = [];
    const usernameNames = AutoFillConstants?.UsernameFieldNames;
    const hasFuzzy = typeof fieldIsFuzzyMatch === "function" && usernameNames && usernameNames.length;
    for (const field of pageDetails.fields) {
      if (!field.viewable) continue;
      if (field.opid === passwordField.opid) continue;
      const type = field.type || "text";
      if (!["text", "email", "tel", "url"].includes(type)) continue;
      if (hasFuzzy) {
        if (fieldIsFuzzyMatch(field, usernameNames)) usernameFields.push(field);
      } else {
        usernameFields.push(field);
      }
    }
    if (usernameFields.length === 1) return usernameFields[0];
    if (usernameFields.length > 1) {
      const pwIdx = pageDetails.fields.indexOf(passwordField);
      const before = usernameFields.filter((f) => pageDetails.fields.indexOf(f) < pwIdx);
      if (before.length) return before[before.length - 1];
      return usernameFields[0];
    }
    const pwIdx = pageDetails.fields.indexOf(passwordField);
    for (let i = pwIdx - 1; i >= 0; i--) {
      const f = pageDetails.fields[i];
      if (f.viewable && ["text", "email", "tel", "url"].includes(f.type || "text")) return f;
    }
    return null;
  }

  function handleFillForm(message) {
    const { fillScript } = message;
    if (fillScript && fillScript.script) performFill(fillScript);
  }

  function performFill(fillScript) {
    if (!fillScript || !fillScript.script || !fillScript.script.length) return;
    fillScript.script.forEach((op, index) => {
      setTimeout(() => {
        // CSS.escape, not escapeHtml: this is a selector, not markup. A `"` in
        // an opid would end the attribute value and change which element the
        // selector matches — or throw — rather than inject HTML, but the fix is
        // the same shape and costs nothing.
        let element =
          document.querySelector(`[data-opid="${CSS.escape(String(op.opid ?? ""))}"]`) ||
          document.querySelector(`[opid="${CSS.escape(String(op.opid ?? ""))}"]`);
        if (!element) {
          const allElements = document.querySelectorAll("[opid]");
          for (let i = 0; i < allElements.length; i++) {
            if (allElements[i].getAttribute("opid") === op.opid) { element = allElements[i]; break; }
          }
        }
        if (!element) {
          const fieldIndex = parseInt(op.opid.replace("__", ""), 10);
          if (!isNaN(fieldIndex)) {
            const excludedTypes = ["hidden","submit","reset","button","image","file","search","url","date","time","datetime","datetime-local","week","color","range"];
            let q = "input:not([data-bwignore]):not([data-vela-ui])";
            excludedTypes.forEach((t) => { q += `:not([type="${t}"])`; });
            q += ", textarea:not([data-bwignore]):not([data-vela-ui]), select:not([data-bwignore]):not([data-vela-ui])";
            const inputs = document.querySelectorAll(q);
            if (inputs[fieldIndex]) element = inputs[fieldIndex];
          }
        }
        if (!element) return;
        switch (op.action) {
          case "fill": fillElement(element, op.value); break;
          case "click": element.click(); break;
          case "submit":
            if (element.form) element.form.submit();
            break;
        }
      }, index * 20);
    });
  }

  function fillElement(element, value) {
    const tagName = element.tagName.toLowerCase();
    if (tagName === "input" || tagName === "textarea") {
      const type = (element.type || "text").toLowerCase();
      element.focus();
      if (type === "checkbox") {
        element.checked = value === "true" || value === "✓";
      } else {
        const nativeInputValueSetter = Object.getOwnPropertyDescriptor(tagName === "textarea" ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype, "value")?.set;
        if (nativeInputValueSetter) {
          nativeInputValueSetter.call(element, value);
        } else {
          element.value = value;
        }
      }
      element.dispatchEvent(new Event("input", { bubbles: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
    } else if (tagName === "select") {
      for (let i = 0; i < element.options.length; i++) {
        if (element.options[i].value === value || element.options[i].text === value) {
          element.selectedIndex = i;
          element.dispatchEvent(new Event("input", { bubbles: true }));
          element.dispatchEvent(new Event("change", { bubbles: true }));
          break;
        }
      }
    }
    element.blur();
  }

  // Defaults to userInitiated=true: every current caller (copy password,
  // fill-on-submit, the legacy autofill bridge) needs the actual password,
  // not just metadata. The passive dropdown path uses velaRequestLogins()
  // instead, which threads its own explicit userInitiated flag.
  async function getLoginsForPage(url, userInitiated = true) {
    try {
      const response = await sendExtensionMessage("getLogins", { url, userInitiated });
      if (response && response.success && response.logins) return response.logins;
    } catch (e) {}
    return [];
  }

  function copyUsername() {
    getLoginsForPage(globalThis.location.href).then((logins) => {
      if (logins && logins.length > 0 && logins[0].username) {
        globalThis.navigator.clipboard.writeText(logins[0].username);
      }
    });
  }

  function copyPassword() {
    getLoginsForPage(globalThis.location.href).then((logins) => {
      if (logins && logins.length > 0 && logins[0].password) {
        globalThis.navigator.clipboard.writeText(logins[0].password);
      }
    });
  }

  // =========================================================
  // INLINE AUTOFILL SYSTEM
  // =========================================================

  function initInlineAutofill() {
    document.addEventListener("focusin", velaOnFocusIn, true);
    document.addEventListener("focusout", velaOnFocusOut, true);
    document.addEventListener("mouseover", velaOnMouseOver, true);
    document.addEventListener("mouseout", velaOnMouseOut, true);
    document.addEventListener("keydown", velaOnKeyDown, true);
    document.addEventListener("submit", velaOnFormSubmit, true);
    document.addEventListener("click", velaOnDocClick, true);
    window.addEventListener("scroll", velaRepositionDropdown, { passive: true, capture: true });
    window.addEventListener("resize", velaRepositionDropdown, { passive: true });

    // Capture support beyond a plain form submit (item 7): SPA logins and
    // flows where the site never fires `submit` at all.
    document.addEventListener("input", velaOnPasswordInput, true);
    document.addEventListener("click", velaOnPossibleSubmitClick, true);
    window.addEventListener("pagehide", velaStashPendingCapture);
    document.addEventListener("visibilitychange", velaOnVisibilityChange);
    velaConsumeStashedCapture();
  }

  function velaIsAutofillable(el) {
    if (!el || el.tagName.toLowerCase() !== "input") return false;
    if (el.hasAttribute("data-vela-ui") || el.hasAttribute("data-bwignore")) return false;
    if (el.disabled || el.readOnly) return false;
    const type = (el.type || "text").toLowerCase();
    if (type === "password") return true;
    if (!["text", "email", "tel", "url"].includes(type)) return false;
    const ac = (el.autocomplete || "").toLowerCase();
    if (["username", "email", "current-password", "new-password"].includes(ac)) return true;
    const attrs = [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.getAttribute("title")]
      .filter(Boolean).join(" ").toLowerCase().replace(/[^a-z0-9]/g, "");
    const patterns = ["user", "email", "login", "account", "mail", "identifier", "phone", "signin", "username"];
    return patterns.some((p) => attrs.includes(p));
  }

  function velaIsNewPasswordField(el) {
    if (!el || (el.type || "").toLowerCase() !== "password") return false;
    if (el.autocomplete === "new-password") return true;
    const form = el.form || el.closest("form");
    if (!form) return false;
    const pwFields = form.querySelectorAll("input[type='password']");
    if (pwFields.length >= 2) return true;
    const formHtml = form.innerHTML.toLowerCase();
    return ["confirm", "repeat", "retype", "register", "signup", "sign_up", "create.account"].some((s) => formHtml.includes(s));
  }

  async function velaOnFocusIn(e) {
    const el = e.target;

    if (velaSiteSettings.neverAutofill) return;

    // Payment fields first: the card heuristics are deliberately narrow, but
    // they must win over the login ones so a cardholder field (which contains
    // "account") is not mistaken for a username.
    // Cards and identities are not tied to a site, so focus alone (which a
    // page can trigger itself) only shows the icon. The chooser, and the
    // vault request behind it, wait for a click on the icon or ArrowDown.
    if (velaIsCardField(el)) {
      velaActiveField = el;
      velaCurrentCards = null;
      velaInjectFieldIcon(el);
      return;
    }

    if (velaIsIdentityField(el)) {
      velaActiveField = el;
      velaInjectFieldIcon(el);
      return;
    }
    if (velaIsTotpInput(el)) {
      velaActiveField = el;
      velaInjectFieldIcon(el);
      return;
    }
    if (!velaIsAutofillable(el)) return;

    velaActiveField = el;
    velaCurrentLogins = null;
    velaRequiresBiometric = false;

    velaShowDropdown(el, null, false);

    if (velaHoveredField !== el) {
      velaInjectFieldIcon(el);
    }

    try {
      const result = await velaRequestLogins(false);
      velaCurrentLogins = result.logins;
      velaRequiresBiometric = result.requiresBiometric;
    } catch (_) {
      velaCurrentLogins = [];
      velaRequiresBiometric = false;
    }

    if (velaActiveField !== el) return;

    const isNewPw = velaIsNewPasswordField(el);
    velaShowDropdown(
      el,
      velaRequiresBiometric ? { requiresBiometric: true } : velaCurrentLogins,
      isNewPw
    );
  }

  function velaOnFocusOut(e) {
    setTimeout(() => {
      if (!velaDropdownEl) return;
      const active = document.activeElement;
      if (active && (velaDropdownEl.contains(active) || velaFieldIconEl?.contains(active))) return;
      if (active && active === velaActiveField) return;
      velaHideDropdown();
    }, 200);
  }

  function velaOnMouseOver(e) {
    if (velaSiteSettings.neverAutofill) return;
    const el = e.target;
    if (!velaIsAutofillable(el) && !velaIsCardField(el) && !velaIsTotpInput(el) && !velaIsIdentityField(el)) return;
    if (velaActiveField === el || velaDropdownEl) return;
    if (velaHoveredField === el) return;
    velaHoveredField = el;
    if (!velaActiveField) velaRemoveFieldIcon();
    velaInjectFieldIcon(el);
  }

  function velaOnMouseOut(e) {
    const el = e.target;
    if (velaHoveredField !== el) return;
    const relatedTarget = e.relatedTarget;
    if (relatedTarget && velaFieldIconEl && (velaFieldIconEl === relatedTarget || velaFieldIconEl.contains(relatedTarget))) return;
    if (velaActiveField === el) return;
    velaHoveredField = null;
    velaRemoveFieldIcon();
  }

  // Releasing a credential needs a real user gesture. Page scripts can call
  // `.click()` on our rows (the dropdown lives in the page DOM), so a row
  // only acts on a trusted click, or on a click we dispatch ourselves from a
  // trusted Enter/Space keypress.
  let velaKeyboardActivation = null;
  function velaActivateFromKey(e, item) {
    if (!e.isTrusted || !item) return;
    e.stopPropagation(); // The row and document key handlers must not activate twice.
    velaKeyboardActivation = item;
    try { item.click(); } finally { velaKeyboardActivation = null; }
  }
  function velaIsUserActivation(e) {
    return e.isTrusted || (velaKeyboardActivation !== null && velaKeyboardActivation === e.currentTarget);
  }

  function velaOnKeyDown(e) {
    if (e.key === "Escape" && velaDropdownEl) {
      e.stopPropagation();
      velaHideDropdown();
      return;
    }

    if (!velaDropdownEl) {
      // Cards and identities never open on focus alone (a page can focus a
      // field itself). The keyboard equivalent of clicking the field icon:
      if (e.key === "ArrowDown" && e.isTrusted && !e.altKey && !e.ctrlKey && !e.metaKey) {
        const field = e.target;
        if (field === velaActiveField && velaIsCardField(field)) { e.preventDefault(); velaShowCardsForField(field); }
        else if (field === velaActiveField && velaIsIdentityField(field)) { e.preventDefault(); velaShowIdentityDropdown(field); }
      }
      return;
    }

    const items = Array.from(velaDropdownEl.querySelectorAll(".vela-dd-item"));
    if (!items.length) return;

    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        e.stopPropagation();
        velaSelectedIndex = Math.min(velaSelectedIndex + 1, items.length - 1);
        velaUpdateSelection(items);
        break;
      case "ArrowUp":
        e.preventDefault();
        e.stopPropagation();
        velaSelectedIndex = Math.max(velaSelectedIndex - 1, 0);
        velaUpdateSelection(items);
        break;
      case "Enter":
        if (velaSelectedIndex >= 0 && items[velaSelectedIndex]) {
          e.preventDefault();
          e.stopPropagation();
          velaActivateFromKey(e, items[velaSelectedIndex]);
        }
        break;
      case "Tab":
        velaHideDropdown();
        break;
    }
  }

  function velaUpdateSelection(items) {
    items.forEach((item, i) => {
      item.classList.toggle("vela-dd-item--selected", i === velaSelectedIndex);
      item.setAttribute("aria-selected", String(i === velaSelectedIndex));
      if (i === velaSelectedIndex) {
        item.scrollIntoView({ block: "nearest" });
      }
    });
  }

  function velaOnDocClick(e) {
    if (!velaDropdownEl) return;
    const t = e.target;
    if (e.composedPath().some(node => node === velaDropdownEl || node === velaFieldIconEl)) return;
    if (t?.closest?.("[data-vela-ui]")) return;
    if (!velaDropdownEl.contains(t) && t !== velaActiveField && t !== velaFieldIconEl) {
      velaHideDropdown();
    }
  }

  function velaRepositionDropdown() {
    if (velaDropdownEl && velaActiveField) velaPositionDropdown(velaActiveField);
  }

  // --- Field Icon ---

  function velaInjectFieldIcon(field) {
    // Keep a hovered icon attached during the focus caused by its own press.
    // Replacing it between mousedown and click retargets the click to the page.
    if (velaFieldIconEl?._velaField === field && velaFieldIconEl.isConnected) return;
    velaRemoveFieldIcon();
    const icon = document.createElement("button");
    icon.setAttribute("data-vela-ui", "true");
    icon.setAttribute("type", "button");
    icon.setAttribute("tabindex", "-1");
    icon.setAttribute("title", "VELA – autofill");
    icon.className = "vela-field-icon";
    icon._velaField = field;
    icon.innerHTML = globalThis.VelaInstrument.icon(velaIsCardField(field) ? "card" : velaIsTotpInput(field) ? "key" : "shield", 14);

    icon.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (!e.isTrusted) return;
      // Focusing a field opens its chooser. Clicking any part of its icon
      // keeps that chooser open rather than toggling it shut.
      if (velaDropdownEl && velaActiveField === field) return;
      if (document.activeElement !== field) {
        field.focus({preventScroll:true});
        if (velaDropdownEl && velaActiveField === field) return;
      }
      {
        velaActiveField = field;
        if (velaIsIdentityField(field)) {
          velaShowIdentityDropdown(field);
          return;
        } else if (velaIsCardField(field)) {
          velaShowCardsForField(field);
          return;
        }
        if (velaIsTotpInput(field)) {
          velaShowTotpDropdown(field);
          return;
        }
        if (velaCurrentLogins !== null) {
          if (velaRequiresBiometric) {
            velaShowDropdown(field, { requiresBiometric: true }, velaIsNewPasswordField(field));
          } else {
            velaShowDropdown(field, velaCurrentLogins, velaIsNewPasswordField(field));
          }
        } else {
          velaShowDropdown(field, null, false);
          velaRequestLogins(false).then((result) => {
            velaCurrentLogins = result.logins;
            velaRequiresBiometric = result.requiresBiometric;
            if (velaActiveField === field) {
              velaShowDropdown(
                field,
                velaRequiresBiometric ? { requiresBiometric: true } : velaCurrentLogins,
                velaIsNewPasswordField(field)
              );
            }
          }).catch(() => {
            velaCurrentLogins = [];
            velaRequiresBiometric = false;
            if (velaActiveField === field) velaShowDropdown(field, [], false);
          });
        }
      }
    });

    icon.addEventListener("click", e => e.stopPropagation());

    const rect = field.getBoundingClientRect();
    const scrollX = window.scrollX || window.pageXOffset;
    const scrollY = window.scrollY || window.pageYOffset;
    icon.style.position = "absolute";
    icon.style.top = (rect.top + scrollY + (rect.height - 24) / 2) + "px";
    icon.style.left = (rect.right + scrollX - 30) + "px";
    icon.style.zIndex = "2147483646";

    document.documentElement.appendChild(icon);
    velaFieldIconEl = icon;

    // One-click inline generator on registration/change-password fields: the
    // dropdown's "generate" action is two clicks deep, and a new password is
    // exactly where a generator earns its keep.
    if (velaIsNewPasswordField(field)) {
      const gen = document.createElement("button");
      gen.setAttribute("data-vela-ui", "true");
      gen.setAttribute("type", "button");
      gen.setAttribute("tabindex", "-1");
      gen.setAttribute("title", "VELA – generate strong password");
      gen.className = "vela-field-icon vela-field-icon--gen";
      gen.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3v2M12 19v2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M3 12h2M19 12h2M5.6 18.4L7 17M18.4 5.6L17 7"/><circle cx="12" cy="12" r="4"/></svg>`;

      gen.addEventListener("mousedown", (e) => {
        e.preventDefault();
        velaHideDropdown();
        velaActiveField = field;
        velaShowPasswordGenerator(field);
      });

      gen.style.position = "absolute";
      gen.style.top = icon.style.top;
      gen.style.left = (rect.right + scrollX - 30 - 28) + "px";
      gen.style.zIndex = "2147483646";

      document.documentElement.appendChild(gen);
      velaGenIconEl = gen;
    }
  }

  function velaRemoveFieldIcon() {
    if (velaFieldIconEl) {
      velaFieldIconEl.remove();
      velaFieldIconEl = null;
    }
    if (velaGenIconEl) {
      velaGenIconEl.remove();
      velaGenIconEl = null;
    }
  }

  // --- Dropdown ---

  function velaShowDropdown(field, logins, isNewPassword) {
    clearInterval(velaTotpTimer); velaTotpTimer = null;
    if (velaDropdownEl) {
      velaDropdownEl.remove();
      velaDropdownEl = null;
    }

    const dd = document.createElement("div");
    dd.setAttribute("data-vela-ui", "true");
    dd.className = "vela-inline-dropdown vela-autofill-animate-slide-up";

    if (logins === null) {
      dd.innerHTML = `
        <div class="vela-dd-header">
          <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
          <span class="vela-dd-title">VELA</span>
        </div>
        <div class="vela-dd-loading">
          <div class="vela-dd-spinner"></div>
          <span>Searching vault…</span>
        </div>`;
    } else if (logins && logins.requiresBiometric) {
      dd.innerHTML = `
        <div class="vela-dd-header">
          <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
          <span class="vela-dd-title">VELA</span>
        </div>
        <div class="vela-dd-empty">
          Unlock VELA Desktop to show logins for <strong>${velaEscapeHtml(velaExtractDomain(location.href))}</strong>
        </div>
        <button class="vela-dd-action-btn" data-vela-action="unlock-logins">
          <span class="vela-dd-action-icon">${globalThis.VelaInstrument.icon("lock",18)}</span>
          Open VELA Desktop
        </button>`;
    } else if (isNewPassword) {
      dd.innerHTML = `
        <div class="vela-dd-header">
          <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
          <span class="vela-dd-title">VELA</span>
        </div>
        <button class="vela-dd-action-btn" data-vela-action="generate-password">
          <span class="vela-dd-action-icon">${globalThis.VelaInstrument.icon("dice",18)}</span>
          Generate strong password
        </button>
        ${logins && logins.length > 0 ? `
        <div class="vela-dd-divider"></div>
        <div class="vela-dd-section-label">Or fill existing login</div>
        ${velaLoginListItems(logins)}` : ""}
        <div class="vela-dd-divider"></div>
        <button class="vela-dd-action-btn" data-vela-action="save-new">
          <span class="vela-dd-action-icon">${globalThis.VelaInstrument.icon("plus",18)}</span>
          Save new account to VELA
        </button>`;
    } else if (logins && logins.length > 0) {
      dd.innerHTML = `
        <div class="vela-dd-header">
          <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
          <span class="vela-dd-title">FILL A LOGIN</span>
        </div>
        ${velaLoginListItems(logins)}`;
    } else {
      dd.innerHTML = `
        <div class="vela-dd-header">
          <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
          <span class="vela-dd-title">VELA</span>
        </div>
        <div class="vela-dd-empty">
          No saved logins for <strong>${velaEscapeHtml(velaExtractDomain(location.href))}</strong>
        </div>
        <button class="vela-dd-action-btn" data-vela-action="save-new">
          <span class="vela-dd-action-icon">${globalThis.VelaInstrument.icon("plus",18)}</span>
          Add to VELA vault
        </button>`;
    }

    const warningHtml = velaPhishingWarningHtml();
    if (warningHtml) {
      dd.innerHTML = warningHtml + dd.innerHTML;
    }

    document.documentElement.appendChild(dd);
    velaDropdownEl = dd;
    velaSelectedIndex = -1;
    velaPrepareDropdown(dd);
    velaPositionDropdown(field);

    dd.querySelectorAll("[data-vela-login-id]").forEach((item) => {
      item.addEventListener("click", async (e) => {
        if (!velaIsUserActivation(e)) return;
        const loginId = item.getAttribute("data-vela-login-id");
        let login = (logins || []).find((l) => String(l.id) === loginId);
        if (!login) return;

        velaHideDropdown();
        if (!login.password) {
          velaShowDropdown(field, null, false);
          const result = await velaRequestLogins(true);
          velaCurrentLogins = result.logins;
          velaRequiresBiometric = result.requiresBiometric;
          login = velaCurrentLogins.find((l) => String(l.id) === loginId);
          velaHideDropdown();
        }

        if (login && login.password) {
          fillWithLogin(login);
        } else if (velaRequiresBiometric && velaActiveField === field) {
          velaShowDropdown(field, { requiresBiometric: true }, velaIsNewPasswordField(field));
        }
      });
      item.addEventListener("mousedown", (e) => e.preventDefault());
    });

    const genBtn = dd.querySelector("[data-vela-action='generate-password']");
    if (genBtn) {
      genBtn.addEventListener("click", () => {
        velaHideDropdown();
        velaShowPasswordGenerator(field);
      });
      genBtn.addEventListener("mousedown", (e) => e.preventDefault());
    }

    const unlockBtn = dd.querySelector("[data-vela-action='unlock-logins']");
    if (unlockBtn) {
      unlockBtn.addEventListener("click", async () => {
        await sendExtensionMessage("openVault");
        velaShowDropdown(field, null, false);
        const result = await velaRequestLogins(true);
        velaCurrentLogins = result.logins;
        velaRequiresBiometric = result.requiresBiometric;
        if (velaActiveField === field) {
          velaShowDropdown(
            field,
            velaRequiresBiometric ? { requiresBiometric: true } : velaCurrentLogins,
            velaIsNewPasswordField(field)
          );
        }
      });
      unlockBtn.addEventListener("mousedown", (e) => e.preventDefault());
    }

    const saveBtn = dd.querySelector("[data-vela-action='save-new']");
    if (saveBtn) {
      saveBtn.addEventListener("click", () => {
        velaHideDropdown();
        const { user, pw } = velaCaptureCreds(field);
        velaShowSaveDialog(user, pw);
      });
      saveBtn.addEventListener("mousedown", (e) => e.preventDefault());
    }
  }

  function velaLoginListItems(logins) {
    return logins.map((login) => {
      const name = velaEscapeHtml(login.name || velaExtractDomain(login.url || "") || "Login");
      const user = velaEscapeHtml(login.username || "");
      const initial = name.charAt(0).toUpperCase();
      return `
        <div class="vela-dd-item" data-vela-login-id="${velaEscapeHtml(login.id || "")}">
          <div class="vela-dd-item-avatar">${initial}</div>
          <div class="vela-dd-item-info">
            <div class="vela-dd-item-name">${name}</div>
            ${user ? `<div class="vela-dd-item-user">${user}</div>` : ""}
          </div>
          <div class="vela-dd-item-fill-hint">Fill ↵</div>
        </div>`;
    }).join("");
  }

  // --- Credit cards ---
  //
  // A card is not scoped to a site, so the heuristics here only decide whether
  // a field is a payment field; the fill is offered as a whole-card action
  // from whichever payment field the user invoked VELA on. The heuristics are
  // deliberately narrow so an ordinary "name"/"number" input is not claimed.

  function velaCardText(el) {
    return [el.name, el.id, el.getAttribute("autocomplete"), el.getAttribute("x-autocomplete"),
            el.getAttribute("x-webkit-autocomplete"), el.getAttribute("data-stripe"),
            el.placeholder, el.getAttribute("aria-label"), el.getAttribute("title")]
      .filter(Boolean).join(" ").toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  function velaCardFieldKind(el) {
    if (!el || !["input", "select"].includes(el.tagName.toLowerCase())) return null;
    if (el.hasAttribute("data-vela-ui") || el.hasAttribute("data-bwignore")) return null;
    if (el.disabled || el.readOnly) return null;
    const type = (el.type || "text").toLowerCase();
    if (el.tagName !== "SELECT" && !["text", "tel", "number", "password", "month"].includes(type)) return null;

    const t = velaCardText(el);
    if (!t) return null;
    const has = (...needles) => needles.some((needle) => t.includes(needle));

    // CVV first: "cvc"/"cvv" never appear in a login field.
    if (has("cvv", "cvc", "csc", "cvn", "ccv", "cardcode", "securitycode", "cardverif", "cryptogramme")) return "cvv";
    // Split expiry before the combined expiry names, which also contain "exp".
    if (has("ccexpmonth", "cardexpmonth", "expmonth", "expirymonth", "expmo", "cardmonth", "ccmm", "cbdatemois")) return "expMonth";
    if (has("ccexpyear", "cardexpyear", "expyear", "expiryyear", "expyy", "cardyear", "ccyy", "cbdateann")) return "expYear";
    if (has("ccnumber", "cardnumber", "creditcard", "ccnum", "cardnum", "ccno", "cardno",
            "numerocarte", "numcarte", "cbnum", "cardpan")) return "number";
    if (has("ccexp", "cardexp", "ccxp", "expirationdate", "expirydate", "cardexpiry",
            "cardexpiration", "paymentcardexpiration", "validite", "dateexpiration")) return "exp";
    if (has("cardholder", "ccname", "cardname", "nameoncard")) return "name";
    return null;
  }

  // The trigger check: a cardholder field only counts when the same form also
  // has a number/expiry/CVV, so a lone "account holder name" on a signup form
  // never offers cards. `velaCardFieldKind` (used when filling) still matches
  // the cardholder field once a payment group is known.
  function velaIsCardField(el) {
    const kind = velaCardFieldKind(el);
    if (!kind) return null;
    if (kind !== "name") return kind;
    const scope = el.form || el.closest("form") || document;
    const hasPayment = Array.from(scope.querySelectorAll("input,select")).some((field) => {
      const k = velaCardFieldKind(field);
      return k && k !== "name";
    });
    return hasPayment ? kind : null;
  }

  async function getCardsForPage(userInitiated = false) {
    try {
      const response = await sendExtensionMessage("getCards", { url: globalThis.location.href, userInitiated });
      if (response && response.success && Array.isArray(response.cards)) return response.cards;
    } catch (_) {}
    return [];
  }

  function velaShowCardsForField(field) {
    if (velaCurrentCards !== null && velaActiveField === field) {
      velaShowCardDropdown(field, velaCurrentCards);
      return;
    }
    velaShowCardDropdown(field, null);
    const pageUrl = location.href;
    const dropdown = velaDropdownEl;
    getCardsForPage().then((cards) => {
      if (location.href !== pageUrl || velaDropdownEl !== dropdown || velaActiveField !== field) return;
      velaCurrentCards = cards;
      if (velaActiveField === field) velaShowCardDropdown(field, cards);
    }).catch(() => {
      velaCurrentCards = [];
      if (velaActiveField === field) velaShowCardDropdown(field, []);
    });
  }

  function velaCardListItems(cards) {
    return cards.map((card) => {
      const name = velaEscapeHtml(card.name || "Card");
      const digits = String(card.number || "").replace(/\D/g, "");
      const last4 = card.last4 || digits.slice(-4);
      const sub = [card.cardholderName, last4 ? `•••• ${last4}` : ""]
        .filter(Boolean).map(velaEscapeHtml).join(" · ");
      const initial = name.charAt(0).toUpperCase();
      return `
        <div class="vela-dd-item" data-vela-card-id="${velaEscapeHtml(card.id || "")}">
          <div class="vela-dd-item-avatar">${initial}</div>
          <div class="vela-dd-item-info">
            <div class="vela-dd-item-name">${name}</div>
            ${sub ? `<div class="vela-dd-item-user">${sub}</div>` : ""}
            ${card.exp ? `<div class="vela-card-expiry">EXP ${velaEscapeHtml(card.exp)}</div>` : ""}
          </div>
          <div class="vela-dd-item-fill-hint">Fill ↵</div>
        </div>`;
    }).join("");
  }

  function velaShowCardDropdown(field, cards) {
    clearInterval(velaTotpTimer); velaTotpTimer = null;
    if (velaDropdownEl) {
      velaDropdownEl.remove();
      velaDropdownEl = null;
    }

    const dd = document.createElement("div");
    dd.setAttribute("data-vela-ui", "true");
    dd.className = "vela-inline-dropdown vela-autofill-animate-slide-up";

    const header = `
      <div class="vela-dd-header">
        <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
        <span class="vela-dd-title">PAYMENT CARDS</span>
      </div>`;

    if (cards === null) {
      dd.innerHTML = `${header}
        <div class="vela-dd-loading">
          <div class="vela-dd-spinner"></div>
          <span>Searching vault…</span>
        </div>`;
    } else if (!cards.length) {
      dd.innerHTML = `${header}
        <div class="vela-dd-empty">No saved cards. Add one in VELA Desktop.</div>`;
    } else {
      dd.innerHTML = `${header}${velaCardListItems(cards)}`;
    }

    document.documentElement.appendChild(dd);
    velaDropdownEl = dd;
    velaSelectedIndex = -1;
    velaPrepareDropdown(dd);
    velaPositionDropdown(field);

    dd.querySelectorAll("[data-vela-card-id]").forEach((item) => {
      item.addEventListener("click", (e) => {
        if (!velaIsUserActivation(e)) return;
        const id = item.getAttribute("data-vela-card-id");
        velaFillChosenItem("card", id, field, undefined, dd);
      });
      item.addEventListener("mousedown", (e) => e.preventDefault());
    });
  }

  function velaParseExpiry(value) {
    const digits = String(value || "").replace(/\D/g, "");
    if (digits.length < 3) return null;
    let mm, yy, yyyy;
    if (digits.length === 4) {
      mm = digits.slice(0, 2); yy = digits.slice(2, 4); yyyy = "20" + yy;
    } else if (digits.length === 6) {
      mm = digits.slice(0, 2); yyyy = digits.slice(2, 6); yy = yyyy.slice(2, 4);
    } else if (digits.length === 3) {
      mm = "0" + digits.slice(0, 1); yy = digits.slice(1, 3); yyyy = "20" + yy;
    } else {
      mm = digits.slice(0, 2); yy = digits.slice(-2); yyyy = "20" + yy;
    }
    const month = Number(mm);
    if (!month || month > 12) return null;
    return { mm, yy, yyyy, mmyy: `${mm}/${yy}`, mmyyyy: `${mm}/${yyyy}` };
  }

  function velaExpiryString(field, exp) {
    const max = parseInt(field.getAttribute("maxlength") || "0", 10);
    const hint = `${field.placeholder || ""} ${field.getAttribute("aria-label") || ""}`;
    return (hint.includes("/") || max === 0 || max >= 5) ? exp.mmyy : `${exp.mm}${exp.yy}`;
  }

  function velaYearString(field, exp) {
    const max = parseInt(field.getAttribute("maxlength") || "0", 10);
    if (field.tagName === "SELECT" && Array.from(field.options).some(o => o.value === exp.yy)) return exp.yy;
    return (max > 0 && max <= 2) ? exp.yy : exp.yyyy;
  }

  // Fill the whole payment group around `anchor`: number, cardholder, CVV and
  // whichever expiry shape the form uses (one combined field, or split
  // month/year).
  function velaFillCard(card, anchor) {
    const scope = (anchor && (anchor.form || anchor.closest("form"))) || document;
    const section = velaFieldSection(anchor);
    const byKind = {};
    for (const el of scope.querySelectorAll("input,select")) {
      const kind = velaCardFieldKind(el);
      if (kind && velaVisibleField(el) && velaSameSection(section, el) && !byKind[kind]) byKind[kind] = el;
    }
    const exp = velaParseExpiry(card.exp);
    let count = 0;
    const put = (field, value) => { if (field && value) { if (velaFillValue(field, value)) count++; } };

    put(byKind.name, card.cardholderName);
    put(byKind.number, String(card.number || "").replace(/\s+/g, ""));
    if (exp) {
      put(byKind.exp, byKind.exp?.type === "month" ? `${exp.yyyy}-${exp.mm}` : byKind.exp ? velaExpiryString(byKind.exp, exp) : "");
      put(byKind.expMonth, exp.mm);
      put(byKind.expYear, byKind.expYear ? velaYearString(byKind.expYear, exp) : "");
    }
    put(byKind.cvv, card.cvv);
    velaHideDropdown();
    return count;
  }

  function velaVisibleField(el) {
    return !el.disabled && !el.readOnly && el.type !== "hidden" && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
  }

  function velaFillValue(el, value) {
    if (!velaVisibleField(el)) return false;
    if (el.tagName === "SELECT") {
      const text = String(value).toLowerCase();
      const option = Array.from(el.options).find(o => o.value && (o.value.toLowerCase() === text || o.text.trim().toLowerCase() === text || (/^\d+$/.test(text) && /^\d+$/.test(o.value) && Number(o.value) === Number(text))));
      if (!option) return false;
      value = option.value;
    }
    fillElement(el, String(value));
    return true;
  }

  const velaIdentityTokens = {"name":"fullName", "given-name":"firstName", "additional-name":"middleName", "family-name":"lastName", "email":"email", "tel":"phone", "organization":"company", "street-address":"street", "address-line1":"line1", "address-line2":"line2", "address-level2":"city", "address-level1":"region", "postal-code":"postalCode", "country":"countryCode", "country-name":"countryName"};
  function velaIdentityFieldKind(el) {
    if (!el || !["INPUT","SELECT","TEXTAREA"].includes(el.tagName) || el.closest("[data-vela-ui]") || el.hasAttribute("data-bwignore") || el.disabled || el.readOnly) return null;
    if (el.tagName === "INPUT" && !["text","email","tel"].includes(el.type)) return null;
    const tokens = (el.autocomplete || "").toLowerCase().split(/\s+/);
    if (tokens.includes("username") || tokens.some(t => /password|cc-|one-time-code/.test(t))) return null;
    const token = tokens.find(t => velaIdentityTokens[t]);
    if (token) return velaIdentityTokens[token];
    const names = [el.name,el.id].filter(Boolean).map(n => n.toLowerCase().replace(/[^a-z0-9]/g, ""));
    const aliases = {firstname:"firstName", givenname:"firstName", lastname:"lastName", surname:"lastName", fullname:"fullName", middlename:"middleName", address:"street", address1:"line1", address2:"line2", state:"region", province:"region", zip:"postalCode", telephone:"phone", company:"company", addressline2:"line2", addresslineone:"line1", addressline1:"line1", streetaddress:"street", postalcode:"postalCode", zipcode:"postalCode", city:"city", country:"countryCode", phone:"phone", email:"email"};
    return names.map(n => aliases[n]).find(Boolean) || null;
  }
  function velaIsIdentityField(el) {
    const kind = velaIdentityFieldKind(el);
    if (!kind) return false;
    // A login email remains a login. Contact fields join identity forms only
    // when a name/address field exists in the same form.
    if (["email","phone"].includes(kind)) {
      const scope = el.form || el.closest("form");
      return !!scope && Array.from(scope.querySelectorAll("input,select,textarea")).some(f => {
        const k = velaIdentityFieldKind(f); return k && !["email","phone","company"].includes(k);
      });
    }
    return true;
  }
  function velaIdentityChoices(identities) {
    return identities.flatMap(identity => (identity.addresses?.length ? identity.addresses : [null]).map(address => ({identity, address})));
  }
  async function velaShowIdentityDropdown(field) {
    clearInterval(velaTotpTimer); velaTotpTimer = null;
    velaSelectedIndex = -1;
    const dd = document.createElement("div");
    dd.className = "vela-inline-dropdown vela-autofill-animate-slide-up"; dd.dataset.velaUi = "true";
    if (velaDropdownEl) velaDropdownEl.remove();
    velaDropdownEl = dd;
    dd.innerHTML = '<div class="vela-dd-header"><span class="vela-dd-title">IDENTITIES</span></div><div class="vela-dd-loading">Searching vault…</div>';
    document.documentElement.appendChild(dd); velaPrepareDropdown(dd); velaPositionDropdown(field);
    let response;
    const pageUrl = location.href;
    try { response = await sendExtensionMessage("getIdentities", {url:pageUrl, userInitiated:false}); } catch (_) {}
    if (velaDropdownEl !== dd || velaActiveField !== field || location.href !== pageUrl) return;
    const choices = velaIdentityChoices(response?.success ? response.identities || [] : []);
    dd.innerHTML = '<div class="vela-dd-header"><span class="vela-dd-title">IDENTITIES</span></div>' + (choices.length ? choices.map(({identity:i,address:a}, index) => `<div class="vela-dd-item" data-identity-index="${velaEscapeHtml(String(index))}"><div class="vela-dd-item-avatar">${globalThis.VelaInstrument.icon("user",18)}</div><div class="vela-dd-item-info"><div class="vela-dd-item-name">${velaEscapeHtml(i.name || [i.firstName,i.lastName].filter(Boolean).join(" "))}</div><div class="vela-dd-item-user">${velaEscapeHtml([a?.label,a?.line1,a?.city,i.email].filter(Boolean).join(" · "))}</div></div><div class="vela-dd-item-fill-hint">Fill ↵</div></div>`).join("") : `<div class="vela-dd-empty">${response?.requires_biometric ? "Unlock VELA Desktop and try again." : response?.success ? "No saved identities. Add one in VELA Desktop." : "Could not load identities. Open VELA Desktop and retry."}</div>`);
    velaPrepareDropdown(dd); velaPositionDropdown(field);
    dd.querySelectorAll("[data-identity-index]").forEach(row => {
      row.addEventListener("mousedown", e => e.preventDefault());
      row.addEventListener("click", (e) => { if (!velaIsUserActivation(e)) return; const c = choices[Number(row.dataset.identityIndex)]; velaFillChosenItem("identity", c.identity.id, field, c.address?.id, dd); });
    });
  }
  async function velaFillChosenItem(type, id, field, addressId, dropdown) {
    if (dropdown.dataset.filling) return;
    dropdown.dataset.filling = "true";
    const url = location.href;
    try {
      const response = await sendExtensionMessage(type === "card" ? "getCards" : "getIdentities", {url, userInitiated:true});
      if (velaDropdownEl !== dropdown || velaActiveField !== field || location.href !== url || !field.isConnected) return;
      const item = response?.success && response[type === "card" ? "cards" : "identities"]?.find(item => String(item.id) === String(id));
      if (!item) { velaShowToast("Unlock VELA Desktop and try again.", true); return; }
      velaHideDropdown();
      if (type === "card") velaFillCard(item,field); else velaFillIdentity(item,field,addressId);
    } catch (_) { velaShowToast("Could not fill this item. Try again.", true); }
    finally { delete dropdown.dataset.filling; }
  }
  /** Same autofill section, or the anchor has none (e.g. a plain email field
   *  next to `shipping …` address fields), so the whole form still fills. */
  function velaSameSection(anchorSection, el) {
    const section = velaFieldSection(el);
    return section === anchorSection || section === "" || anchorSection === "";
  }
  function velaFieldSection(el) {
    return (el?.autocomplete || "").split(/\s+/).filter(t => t.startsWith("section-") || ["shipping","billing"].includes(t)).join(" ");
  }
  function velaFillIdentity(identity, anchor, addressId) {
    const addresses = identity.addresses || [];
    // A chosen address that no longer exists is an error, not a cue to fill another one.
    if (addressId && !addresses.some(a => a.id === addressId)) { velaShowToast("That address was removed. Choose it again.", true); return 0; }
    const address = addresses.find(a => a.id === addressId) || addresses[0] || {};
    const values = {...address, ...identity, fullName:[identity.firstName,identity.middleName,identity.lastName].filter(Boolean).join(" "), street:[address.line1,address.line2].filter(Boolean).join("\n")};
    try { values.countryName = new Intl.DisplayNames([document.documentElement.lang || "en"], {type:"region"}).of(address.countryCode); } catch (_) {}
    const scope = anchor.form || anchor.closest("form") || document;
    const section = velaFieldSection(anchor);
    let count = 0;
    for (const el of scope.querySelectorAll("input,select,textarea")) {
      const kind = velaIdentityFieldKind(el);
      if (kind && velaSameSection(section, el) && values[kind] && velaVisibleField(el)) {
        if (velaFillValue(el,values[kind])) count++;
        else if (kind === "countryCode" && values.countryName && velaFillValue(el,values.countryName)) count++;
      }
    }
    velaHideDropdown(); return count;
  }

  function velaPositionDropdown(field) {
    if (!velaDropdownEl || !field) return;
    const rect = field.getBoundingClientRect();
    const sx = window.scrollX || 0, sy = window.scrollY || 0;
    const width = Math.max(0, Math.min(Math.max(336, rect.width), 360, window.innerWidth - 16));
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - width - 8));
    Object.assign(velaDropdownEl.style, {position:"absolute",width:width+"px",left:(sx+left)+"px",zIndex:"2147483647",maxHeight:Math.min(480,window.innerHeight-16)+"px"});
    const height = velaDropdownEl.getBoundingClientRect().height;
    const below = window.innerHeight - rect.bottom - 8, above = rect.top - 8;
    const up = below < Math.min(height,220) && above > below;
    velaDropdownEl.style.maxHeight = Math.max(60,Math.min(480,up?above:below))+"px";
    const h = velaDropdownEl.getBoundingClientRect().height;
    velaDropdownEl.style.top = (sy + Math.max(8, up ? rect.top-h-6 : rect.bottom+6))+"px";
  }

  function velaPrepareDropdown(dd) {
    if (!dd.querySelector(".vela-dd-warning")) {
      const warning = velaPhishingWarningHtml();
      if (warning) dd.insertAdjacentHTML("afterbegin", warning);
    }
    const header = dd.querySelector(".vela-dd-header");
    if (header) {
      const close = document.createElement("button");
      close.type = "button"; close.className = "vela-dd-close";
      close.setAttribute("aria-label", "Close suggestions"); close.innerHTML = globalThis.VelaInstrument.icon("x",14);
      close.addEventListener("mousedown", e => e.preventDefault());
      close.addEventListener("click", velaHideDropdown); header.appendChild(close);
    }
    const origin = document.createElement("div"); origin.className = "vela-dd-origin";
    origin.textContent = velaExtractDomain(location.href); dd.appendChild(origin);
    const footer = document.createElement("div"); footer.className = "vela-dd-footer";
    footer.innerHTML = '<span>↑ ↓ Choose · ↵ Fill</span><button type="button">Open vault ↗</button>';
    footer.querySelector("button").addEventListener("mousedown", e => e.preventDefault());
    footer.querySelector("button").addEventListener("click", () => sendExtensionMessage("openVault"));
    dd.appendChild(footer);
    dd.querySelectorAll(".vela-dd-item").forEach((item,index) => {
      item.setAttribute("role", "option"); item.tabIndex = 0; item.setAttribute("aria-selected", "false");
      item.addEventListener("mouseenter", () => { velaSelectedIndex = index; velaUpdateSelection(Array.from(dd.querySelectorAll(".vela-dd-item"))); });
      item.addEventListener("keydown", e => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); velaActivateFromKey(e, item); } });
    });
  }

  function velaPrepareModal(overlay) {
    velaHideDropdown();
    const modal = overlay.querySelector(".vela-modal"); if (!modal) return;
    modal.setAttribute("role", "dialog"); modal.setAttribute("aria-modal", "true");
    modal.setAttribute("aria-label", modal.querySelector(".vela-modal-title")?.textContent || "VELA");
    overlay.addEventListener("keydown", e => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); modal.querySelector(".vela-modal-close")?.click(); }
      if (e.key !== "Tab") return;
      const fields = Array.from(modal.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),[tabindex="0"]')).filter(x => x.getClientRects().length);
      const first=fields[0],last=fields[fields.length-1];
      if (e.shiftKey && document.activeElement===first) {e.preventDefault();last?.focus();}
      else if (!e.shiftKey && document.activeElement===last) {e.preventDefault();first?.focus();}
    });
    queueMicrotask(() => modal.querySelector('input:not([type="range"]),.vela-modal-close')?.focus());
  }

  function velaIsTotpInput(el) {
    if (!el || el.tagName !== "INPUT" || el.disabled || el.readOnly || el.hasAttribute("data-vela-ui")) return false;
    if (!['text','tel','number','password',''].includes(el.type || '')) return false;
    const ac = (el.autocomplete || "").toLowerCase();
    if (ac.includes("one-time-code")) return true;
    const text=[el.name,el.id,el.placeholder,el.getAttribute("aria-label")].filter(Boolean).join(" ").toLowerCase().replace(/[^a-z0-9]/g,"");
    return /totp|onetimecode|verificationcode|authenticatorcode|2facode|mfacode|otp/.test(text);
  }

  async function velaShowTotpDropdown(field) {
    clearInterval(velaTotpTimer); velaTotpTimer=null;
    velaDropdownEl?.remove(); velaActiveField=field;
    const dd=document.createElement("div"); dd.setAttribute("data-vela-ui","true"); dd.className="vela-inline-dropdown vela-autofill-animate-slide-up";
    dd.innerHTML=`<div class="vela-dd-header"><span class="vela-dd-logo">${velaShieldSvg(14)}</span><span class="vela-dd-title">ONE-TIME CODE</span></div><div class="vela-dd-loading">Loading authenticator codes…</div>`;
    document.documentElement.appendChild(dd); velaDropdownEl=dd; velaPrepareDropdown(dd); velaPositionDropdown(field);
    const alive=()=>velaDropdownEl===dd && dd.isConnected;
    let result;
    try { result=await velaRequestLogins(false); } catch (_) { result={logins:[]}; }
    if(!alive())return;
    dd.querySelector(".vela-dd-loading")?.remove();
    const entries=[];
    for(const login of result.logins || []) {
      let response;
      try { response=await sendExtensionMessage("getTotpCode",{loginId:login.id,url:location.href}); } catch (_) { continue; }
      if(!alive())return;
      if(!response?.success || !response.code)continue;
      const item=document.createElement("div");item.className="vela-dd-item";item.setAttribute("role","option");item.tabIndex=0;
      const ttl=response.remainingSecs == null ? 30 : Math.max(0,Number(response.remainingSecs)||0);
      const entry={login,item,code:response.code,remaining:ttl,expiresAt:Date.now()+ttl*1000,pending:false}; entries.push(entry);
      item.innerHTML=`<div class="vela-dd-item-info"><div class="vela-dd-item-name">${velaEscapeHtml(login.name || "Authenticator")}</div><div class="vela-dd-item-user">${velaEscapeHtml(login.username || "")}</div><div class="vela-dd-totp-code"><span class="vela-code-readout"></span><span class="vela-totp-timer"></span></div></div>`;
      item.setAttribute("aria-selected","false");
      const update=()=>{item.querySelector(".vela-code-readout").innerHTML=globalThis.VelaInstrument.dots(entry.code,4);const timer=item.querySelector(".vela-totp-timer");timer.textContent=entry.remaining+"s";timer.dataset.expiring=entry.remaining<6;}; entry.update=update;update();
      item.addEventListener("mousedown",e=>e.preventDefault());
      item.addEventListener("mouseenter",()=>{velaSelectedIndex=entries.indexOf(entry);velaUpdateSelection(entries.map(x=>x.item));});
      item.addEventListener("click",(e)=>{if(!velaIsUserActivation(e))return;if(!entry.code||entry.remaining<=0||Date.now()>=entry.expiresAt)return;const code=entry.code;velaHideDropdown();fillElement(field,code);});
      item.addEventListener("keydown",e=>{if(e.key===" "||e.key==="Enter"){e.preventDefault();velaActivateFromKey(e,item);}});
      dd.insertBefore(item,dd.querySelector(".vela-dd-origin"));
    }
    if(!alive())return;
    if(!entries.length){const empty=document.createElement("div");empty.className="vela-dd-empty";empty.textContent=result.requiresBiometric?"Unlock VELA Desktop to access your authenticator codes.":"No authenticator codes available for this site.";dd.insertBefore(empty,dd.querySelector(".vela-dd-origin"));}
    velaPositionDropdown(field);
    if(!entries.length)return;
    velaTotpTimer=setInterval(async()=>{
      if(!alive()){clearInterval(velaTotpTimer);velaTotpTimer=null;return;}
      for(const entry of entries){
        if(entry.pending || (entry.retryAt && Date.now()<entry.retryAt))continue;
        entry.remaining=Math.max(0,Math.ceil((entry.expiresAt-Date.now())/1000));
        if(entry.remaining===0){entry.code="";entry.pending=true;entry.update();try{const response=await sendExtensionMessage("getTotpCode",{loginId:entry.login.id,url:location.href});if(!alive())return;if(response?.success&&response.code){entry.code=response.code;entry.remaining=response.remainingSecs == null ? 30 : Math.max(0,Number(response.remainingSecs)||0);entry.expiresAt=Date.now()+entry.remaining*1000;entry.retryAt=0;}else{entry.retryAt=Date.now()+15000;}}catch(_){entry.retryAt=Date.now()+15000;}finally{entry.pending=false;}}
        if(alive())entry.update();
      }
    },1000);
  }

  function velaHideDropdown() {
    clearInterval(velaTotpTimer); velaTotpTimer = null;
    if (velaDropdownEl) {
      velaDropdownEl.remove();
      velaDropdownEl = null;
    }
    velaRemoveFieldIcon();
    velaActiveField = null;
    velaHoveredField = null;
    velaSelectedIndex = -1;
  }

  // --- Account Picker Modal ---

  function velaShowAccountPickerModal(logins) {
    velaRemoveModal("vela-account-picker-modal");
    const overlay = document.createElement("div");
    overlay.setAttribute("data-vela-ui", "true");
    overlay.id = "vela-account-picker-modal";
    overlay.className = "vela-overlay";
    overlay.innerHTML = `
      <div class="vela-modal vela-autofill-animate-slide-up">
        <div class="vela-modal-header">
          <div class="vela-modal-logo">${velaShieldSvg(20)}</div>
          <h2 class="vela-modal-title">Choose account</h2>
          <button class="vela-modal-close" data-vela-action="close" title="Close">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <p class="vela-modal-subtitle">Multiple logins saved for <strong>${velaEscapeHtml(velaExtractDomain(location.href))}</strong></p>
        <div class="vela-account-list">
          ${logins.map((login) => {
            const name = velaEscapeHtml(login.name || velaExtractDomain(login.url || "") || "Login");
            const user = velaEscapeHtml(login.username || "");
            const initial = name.charAt(0).toUpperCase();
            return `
              <button class="vela-account-item" data-vela-login-id="${velaEscapeHtml(login.id || "")}">
                <div class="vela-account-avatar">${initial}</div>
                <div class="vela-account-info">
                  <div class="vela-account-name">${name}</div>
                  ${user ? `<div class="vela-account-user">${user}</div>` : ""}
                </div>
                <div class="vela-account-arrow">→</div>
              </button>`;
          }).join("")}
        </div>
      </div>`;

    document.documentElement.appendChild(overlay);
    velaPrepareModal(overlay);

    overlay.querySelector("[data-vela-action='close']").addEventListener("click", () => overlay.remove());
    overlay.addEventListener("click", (e) => { if (e.target === overlay) overlay.remove(); });

    overlay.querySelectorAll("[data-vela-login-id]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const loginId = btn.getAttribute("data-vela-login-id");
        const login = logins.find((l) => String(l.id) === loginId);
        if (login) {
          overlay.remove();
          fillWithLogin(login);
        }
      });
    });
  }

  // --- Form Submit Capture ---

  function velaOnFormSubmit(e) {
    const form = e.target;
    if (!elementIsFormElement(form)) return;

    const creds = velaCaptureFormCredentials(form);
    if (!creds) return;

    // Keep the trail alive: a classic full-page form POST navigates away
    // before this page's prompt can be seen, and the landing page picks the
    // credentials up from the pagehide stash.
    velaPendingCreds = { ...creds, at: Date.now() };
    velaOfferCapture(creds);
  }

  /**
   * Read username/password credentials out of a form element.
   *
   * Registration means "the user is creating or replacing a password": two
   * password fields (the confirm box) or an explicit `autocomplete=
   * "new-password"` — the hint modern registration and change-password forms
   * carry.
   */
  function velaCaptureFormCredentials(form) {
    const pwFields = Array.from(form.querySelectorAll("input[type='password']")).filter((f) => !f.hasAttribute("data-vela-ui"));
    if (!pwFields.length) return null;

    const pwValue = pwFields[0].value;
    if (!pwValue) return null;

    const allInputs = Array.from(form.querySelectorAll("input:not([type='password']):not([type='hidden']):not([data-vela-ui])"));
    let userValue = "";
    for (const inp of allInputs) {
      const type = (inp.type || "text").toLowerCase();
      if (!["text", "email", "tel", "url"].includes(type)) continue;
      if (inp.value) { userValue = inp.value; break; }
    }

    const isRegistration =
      pwFields.length >= 2 ||
      pwFields.some((f) => (f.autocomplete || "").toLowerCase() === "new-password");

    return { username: userValue, password: pwValue, isRegistration };
  }

  // =========================================================
  // CAPTURE ENGINE (save-on-submit + SPA + update prompts)
  // =========================================================
  //
  // Three paths lead to the same prompt, deduplicated by credentials key:
  //
  // 1. `submit` — the classic case, handled above.
  // 2. Submit-button click in a password form whose fields clear or vanish
  //    shortly after (SPA logins that submit over fetch/XHR).
  // 3. Page navigation with typed-but-unsent credentials (sites that build
  //    their own login without a form), stashed in sessionStorage and offered
  //    on the page the navigation landed on.
  //
  // The prompt itself is shared: "Save login" for a new username, "Password
  // changed — update item?" when the username matches a saved login but the
  // password differs. A matching username AND password prompts nothing.

  function velaCredsKey(creds) {
    return `${creds.username || ""}\u0000${creds.password || ""}`;
  }

  /**
   * Offer save or update for `creds`, unless this site is on the never-save
   * list, the identical credentials were already prompted, or they were
   * already saved with the same password.
   *
   * The dedupe key is recorded synchronously so the three capture paths
   * (submit, SPA click, navigation stash) cannot double-prompt while the
   * vault lookup is in flight.
   */
  function velaOfferCapture(creds) {
    const key = velaCredsKey(creds);
    if (key === velaPromptedCredsKey) return;
    if (!creds.password) return;
    velaPromptedCredsKey = key;

    const domain = velaExtractDomain(location.href);
    Promise.all([
      getLoginsForPage(location.href),
      velaIsNeverSave(domain)
    ]).then(([logins, neverSave]) => {
      if (neverSave) {
        velaClearPendingCapture();
        return;
      }

      const match = logins.find((l) => l.username === creds.username);
      if (match) {
        if (!match.password || match.password === creds.password) {
          // Same credentials as the vault: nothing to capture.
          velaClearPendingCapture();
          return;
        }
        setTimeout(() => velaShowUpdateBar(match, creds), 100);
        return;
      }

      setTimeout(() => velaShowSaveBar(creds.username, creds.password, creds.isRegistration), 100);
    });
  }

  /**
   * Drop the typed-credentials trail: the capture prompt was seen (saved,
   * dismissed or expired), so it must not resurface on the next page.
   */
  function velaClearPendingCapture() {
    velaPendingCreds = null;
    try {
      sendExtensionMessage("clearPendingCapture", {});
    } catch (_) {}
  }

  /**
   * Remember what the user is typing into password fields so the SPA and
   * navigation paths have something to offer even if `submit` never fires.
   * Only trusted (human) input counts — VELA's own autofill dispatches
   * synthetic events, and we must not offer to save what we just filled.
   */
  function velaOnPasswordInput(e) {
    if (!e.isTrusted) return;
    const el = e.target;
    if (!el || el.tagName.toLowerCase() !== "input") return;
    if ((el.type || "").toLowerCase() !== "password") return;
    if (el.hasAttribute("data-vela-ui") || el.hasAttribute("data-bwignore")) return;
    if (!el.value) return;

    const form = el.form || el.closest("form");
    const creds = velaCaptureFormCredentials(form || el.closest("div,section,main,body") || document.body);
    if (creds && creds.password) {
      velaPendingCreds = { ...creds, at: Date.now() };
    }
  }

  /**
   * A click on a submit-shaped control inside a form with password fields:
   * snapshot the form, then check shortly after whether the login went
   * through (password field emptied or removed — the usual SPA success
   * behavior). If it did, offer capture even though no `submit` fired.
   */
  function velaOnPossibleSubmitClick(e) {
    if (!e.isTrusted) return;
    const target = e.target;
    if (!target || target.closest("[data-vela-ui]")) return;
    if (target.tagName.toLowerCase() !== "button" && !((target.type || "").toLowerCase() === "submit" && target.tagName.toLowerCase() === "input")) return;

    const form = target.form || target.closest("form");
    if (!form) return;
    const pwFields = Array.from(form.querySelectorAll("input[type='password']")).filter((f) => !f.hasAttribute("data-vela-ui"));
    if (!pwFields.length) return;

    const creds = velaCaptureFormCredentials(form);
    if (!creds) return;

    // The snapshot to compare against: which password fields hold the typed
    // value right now.
    const snapshot = pwFields.map((f) => f.value);
    const hrefAtClick = location.href;
    velaPendingCreds = { ...creds, at: Date.now() };

    setTimeout(() => {
      if (!velaPendingCreds || velaCredsKey(velaPendingCreds) !== velaCredsKey(creds)) return;
      if (location.href !== hrefAtClick) return; // already navigating; the stash path owns it
      const stillThere = pwFields.some((f, i) => f.isConnected && f.value === snapshot[i] && snapshot[i]);
      if (stillThere) return; // form is still sitting there; nothing submitted
      velaOfferCapture(creds);
      velaClearPendingCapture();
    }, 900);
  }

  /**
   * The tab is going away (real navigation or tab close). Park any typed
   * credentials with the background so the page the navigation lands on can
   * still offer to save them.
   *
   * The stash deliberately does NOT live in the page's sessionStorage: DOM
   * storage is shared with the page's own JavaScript, so a hostile page could
   * read a typed password straight out of it. `storage.session` in the
   * background is extension-private.
   */
  function velaStashPendingCapture() {
    if (!velaPendingCreds || !velaPendingCreds.password) return;
    try {
      sendExtensionMessage("stashPendingCapture", {
        url: location.href,
        at: Date.now(),
        creds: {
          username: velaPendingCreds.username,
          password: velaPendingCreds.password,
          isRegistration: velaPendingCreds.isRegistration
        }
      });
    } catch (_) {}
  }

  function velaOnVisibilityChange() {
    if (document.visibilityState === "hidden") {
      velaStashPendingCapture();
    }
  }

  /**
   * A new page just loaded in a tab whose previous page had typed credentials
   * it never submitted through a form. Ask the background for the tab's stash
   * and offer it here — same origin, so it is the login the user just
   * attempted (or abandoned; dismissible either way).
   */
  async function velaConsumeStashedCapture() {
    try {
      const response = await sendExtensionMessage("getPendingCapture", { url: location.href });
      if (response && response.success && response.creds && response.creds.password) {
        setTimeout(() => velaOfferCapture(response.creds), 600);
      }
    } catch (_) {}
  }

  // --- Save Bar ---

  function velaShowSaveBar(username, password, isRegistration) {
    velaHideSaveBar();
    const bar = document.createElement("div");
    bar.setAttribute("data-vela-ui", "true");
    bar.className = "vela-save-bar vela-autofill-animate-slide-up";
    bar.innerHTML = `
      <div class="vela-save-bar-inner">
        <span class="vela-save-bar-logo">${velaShieldSvg(18)}</span>
        <span class="vela-save-bar-text">
          <strong>${isRegistration ? "A new account. A place in your vault." : "Save this login to VELA?"}</strong><small>${velaEscapeHtml(velaExtractDomain(location.href))}${username ? " · " + velaEscapeHtml(username) : ""}</small>
        </span>
        <div class="vela-save-bar-actions">
          <button class="vela-save-bar-btn vela-save-bar-never" data-vela-action="never">Never for this site</button>
          <button class="vela-save-bar-btn vela-save-bar-dismiss" data-vela-action="dismiss">Not now</button>
          <button class="vela-save-bar-btn vela-save-bar-save" data-vela-action="save">Review & save</button>
        </div>
        <button class="vela-save-bar-close" data-vela-action="close" title="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>`;

    document.documentElement.appendChild(bar);
    velaSaveBarEl = bar;

    bar.querySelector("[data-vela-action='save']").addEventListener("click", () => {
      velaHideSaveBar();
      velaShowSaveDialog(username, password);
    });
    bar.querySelector("[data-vela-action='never']").addEventListener("click", () => {
      velaConfirmNeverSave();
    });
    bar.querySelector("[data-vela-action='dismiss']").addEventListener("click", velaHideSaveBar);
    bar.querySelector("[data-vela-action='close']").addEventListener("click", velaHideSaveBar);

    setTimeout(velaHideSaveBar, 20000);
  }

  // --- Update Bar ("password changed — update item?") ---

  /**
   * The submitted credentials match a saved login's username but not its
   * password — the user changed (or typo'd) it. Ask before overwriting: the
   * update replaces the stored password and never creates a duplicate.
   */
  function velaShowUpdateBar(login, creds) {
    velaHideSaveBar();
    const name = login.name || login.username || velaExtractDomain(location.href);
    const bar = document.createElement("div");
    bar.setAttribute("data-vela-ui", "true");
    bar.className = "vela-save-bar vela-autofill-animate-slide-up";
    bar.innerHTML = `
      <div class="vela-save-bar-inner">
        <span class="vela-save-bar-logo">${velaShieldSvg(18)}</span>
        <span class="vela-save-bar-text">
          <strong>A new password. Same account.</strong><small>${velaEscapeHtml(name)} · ${velaEscapeHtml(velaExtractDomain(location.href))}</small>
        </span>
        <div class="vela-save-bar-actions">
          <button class="vela-save-bar-btn vela-save-bar-dismiss" data-vela-action="dismiss">Not now</button>
          <button class="vela-save-bar-btn vela-save-bar-save" data-vela-action="update">Review update</button>
        </div>
        <button class="vela-save-bar-close" data-vela-action="close" title="Close">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>`;

    document.documentElement.appendChild(bar);
    velaSaveBarEl = bar;

    bar.querySelector("[data-vela-action='update']").addEventListener("click", () => {
      velaHideSaveBar();
      velaShowSaveDialog(creds.username, creds.password, login);
    });
    bar.querySelector("[data-vela-action='dismiss']").addEventListener("click", velaHideSaveBar);
    bar.querySelector("[data-vela-action='close']").addEventListener("click", velaHideSaveBar);

    setTimeout(velaHideSaveBar, 20000);
  }

  function velaHideSaveBar() {
    if (velaSaveBarEl) {
      velaSaveBarEl.remove();
      velaSaveBarEl = null;
    }
    // Whatever the prompt's fate (saved, dismissed, expired), the credentials
    // were offered once; do not let them resurface on the next page.
    velaClearPendingCapture();
  }

  function velaConfirmNeverSave() {
    const overlay=document.createElement("div");overlay.className="vela-overlay";overlay.setAttribute("data-vela-ui","true");
    overlay.innerHTML=`<div class="vela-modal"><div class="vela-modal-header"><h2 class="vela-modal-title">SITE PREFERENCE</h2><button class="vela-modal-close" aria-label="Close">${globalThis.VelaInstrument.icon("x")}</button></div><div class="vela-modal-intro">No more nudges here?</div><p class="vela-modal-subtitle">VELA will stop asking to save logins on ${velaEscapeHtml(velaExtractDomain(location.href))}. Your existing items and click-to-fill stay available.</p><div class="vela-modal-actions"><button class="vela-btn vela-btn-ghost" data-cancel>Cancel</button><button class="vela-btn vela-btn-primary" data-confirm>Turn off prompts</button></div></div>`;
    const close=()=>overlay.remove();overlay.querySelector(".vela-modal-close").onclick=close;overlay.querySelector("[data-cancel]").onclick=close;
    overlay.addEventListener("click",e=>{if(e.target===overlay)close();});
    overlay.querySelector("[data-confirm]").onclick=async()=>{const button=overlay.querySelector("[data-confirm]");button.disabled=true;try{await velaAddNeverSave(velaExtractDomain(location.href));velaHideSaveBar();close();velaShowToast("Save prompts turned off for this site.");}catch(_){button.disabled=false;velaShowToast("Could not save this preference. Try again.",true);}};
    document.documentElement.appendChild(overlay);velaPrepareModal(overlay);
  }

  // --- Save to Vault Dialog ---

  /**
   * `updateLogin` (optional) switches the dialog into update mode: the
   * credentials replace the given vault item instead of creating a new one.
   */
  function velaShowSaveDialog(username, password, updateLogin) {
    velaRemoveModal("vela-save-modal");
    const domain = velaExtractDomain(location.href);
    const isUpdate = Boolean(updateLogin && updateLogin.id);
    const overlay = document.createElement("div");
    overlay.setAttribute("data-vela-ui", "true");
    overlay.id = "vela-save-modal";
    overlay.className = "vela-overlay";
    overlay.innerHTML = `
      <div class="vela-modal vela-autofill-animate-slide-up">
        <div class="vela-modal-header">
          <div class="vela-modal-logo">${velaShieldSvg(20)}</div>
          <h2 class="vela-modal-title">${isUpdate ? "Update in VELA" : "Save to VELA"}</h2>
          <button class="vela-modal-close" data-vela-action="close" title="Close">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        ${isUpdate ? `
        <div class="vela-modal-site-badge">
          <span class="vela-modal-site-icon">${velaEscapeHtml((updateLogin.name || domain).charAt(0).toUpperCase())}</span>
          <span class="vela-modal-site-name">Updating ${velaEscapeHtml(updateLogin.name || domain)}</span>
        </div>` : `
        <div class="vela-modal-site-badge">
          <span class="vela-modal-site-icon">${domain.charAt(0).toUpperCase()}</span>
          <span class="vela-modal-site-name">${velaEscapeHtml(domain)}</span>
        </div>`}
        <div class="vela-save-fields">
          <div class="vela-save-field">
            <label class="vela-save-label">Name</label>
            <input class="vela-save-input" id="vela-save-name" data-vela-ui="true" type="text" value="${velaEscapeHtml(updateLogin ? (updateLogin.name || domain) : domain)}" placeholder="Login name"/>
          </div>
          <div class="vela-save-field">
            <label class="vela-save-label">Username / Email</label>
            <input class="vela-save-input" id="vela-save-username" data-vela-ui="true" type="text" value="${velaEscapeHtml(username || (updateLogin ? updateLogin.username : "") || "")}" placeholder="Enter username"/>
          </div>
          <div class="vela-save-field">
            <label class="vela-save-label">Password</label>
            <div class="vela-save-pw-wrap">
              <input class="vela-save-input" id="vela-save-password" data-vela-ui="true" type="password" value="${velaEscapeHtml(password || "")}" placeholder="Enter password"/>
              <button class="vela-save-pw-toggle" data-vela-action="toggle-pw" title="Show/hide password">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              </button>
              <button class="vela-save-pw-gen" data-vela-action="open-gen" title="Generate password">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L15.09 8.26L22 9.27L17 14.14L18.18 21.02L12 17.77L5.82 21.02L7 14.14L2 9.27L8.91 8.26L12 2Z"/></svg>
              </button>
            </div>
          </div>
        </div>
        <div class="vela-modal-actions">
          <button class="vela-btn vela-btn-ghost" data-vela-action="close">Cancel</button>
          <button class="vela-btn vela-btn-primary" data-vela-action="save">${isUpdate ? "Update Password" : "Save to Vault"}</button>
        </div>
      </div>`;

    document.documentElement.appendChild(overlay);
    velaPrepareModal(overlay);
    velaSaveModal = overlay;

    const close = () => { overlay.remove(); velaSaveModal = null; };

    overlay.querySelector("[data-vela-action='close']").addEventListener("click", close);
    overlay.querySelector(".vela-modal-close").addEventListener("click", close);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

    const pwInput = overlay.querySelector("#vela-save-password");
    overlay.querySelector("[data-vela-action='toggle-pw']").addEventListener("click", () => {
      pwInput.type = pwInput.type === "password" ? "text" : "password";
    });

    overlay.querySelector("[data-vela-action='open-gen']").addEventListener("click", () => {
      velaShowPasswordGenerator(null, (generated) => {
        pwInput.type = "text";
        pwInput.value = generated;
      });
    });

    overlay.querySelector("[data-vela-action='save']").addEventListener("click", async () => {
      const name = overlay.querySelector("#vela-save-name").value.trim();
      const user = overlay.querySelector("#vela-save-username").value.trim();
      const pw = overlay.querySelector("#vela-save-password").value;
      if (!pw) {
        overlay.querySelector("#vela-save-password").classList.add("vela-input-error");
        return;
      }
      const idleLabel = isUpdate ? "Update Password" : "Save to Vault";
      const saveBtn = overlay.querySelector("[data-vela-action='save']");
      saveBtn.disabled = true;
      saveBtn.textContent = isUpdate ? "Updating…" : "Saving…";
      try {
        const payload = {
          name: name || velaExtractDomain(location.href),
          username: user,
          password: pw,
          url: location.href
        };
        if (isUpdate) {
          payload.item_id = updateLogin.id;
        }
        const response = await sendExtensionMessage("saveCredentials", payload);
        if (response && response.success) {
          close();
          velaClearPendingCapture();
          velaShowToast(isUpdate ? "Password updated in VELA ✓" : "Saved to VELA vault ✓");
        } else {
          saveBtn.disabled = false;
          saveBtn.textContent = idleLabel;
          const reason = response && response.error ? response.error : "is VELA Desktop running?";
          velaShowToast(`Failed to ${isUpdate ? "update" : "save"} – ${reason}`, true);
        }
      } catch (_) {
        saveBtn.disabled = false;
        saveBtn.textContent = idleLabel;
        velaShowToast(`Failed to ${isUpdate ? "update" : "save"} – is VELA Desktop running?`, true);
      }
    });
  }

  // --- Password Generator ---

  function velaShowPasswordGenerator(targetField, onUseCb) {
    velaRemoveModal("vela-gen-modal");
    const opts = Object.assign({}, velaGenOptions);
    let currentPassword = velaGeneratePassword(opts);

    const overlay = document.createElement("div");
    overlay.setAttribute("data-vela-ui", "true");
    overlay.id = "vela-gen-modal";
    overlay.className = "vela-overlay";

    function renderModal() {
      // Clamped to the range the slider itself declares. `opts` is round-tripped
      // through storage, so treating its length as a number rather than trusting
      // it into an attribute keeps a corrupted value from reaching the markup.
      const sliderLength = Math.min(64, Math.max(8, Number(opts.length) || 20));
      overlay.innerHTML = `
        <div class="vela-modal vela-autofill-animate-slide-up vela-gen-modal">
          <div class="vela-modal-header">
            <div class="vela-modal-logo">${velaShieldSvg(20)}</div>
            <h2 class="vela-modal-title">Generate Password</h2>
            <button class="vela-modal-close" data-vela-action="close" title="Close">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>

          <div class="vela-modal-intro">Make it hard to guess.</div>
          <div class="vela-gen-preview-wrap">
            <div class="vela-gen-preview" id="vela-gen-preview">${velaEscapeHtml(currentPassword)}</div>
            <div class="vela-gen-preview-actions">
              <button class="vela-gen-icon-btn" data-vela-action="regenerate" title="Regenerate">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
              </button>
              <button class="vela-gen-icon-btn" data-vela-action="copy" title="Copy to clipboard">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
            </div>
          </div>

          <div class="vela-gen-strength" id="vela-gen-strength">
            ${velaStrengthBar(currentPassword)}
          </div>

          <div class="vela-gen-options">
            <div class="vela-gen-option-row vela-gen-length-row">
              <label class="vela-gen-option-label">Length</label>
              <div class="vela-gen-length-control">
                <input class="vela-gen-slider" id="vela-gen-length" data-vela-ui="true" type="range" min="8" max="64" value="${velaEscapeHtml(sliderLength)}" step="1"/>
                <span class="vela-gen-length-value" id="vela-gen-length-val">${velaEscapeHtml(sliderLength)}</span>
              </div>
            </div>

            <div class="vela-gen-option-row">
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="uppercase" aria-label="Uppercase letters" ${opts.uppercase ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>A–Z</span>
              </label>
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="lowercase" aria-label="Lowercase letters" ${opts.lowercase ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>a–z</span>
              </label>
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="numbers" aria-label="Numbers" ${opts.numbers ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>0–9</span>
              </label>
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="symbols" aria-label="Symbols" ${opts.symbols ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>!@#</span>
              </label>
            </div>
          </div>

          <div class="vela-gen-alias">
            <div class="vela-gen-divider"></div>
            <div class="vela-gen-alias-row">
              <div class="vela-gen-alias-info">
                <label class="vela-gen-option-label">Email alias</label>
                <span class="vela-gen-alias-hint" id="vela-gen-alias-hint">Hide your real address</span>
              </div>
              <button class="vela-btn vela-btn-ghost vela-gen-alias-btn" id="vela-gen-alias-btn">…</button>
            </div>
            <div class="vela-gen-alias-result" id="vela-gen-alias-result" hidden></div>
          </div>

          <div class="vela-modal-actions">
            <button class="vela-btn vela-btn-ghost" data-vela-action="close">Cancel</button>
            <button class="vela-btn vela-btn-primary" data-vela-action="use">Use this password</button>
          </div>
        </div>`;

      const close = () => { overlay.remove(); velaGenModal = null; };
      overlay.querySelector(".vela-modal-close").addEventListener("click", close);
      overlay.querySelectorAll("[data-vela-action='close']").forEach((b) => b.addEventListener("click", close));
      overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });

      const refresh = () => {
        currentPassword = velaGeneratePassword(opts);
        overlay.querySelector("#vela-gen-preview").textContent = currentPassword;
        globalThis.VelaInstrument.animateReadout(overlay.querySelector("#vela-gen-preview"));
        overlay.querySelector("#vela-gen-strength").innerHTML = velaStrengthBar(currentPassword);
      };

      overlay.querySelector("[data-vela-action='regenerate']").addEventListener("click", refresh);

      overlay.querySelector("[data-vela-action='copy']").addEventListener("click", () => {
        navigator.clipboard.writeText(currentPassword).catch(() => {});
        velaShowToast("Password copied!");
      });

      overlay.querySelector("#vela-gen-length").addEventListener("input", (e) => {
        opts.length = parseInt(e.target.value, 10);
        overlay.querySelector("#vela-gen-length-val").textContent = opts.length;
        refresh();
      });

      overlay.querySelectorAll(".vela-gen-checkbox").forEach((cb) => {
        cb.addEventListener("change", () => {
          opts[cb.dataset.opt] = cb.checked;
          if (!opts.uppercase && !opts.lowercase && !opts.numbers && !opts.symbols) {
            opts[cb.dataset.opt] = true;
            cb.checked = true;
          }
          velaGenOptions = Object.assign({}, opts);
          refresh();
        });
      });

      velaWireAliasRow(overlay, targetField);

      overlay.querySelector("[data-vela-action='use']").addEventListener("click", () => {
        velaGenOptions = Object.assign({}, opts);
        close();
        if (onUseCb) {
          onUseCb(currentPassword);
        } else if (targetField) {
          fillElement(targetField, currentPassword);
          targetField.type = "text";
          setTimeout(() => { targetField.type = "password"; }, 1500);
          setTimeout(() => {
            const form = targetField.form || targetField.closest("form");
            if (form) {
              const allInputs = Array.from(form.querySelectorAll("input:not([type='password']):not([type='hidden']):not([data-vela-ui])"));
              let user = "";
              for (const inp of allInputs) {
                if (inp.value) { user = inp.value; break; }
              }
              velaShowSaveBar(user, currentPassword, true);
            }
          }, 500);
        }
      });
    }

    renderModal();
    document.documentElement.appendChild(overlay);
    velaPrepareModal(overlay);
    velaGenModal = overlay;
  }

  // --- Generator: Email Alias Row (addy.io / SimpleLogin / Firefox Relay) ---

  /**
   * Populate and drive the generator's alias row.
   *
   * The provider never hears about the page: the background mints the alias
   * against the user's account, the site only ever sees the address string.
   * A click here must be human — a hostile page that could synthesize it
   * could drain the user's alias quota without a single visible prompt.
   */
  function velaWireAliasRow(overlay, targetField) {
    const hint = overlay.querySelector("#vela-gen-alias-hint");
    const btn = overlay.querySelector("#vela-gen-alias-btn");
    const result = overlay.querySelector("#vela-gen-alias-result");
    if (!hint || !btn || !result) return;

    const alive = () => overlay.isConnected && velaGenModal === overlay;

    // One listener, dispatched by mode — re-adding listeners per state
    // transition would stack handlers and mint two aliases on one click.
    let mode = "loading";
    let providerLabel = "";

    const setRow = (hintText, btnText, enabled) => {
      if (!alive()) return;
      hint.textContent = hintText;
      btn.textContent = btnText;
      btn.disabled = !enabled;
    };

    const showResult = (html) => {
      if (!alive()) return;
      result.hidden = !html;
      result.innerHTML = html || "";
    };

    const showAlias = (alias) => {
      showResult(`
        <span class="vela-gen-alias-value">${velaEscapeHtml(alias)}</span>
        <button class="vela-gen-icon-btn" data-vela-alias-copy title="Copy alias">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        </button>`);
      const copy = result.querySelector("[data-vela-alias-copy]");
      if (copy) {
        copy.addEventListener("click", () => {
          navigator.clipboard.writeText(alias).catch(() => {});
          velaShowToast("Alias copied!");
        });
      }
    };

    btn.addEventListener("click", async (e) => {
      if (!e.isTrusted) return;
      if (!alive() || btn.disabled) return;

      if (mode === "connect") {
        await sendExtensionMessage("openPopup");
        return;
      }

      if (mode !== "create") return;
      mode = "working";
      btn.disabled = true;
      btn.textContent = "Creating…";
      showResult("");
      const resp = await sendExtensionMessage("createEmailAlias", { url: location.href });
      if (!alive()) return;

      if (resp && resp.success && resp.alias) {
        showAlias(resp.alias);
        velaApplyAliasToPage(resp.alias, targetField);
        mode = "create";
        setRow(`Hide your real address with ${velaEscapeHtml(providerLabel)}`, "New alias", true);
      } else if (resp && resp.needsPermission) {
        mode = "connect";
        setRow(`VELA lost permission to reach ${velaEscapeHtml(providerLabel)} — reconnect it in the popup`, "Open popup", true);
      } else {
        showResult(`<span class="vela-gen-alias-error">${velaEscapeHtml(resp?.error || "Alias creation failed")}</span>`);
        mode = "create";
        setRow(`Hide your real address with ${velaEscapeHtml(providerLabel)}`, "Try again", true);
      }
    });

    sendExtensionMessage("getAliasProvider").then((provider) => {
      if (!alive()) return;
      if (!provider || !provider.configured) {
        mode = "connect";
        providerLabel = "";
        setRow("Connect addy.io, SimpleLogin or Firefox Relay in VELA's popup", "Connect", true);
        return;
      }
      mode = "create";
      providerLabel = provider.label;
      setRow(`Hide your real address with ${velaEscapeHtml(providerLabel)}`, `Create with ${providerLabel}`, true);
    }).catch(() => {
      mode = "create";
      providerLabel = "";
      setRow("Hide your real address", "Create", true);
    });
  }

  /**
   * Put the fresh alias where the user needs it: the username field of the
   * form being filled (so the capture prompt saves the alias as the login's
   * username), or the open save dialog when the generator was launched from
   * there.
   */
  function velaApplyAliasToPage(alias, targetField) {
    let filled = false;
    const form = targetField?.form || targetField?.closest("form");
    if (form) {
      const inputs = Array.from(form.querySelectorAll("input:not([type='password']):not([type='hidden']):not([data-vela-ui])"));
      const usable = (inp) => ["text", "email", "tel", "url"].includes((inp.type || "text").toLowerCase());
      // First pass: a field VELA would treat as the username. Second pass:
      // any empty text-ish input — bare `<input type="email">` with no name
      // or placeholder fails the heuristic but is still obviously it.
      for (const inp of inputs) {
        if (usable(inp) && velaIsAutofillable(inp)) {
          fillElement(inp, alias);
          filled = true;
          break;
        }
      }
      if (!filled) {
        for (const inp of inputs) {
          if (usable(inp) && !inp.value) {
            fillElement(inp, alias);
            filled = true;
            break;
          }
        }
      }
    }
    if (velaSaveModal) {
      const saveUser = velaSaveModal.querySelector("#vela-save-username");
      if (saveUser) {
        saveUser.value = alias;
        filled = true;
      }
    }
    if (filled) velaShowToast("Alias placed in the username field");
  }

  function velaGeneratePassword(opts) {
    const { length = 20, uppercase = true, lowercase = true, numbers = true, symbols = true } = opts;
    const sets = [];
    if (uppercase) sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (lowercase) sets.push("abcdefghijklmnopqrstuvwxyz");
    if (numbers) sets.push("0123456789");
    if (symbols) sets.push("!@#$%^&*()-_=+[]{}|;:,.< >?");

    const allChars = sets.join("") || "abcdefghijklmnopqrstuvwxyz";
    const buf = new Uint32Array(length + sets.length);
    crypto.getRandomValues(buf);

    const result = [];
    sets.forEach((set, i) => result.push(set[buf[i] % set.length]));

    for (let i = sets.length; i < length; i++) {
      result.push(allChars[buf[i] % allChars.length]);
    }

    const shuffle = new Uint32Array(result.length);
    crypto.getRandomValues(shuffle);
    for (let i = result.length - 1; i > 0; i--) {
      const j = shuffle[i] % (i + 1);
      [result[i], result[j]] = [result[j], result[i]];
    }

    return result.join("");
  }

  function velaStrengthBar(password) {
    let score = 0;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    const levels = [
      { max: 1, label: "Very weak", color: "var(--vela-error)" },
      { max: 2, label: "Weak", color: "var(--vela-error)" },
      { max: 3, label: "Fair", color: "var(--vela-violet)" },
      { max: 4, label: "Good", color: "var(--vela-signal)" },
      { max: 6, label: "Strong", color: "var(--vela-signal)" }
    ];
    const level = levels.find((l) => score <= l.max) || levels[levels.length - 1];
    const pct = Math.round((score / 6) * 100);
    return `
      <div class="vela-strength-bar-track">
        <div class="vela-strength-bar-fill" style="width:${pct}%;background:${level.color}"></div>
      </div>
      <span class="vela-strength-label" style="color:${level.color}">${level.label}</span>`;
  }

  // --- Never-save blocklist ---

  async function velaIsNeverSave(domain) {
    try { const data=await getBrowserAPI()?.storage.local.get("velaNeverSaveDomains");return Array.isArray(data?.velaNeverSaveDomains) && data.velaNeverSaveDomains.includes(domain); } catch (_) {return false;}
  }

  async function velaAddNeverSave(domain) {
    const api=getBrowserAPI(); if(!api)throw Error("Extension disconnected");
    const data=await api.storage.local.get("velaNeverSaveDomains");
    const domains=Array.isArray(data?.velaNeverSaveDomains)?data.velaNeverSaveDomains:[];
    if(!domains.includes(domain))await api.storage.local.set({velaNeverSaveDomains:[...domains,domain]});
  }

  // --- Helpers ---

  function velaCaptureCreds(field) {
    const form = field?.form || field?.closest("form");
    let pw = "";
    let user = "";
    if (form) {
      const pwField = form.querySelector("input[type='password']:not([data-vela-ui])");
      if (pwField) pw = pwField.value;
      const inputs = Array.from(form.querySelectorAll("input:not([type='password']):not([type='hidden']):not([data-vela-ui])"));
      for (const inp of inputs) {
        if (inp.value) { user = inp.value; break; }
      }
    }
    return { user, pw };
  }

  function velaExtractDomain(url) {
    try { return new URL(url).hostname; } catch (_) { return url; }
  }

  /// Escape for both text and attribute contexts.
  ///
  /// The `textContent`/`innerHTML` round trip this used to do escapes `&`, `<`
  /// and `>` but **not quotes**, and five call sites interpolate into attribute
  /// values — including the save prompt's username and password, which come
  /// straight from the page's form fields. A `"` in one of those broke out of
  /// the attribute and injected markup into VELA's own overlay (same defect as
  /// audit E-2, which was fixed in the popup but not here).
  function velaEscapeHtml(str) {
    return String(str ?? "").replace(
      /[&<>"']/g,
      (character) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[character],
    );
  }

  function velaRemoveModal(id) {
    const existing = document.getElementById(id);
    if (existing) existing.remove();
  }

  function velaShowToast(msg, isError = false) {
    const existing = document.querySelector(".vela-toast");
    if (existing) existing.remove();
    const toast = document.createElement("div");
    toast.setAttribute("data-vela-ui", "true");
    toast.className = "vela-toast" + (isError ? " vela-toast-error" : "");
    toast.textContent = msg;
    document.documentElement.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      setTimeout(() => toast.remove(), 300);
    }, 2500);
  }

  function velaShieldSvg(size) {
    return globalThis.VelaInstrument.mark();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
