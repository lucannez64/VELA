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
    generateRandomCustomElementName
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
  let velaFieldIconEl = null;
  let velaSaveBarEl = null;
  let velaCurrentLogins = null;
  let velaRequiresBiometric = false;
  let velaLoginRequestPromise = null;
  let velaLoginRequestKey = "";
  let velaCapturedCredentials = null;
  let velaGenModal = null;
  let velaSaveModal = null;
  let velaGenOptions = { length: 20, uppercase: true, lowercase: true, numbers: true, symbols: true };
  let velaSelectedIndex = -1;
  let velaHoveredField = null;

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
      }
    };

    api.runtime.onMessage.addListener(handleMessage);
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
      if (fillScript) performFill(fillScript);
    } else {
      velaShowAccountPickerModal(logins);
    }
  }

  async function fillWithLogin(login) {
    const details = await collectPageDetails();
    if (!details) return;
    const fillScript = generateFillScript(details, login);
    if (fillScript) performFill(fillScript);
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
        let element = document.querySelector(`[data-opid="${op.opid}"]`) || document.querySelector(`[opid="${op.opid}"]`);
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
        const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
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
          element.dispatchEvent(new Event("change", { bubbles: true }));
          break;
        }
      }
    }
    element.blur();
  }

  async function getLoginsForPage(url) {
    try {
      const response = await sendExtensionMessage("getLogins", { url });
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
      if (active && velaDropdownEl.contains(active)) return;
      if (active && active === velaActiveField) return;
      velaHideDropdown();
    }, 200);
  }

  function velaOnMouseOver(e) {
    const el = e.target;
    if (!velaIsAutofillable(el)) return;
    if (velaActiveField === el) return;
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

  function velaOnKeyDown(e) {
    if (e.key === "Escape" && velaDropdownEl) {
      e.stopPropagation();
      velaHideDropdown();
      return;
    }

    if (!velaDropdownEl) return;

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
          items[velaSelectedIndex].click();
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
      if (i === velaSelectedIndex) {
        item.scrollIntoView({ block: "nearest" });
      }
    });
  }

  function velaOnDocClick(e) {
    if (!velaDropdownEl) return;
    const t = e.target;
    if (t && t.hasAttribute("data-vela-ui")) return;
    if (!velaDropdownEl.contains(t) && t !== velaActiveField && t !== velaFieldIconEl) {
      velaHideDropdown();
    }
  }

  function velaRepositionDropdown() {
    if (velaDropdownEl && velaActiveField) velaPositionDropdown(velaActiveField);
  }

  // --- Field Icon ---

  function velaInjectFieldIcon(field) {
    velaRemoveFieldIcon();
    const icon = document.createElement("button");
    icon.setAttribute("data-vela-ui", "true");
    icon.setAttribute("type", "button");
    icon.setAttribute("tabindex", "-1");
    icon.setAttribute("title", "VELA – autofill");
    icon.className = "vela-field-icon";
    icon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7l-9-5z" fill="currentColor"/></svg>`;

    icon.addEventListener("mousedown", (e) => {
      e.preventDefault();
      if (velaDropdownEl) {
        velaHideDropdown();
      } else {
        velaActiveField = field;
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

    const rect = field.getBoundingClientRect();
    const scrollX = window.scrollX || window.pageXOffset;
    const scrollY = window.scrollY || window.pageYOffset;
    icon.style.position = "absolute";
    icon.style.top = (rect.top + scrollY + (rect.height - 24) / 2) + "px";
    icon.style.left = (rect.right + scrollX - 30) + "px";
    icon.style.zIndex = "2147483646";

    document.documentElement.appendChild(icon);
    velaFieldIconEl = icon;
  }

  function velaRemoveFieldIcon() {
    if (velaFieldIconEl) {
      velaFieldIconEl.remove();
      velaFieldIconEl = null;
    }
  }

  // --- Dropdown ---

  function velaShowDropdown(field, logins, isNewPassword) {
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
          <span class="vela-dd-action-icon">🔒</span>
          Open VELA Desktop
        </button>`;
    } else if (isNewPassword) {
      dd.innerHTML = `
        <div class="vela-dd-header">
          <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
          <span class="vela-dd-title">VELA</span>
        </div>
        <button class="vela-dd-action-btn" data-vela-action="generate-password">
          <span class="vela-dd-action-icon">🔑</span>
          Generate strong password
        </button>
        ${logins && logins.length > 0 ? `
        <div class="vela-dd-divider"></div>
        <div class="vela-dd-section-label">Or fill existing login</div>
        ${velaLoginListItems(logins)}` : ""}
        <div class="vela-dd-divider"></div>
        <button class="vela-dd-action-btn" data-vela-action="save-new">
          <span class="vela-dd-action-icon">＋</span>
          Save new account to VELA
        </button>`;
    } else if (logins && logins.length > 0) {
      dd.innerHTML = `
        <div class="vela-dd-header">
          <span class="vela-dd-logo">${velaShieldSvg(14)}</span>
          <span class="vela-dd-title">VELA – ${velaExtractDomain(location.href)}</span>
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
          <span class="vela-dd-action-icon">＋</span>
          Add to VELA vault
        </button>`;
    }

    document.documentElement.appendChild(dd);
    velaDropdownEl = dd;
    velaSelectedIndex = -1;
    velaPositionDropdown(field);

    dd.querySelectorAll("[data-vela-login-id]").forEach((item) => {
      item.addEventListener("click", async () => {
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

  function velaPositionDropdown(field) {
    if (!velaDropdownEl || !field) return;
    const rect = field.getBoundingClientRect();
    const scrollX = window.scrollX || window.pageXOffset;
    const scrollY = window.scrollY || window.pageYOffset;
    const ddWidth = Math.max(rect.width, 260);

    let left = rect.left + scrollX;
    const maxLeft = scrollX + window.innerWidth - ddWidth - 8;
    if (left > maxLeft) left = maxLeft;
    if (left < scrollX + 8) left = scrollX + 8;

    velaDropdownEl.style.position = "absolute";
    velaDropdownEl.style.top = (rect.bottom + scrollY + 4) + "px";
    velaDropdownEl.style.left = left + "px";
    velaDropdownEl.style.width = ddWidth + "px";
    velaDropdownEl.style.zIndex = "2147483647";
  }

  function velaHideDropdown() {
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

    const pwFields = Array.from(form.querySelectorAll("input[type='password']")).filter((f) => !f.hasAttribute("data-vela-ui"));
    if (!pwFields.length) return;

    const pwValue = pwFields[0].value;
    if (!pwValue) return;

    const allInputs = Array.from(form.querySelectorAll("input:not([type='password']):not([type='hidden']):not([data-vela-ui])"));
    let userValue = "";
    for (const inp of allInputs) {
      const type = (inp.type || "text").toLowerCase();
      if (!["text", "email", "tel", "url"].includes(type)) continue;
      if (inp.value) { userValue = inp.value; break; }
    }

    const isRegistration = pwFields.length >= 2;
    const creds = { username: userValue, password: pwValue, isRegistration };

    const domain = velaExtractDomain(location.href);
    Promise.all([
      getLoginsForPage(location.href),
      velaIsNeverSave(domain)
    ]).then(([logins, neverSave]) => {
      if (neverSave) return;
      const alreadySaved = logins.some((l) => l.username === creds.username);
      if (!alreadySaved) {
        setTimeout(() => velaShowSaveBar(creds.username, creds.password, creds.isRegistration), 100);
      }
    });
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
          ${isRegistration ? "Save new account" : "Save login"} to VELA?
        </span>
        <div class="vela-save-bar-actions">
          <button class="vela-save-bar-btn vela-save-bar-never" data-vela-action="never">Never</button>
          <button class="vela-save-bar-btn vela-save-bar-dismiss" data-vela-action="dismiss">Not now</button>
          <button class="vela-save-bar-btn vela-save-bar-save" data-vela-action="save">Save</button>
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
      velaHideSaveBar();
      velaAddNeverSave(velaExtractDomain(location.href));
      velaShowToast("VELA will never ask to save for this site.");
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
  }

  // --- Save to Vault Dialog ---

  function velaShowSaveDialog(username, password) {
    velaRemoveModal("vela-save-modal");
    const domain = velaExtractDomain(location.href);
    const overlay = document.createElement("div");
    overlay.setAttribute("data-vela-ui", "true");
    overlay.id = "vela-save-modal";
    overlay.className = "vela-overlay";
    overlay.innerHTML = `
      <div class="vela-modal vela-autofill-animate-slide-up">
        <div class="vela-modal-header">
          <div class="vela-modal-logo">${velaShieldSvg(20)}</div>
          <h2 class="vela-modal-title">Save to VELA</h2>
          <button class="vela-modal-close" data-vela-action="close" title="Close">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
        <div class="vela-modal-site-badge">
          <span class="vela-modal-site-icon">${domain.charAt(0).toUpperCase()}</span>
          <span class="vela-modal-site-name">${velaEscapeHtml(domain)}</span>
        </div>
        <div class="vela-save-fields">
          <div class="vela-save-field">
            <label class="vela-save-label">Name</label>
            <input class="vela-save-input" id="vela-save-name" data-vela-ui="true" type="text" value="${velaEscapeHtml(domain)}" placeholder="Login name"/>
          </div>
          <div class="vela-save-field">
            <label class="vela-save-label">Username / Email</label>
            <input class="vela-save-input" id="vela-save-username" data-vela-ui="true" type="text" value="${velaEscapeHtml(username || "")}" placeholder="Enter username"/>
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
          <button class="vela-btn vela-btn-primary" data-vela-action="save">Save to Vault</button>
        </div>
      </div>`;

    document.documentElement.appendChild(overlay);
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
      const saveBtn = overlay.querySelector("[data-vela-action='save']");
      saveBtn.disabled = true;
      saveBtn.textContent = "Saving…";
      try {
        const response = await sendExtensionMessage("saveCredentials", {
          name: name || velaExtractDomain(location.href),
          username: user,
          password: pw,
          url: location.href
        });
        if (response && response.success) {
          close();
          velaShowToast("Saved to VELA vault ✓");
        } else {
          saveBtn.disabled = false;
          saveBtn.textContent = "Save to Vault";
          const reason = response && response.error ? response.error : "is VELA Desktop running?";
          velaShowToast(`Failed to save – ${reason}`, true);
        }
      } catch (_) {
        saveBtn.disabled = false;
        saveBtn.textContent = "Save to Vault";
        velaShowToast("Failed to save – is VELA Desktop running?", true);
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
      overlay.innerHTML = `
        <div class="vela-modal vela-autofill-animate-slide-up vela-gen-modal">
          <div class="vela-modal-header">
            <div class="vela-modal-logo">${velaShieldSvg(20)}</div>
            <h2 class="vela-modal-title">Generate Password</h2>
            <button class="vela-modal-close" data-vela-action="close" title="Close">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
          </div>

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
                <input class="vela-gen-slider" id="vela-gen-length" data-vela-ui="true" type="range" min="8" max="64" value="${opts.length}" step="1"/>
                <span class="vela-gen-length-value" id="vela-gen-length-val">${opts.length}</span>
              </div>
            </div>

            <div class="vela-gen-option-row">
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="uppercase" ${opts.uppercase ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>Uppercase (A-Z)</span>
              </label>
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="lowercase" ${opts.lowercase ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>Lowercase (a-z)</span>
              </label>
            </div>
            <div class="vela-gen-option-row">
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="numbers" ${opts.numbers ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>Numbers (0-9)</span>
              </label>
              <label class="vela-gen-toggle-label">
                <input class="vela-gen-checkbox" data-vela-ui="true" type="checkbox" data-opt="symbols" ${opts.symbols ? "checked" : ""}/>
                <span class="vela-gen-checkbox-custom"></span>
                <span>Symbols (!@#…)</span>
              </label>
            </div>
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
    velaGenModal = overlay;
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
      { max: 1, label: "Very weak", color: "#ef4444" },
      { max: 2, label: "Weak", color: "#f97316" },
      { max: 3, label: "Fair", color: "#eab308" },
      { max: 4, label: "Good", color: "#22c55e" },
      { max: 6, label: "Strong", color: "#10b981" }
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

  function velaIsNeverSave(domain) {
    const api = getBrowserAPI();
    if (!api) return Promise.resolve(false);

    return new Promise((resolve) => {
      try {
        api.storage.local.get("velaNeverSaveDomains", (data) => {
          const domains = (data && data.velaNeverSaveDomains) || [];
          resolve(domains.includes(domain));
        });
      } catch (_) {
        resolve(false);
      }
    });
  }

  function velaAddNeverSave(domain) {
    const api = getBrowserAPI();
    if (!api) return;

    try {
      api.storage.local.get("velaNeverSaveDomains", (data) => {
        const domains = (data && data.velaNeverSaveDomains) || [];
        if (!domains.includes(domain)) {
          domains.push(domain);
          api.storage.local.set({ velaNeverSaveDomains: domains });
        }
      });
    } catch (_) {}
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

  function velaEscapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str);
    return div.innerHTML;
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
    return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7l-9-5z" fill="currentColor"/></svg>`;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
