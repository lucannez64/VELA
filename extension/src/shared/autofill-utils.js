(function () {
  "use strict";

  function getBrowserAPI() {
    if (typeof browser !== "undefined" && browser.runtime) return browser;
    if (typeof chrome !== "undefined" && chrome.runtime) return chrome;
    return null;
  }

  function sendExtensionMessage(command, options = {}) {
    const api = getBrowserAPI();
    if (!api || !api.runtime?.sendMessage) {
      return Promise.resolve(null);
    }
    return api.runtime.sendMessage({ command, ...options })
      .then((response) => response)
      .catch(() => null);
  }

  function setupExtensionDisconnectAction(callback) {
    const api = getBrowserAPI();
    if (!api) return;
    const port = api.runtime.connect({ name: "injected-script" });
    const onDisconnectCallback = (disconnectedPort) => {
      callback(disconnectedPort);
      port.onDisconnect.removeListener(onDisconnectCallback);
    };
    port.onDisconnect.addListener(onDisconnectCallback);
  }

  const AutoFillConstants = {
    EmailFieldNames: [
      "email",
      "email address",
      "e-mail",
      "e-mail address",
      "email adresse",
      "e-mail adresse"
    ],

    UsernameFieldNames: [
      "username",
      "user name",
      "userid",
      "user id",
      "customer id",
      "login id",
      "login",
      "benutzername",
      "benutzer name",
      "benutzerid",
      "benutzer id",
      "email",
      "email address",
      "e-mail",
      "e-mail address",
      "email adresse",
      "e-mail adresse"
    ],

    TotpFieldNames: [
      "totp",
      "totpcode",
      "2facode",
      "approvals_code",
      "mfacode",
      "otc-code",
      "onetimecode",
      "otp-code",
      "otpcode",
      "onetimepassword",
      "security_code",
      "second-factor",
      "twofactor",
      "twofa",
      "twofactorcode",
      "verificationcode",
      "verification code"
    ],

    RecoveryCodeFieldNames: ["backup", "recovery"],

    AmbiguousTotpFieldNames: ["code", "pin", "otc", "otp", "2fa", "mfa"],

    SearchFieldNames: ["search", "query", "find", "go"],

    FieldIgnoreList: ["captcha", "findanything", "forgot"],

    PasswordFieldExcludeList: [
      "hint",
      "captcha",
      "findanything",
      "forgot",
      "totp",
      "totpcode",
      "2facode",
      "approvals_code",
      "mfacode",
      "otc-code",
      "onetimecode",
      "otp-code",
      "otpcode",
      "onetimepassword",
      "security_code",
      "second-factor",
      "twofactor",
      "twofa",
      "twofactorcode",
      "verificationcode",
      "verification code"
    ],

    ExcludedAutofillLoginTypes: ["hidden", "file", "button", "image", "reset", "search"],

    ExcludedAutofillTypes: [
      "radio",
      "checkbox",
      "hidden",
      "file",
      "button",
      "image",
      "reset",
      "search"
    ],

    ExcludedInlineMenuTypes: ["textarea", "radio", "checkbox", "hidden", "file", "button", "image", "reset", "search"],

    FieldElements: ["input", "select", "textarea"],

    ExcludedIdentityAutocompleteTypes: new Set(["current-password", "new-password"])
  };

  const CreditCardAutoFillConstants = {
    CardAttributes: [
      "autoCompleteType",
      "data-stripe",
      "htmlName",
      "htmlID",
      "title",
      "label-tag",
      "placeholder",
      "label-left",
      "label-top",
      "data-recurly"
    ],

    CardAttributesExtended: [
      "autoCompleteType",
      "data-stripe",
      "htmlName",
      "htmlID",
      "title",
      "label-tag",
      "placeholder",
      "label-left",
      "label-top",
      "data-recurly",
      "label-right"
    ],

    CardHolderFieldNames: [
      "accountholdername",
      "cc-name",
      "card-name",
      "cardholder-name",
      "cardholder",
      "name",
      "nom"
    ],

    CardHolderFieldNameValues: [
      "accountholdername",
      "cc-name",
      "card-name",
      "cardholder-name",
      "cardholder",
      "tbName"
    ],

    CardNumberFieldNames: [
      "cc-number",
      "cc-num",
      "card-number",
      "card-num",
      "number",
      "cc",
      "cc-no",
      "card-no",
      "credit-card",
      "numero-carte",
      "carte",
      "carte-credit",
      "num-carte",
      "cb-num",
      "card-pan"
    ],

    CardNumberFieldNameValues: [
      "cc-number",
      "cc-num",
      "card-number",
      "card-num",
      "cc-no",
      "card-no",
      "numero-carte",
      "num-carte",
      "cb-num"
    ],

    CardExpiryFieldNames: [
      "cc-exp",
      "card-exp",
      "cc-expiration",
      "card-expiration",
      "cc-ex",
      "card-ex",
      "card-expire",
      "card-expiry",
      "validite",
      "expiration",
      "expiry",
      "mm-yy",
      "mm-yyyy",
      "yy-mm",
      "yyyy-mm",
      "expiration-date",
      "payment-card-expiration",
      "payment-cc-date"
    ],

    CardExpiryFieldNameValues: [
      "mm-yy",
      "mm-yyyy",
      "yy-mm",
      "yyyy-mm",
      "expiration-date",
      "payment-card-expiration"
    ],

    ExpiryMonthFieldNames: [
      "exp-month",
      "cc-exp-month",
      "cc-month",
      "card-month",
      "cc-mo",
      "card-mo",
      "exp-mo",
      "card-exp-mo",
      "cc-exp-mo",
      "card-expiration-month",
      "expiration-month",
      "cc-mm",
      "cc-m",
      "card-mm",
      "card-m",
      "card-exp-mm",
      "cc-exp-mm",
      "exp-mm",
      "exp-m",
      "expire-month",
      "expire-mo",
      "expiry-month",
      "expiry-mo",
      "card-expire-month",
      "card-expire-mo",
      "card-expiry-month",
      "card-expiry-mo",
      "mois-validite",
      "mois-expiration",
      "m-validite",
      "m-expiration",
      "expiry-date-field-month",
      "expiration-date-month",
      "expiration-date-mm",
      "exp-mon",
      "validity-mo",
      "exp-date-mo",
      "cb-date-mois",
      "date-m"
    ],

    ExpiryYearFieldNames: [
      "exp-year",
      "cc-exp-year",
      "cc-year",
      "card-year",
      "cc-yr",
      "card-yr",
      "exp-yr",
      "card-exp-yr",
      "cc-exp-yr",
      "card-expiration-year",
      "expiration-year",
      "cc-yy",
      "cc-y",
      "card-yy",
      "card-y",
      "card-exp-yy",
      "cc-exp-yy",
      "exp-yy",
      "exp-y",
      "cc-yyyy",
      "card-yyyy",
      "card-exp-yyyy",
      "cc-exp-yyyy",
      "expire-year",
      "expire-yr",
      "expiry-year",
      "expiry-yr",
      "card-expire-year",
      "card-expire-yr",
      "card-expiry-year",
      "card-expiry-yr",
      "an-validite",
      "an-expiration",
      "annee-validite",
      "annee-expiration",
      "expiry-date-field-year",
      "expiration-date-year",
      "cb-date-ann",
      "expiration-date-yy",
      "expiration-date-yyyy",
      "validity-year",
      "exp-date-year",
      "date-y"
    ],

    CVVFieldNames: [
      "cvv",
      "cvc",
      "cvv2",
      "cc-csc",
      "cc-cvv",
      "card-csc",
      "card-cvv",
      "cvd",
      "cid",
      "cvc2",
      "cnv",
      "cvn2",
      "cc-code",
      "card-code",
      "code-securite",
      "security-code",
      "crypto",
      "card-verif",
      "verification-code",
      "csc",
      "ccv"
    ],

    CardBrandFieldNames: ["cc-type", "card-type", "card-brand", "cc-brand", "cb-type"]
  };

  const IdentityAutoFillConstants = {
    IdentityAttributes: [
      "autoCompleteType",
      "data-stripe",
      "htmlName",
      "htmlID",
      "label-tag",
      "placeholder",
      "label-left",
      "label-top",
      "data-recurly",
      "accountCreationFieldType"
    ],

    FullNameFieldNames: ["name", "full-name", "your-name"],
    FullNameFieldNameValues: ["full-name", "your-name"],

    TitleFieldNames: ["honorific-prefix", "prefix", "title", "anrede"],

    FirstnameFieldNames: [
      "f-name",
      "first-name",
      "given-name",
      "first-n",
      "vorname"
    ],

    MiddlenameFieldNames: [
      "m-name",
      "middle-name",
      "additional-name",
      "middle-initial",
      "middle-n",
      "middle-i"
    ],

    LastnameFieldNames: [
      "l-name",
      "last-name",
      "s-name",
      "surname",
      "family-name",
      "family-n",
      "last-n",
      "nachname",
      "familienname"
    ],

    EmailFieldNames: ["e-mail", "email-address"],

    AddressFieldNames: [
      "address",
      "street-address",
      "addr",
      "street",
      "mailing-addr",
      "billing-addr",
      "mail-addr",
      "bill-addr",
      "strasse",
      "adresse"
    ],

    AddressFieldNameValues: [
      "mailing-addr",
      "billing-addr",
      "mail-addr",
      "bill-addr"
    ],

    Address1FieldNames: ["address-1", "address-line-1", "addr-1", "street-1"],
    Address2FieldNames: ["address-2", "address-line-2", "addr-2", "street-2", "address-ext"],
    Address3FieldNames: ["address-3", "address-line-3", "addr-3", "street-3"],

    PostalCodeFieldNames: [
      "postal",
      "zip",
      "zip2",
      "zip-code",
      "postal-code",
      "post-code",
      "postcode",
      "address-zip",
      "address-postal",
      "address-code",
      "address-postal-code",
      "address-zip-code",
      "plz",
      "postleitzahl"
    ],

    CityFieldNames: [
      "city",
      "town",
      "address-level-2",
      "address-city",
      "address-town",
      "ort",
      "stadt",
      "wohnort"
    ],

    StateFieldNames: [
      "state",
      "province",
      "provence",
      "address-level-1",
      "address-state",
      "address-province",
      "bundesland"
    ],

    CountryFieldNames: [
      "country",
      "country-code",
      "country-name",
      "address-country",
      "address-country-name",
      "address-country-code",
      "land"
    ],

    PhoneFieldNames: [
      "phone",
      "mobile",
      "mobile-phone",
      "tel",
      "telephone",
      "phone-number",
      "telefon",
      "telefonnummer",
      "mobil",
      "handy"
    ],

    UserNameFieldNames: ["user-name", "user-id", "screen-name"],

    CompanyFieldNames: [
      "company",
      "company-name",
      "organization",
      "organization-name",
      "firma"
    ]
  };

  const SubmitLoginButtonNames = [
    "login",
    "signin",
    "submit",
    "continue",
    "next",
    "verify"
  ];

  const SubmitChangePasswordButtonNames = [
    "change",
    "save",
    "savepassword",
    "updatepassword",
    "changepassword",
    "resetpassword"
  ];

  function generateRandomChars(length) {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    const randomChars = [];
    const randomBytes = new Uint8Array(length);
    crypto.getRandomValues(randomBytes);

    for (let byteIndex = 0; byteIndex < randomBytes.length; byteIndex++) {
      const byte = randomBytes[byteIndex];
      randomChars.push(chars[byte % chars.length]);
    }

    return randomChars.join("");
  }

  function generateRandomCustomElementName() {
    const length = Math.floor(Math.random() * 5) + 8;
    const numHyphens = Math.min(Math.max(Math.floor(Math.random() * 4), 1), length - 1);

    const hyphenIndices = [];
    while (hyphenIndices.length < numHyphens) {
      const index = Math.floor(Math.random() * (length - 1)) + 1;
      if (!hyphenIndices.includes(index)) {
        hyphenIndices.push(index);
      }
    }
    hyphenIndices.sort((a, b) => a - b);

    let randomString = "";
    let prevIndex = 0;

    for (let index = 0; index < hyphenIndices.length; index++) {
      const hyphenIndex = hyphenIndices[index];
      randomString = randomString + generateRandomChars(hyphenIndex - prevIndex) + "-";
      prevIndex = hyphenIndex;
    }

    randomString += generateRandomChars(length - prevIndex);

    return randomString;
  }

  /// Normalized site key: lowercase host with a leading `www.` and any
  /// trailing dot removed. Used to key per-site settings. Not a registrable
  /// domain (the extension has no public-suffix list); a subdomain simply has
  /// its own row, which is predictable.
  function siteKey(value) {
    if (!value) return "";
    let host = String(value).trim().toLowerCase();
    if (host.includes("://")) {
      try {
        host = new URL(host).hostname;
      } catch (e) {
        return "";
      }
    }
    host = host.replace(/^\.+|\.+$/g, "");
    if (host.startsWith("www.")) host = host.slice(4);
    if (!host || /\s/.test(host)) return "";
    return host;
  }

  // ── IDN / homograph detection ─────────────────────────────────────────────
  //
  // The classic lookalike attack is a punycode (`xn--`) label whose decoded
  // form mixes scripts — `аpple.com` with a Cyrillic `а`. The desktop never
  // autofills a domain that is not the registrable domain it stored, so a
  // lookalike simply gets no matches; this only tells the user *why* nothing
  // was offered, and warns on a site that pretends to be another.

  const PUNYCODE_BASE = 36;
  const PUNYCODE_TMIN = 1;
  const PUNYCODE_TMAX = 26;
  const PUNYCODE_SKEW = 38;
  const PUNYCODE_DAMP = 700;
  const PUNYCODE_INITIAL_BIAS = 72;
  const PUNYCODE_INITIAL_N = 128;

  function punycodeBasicToDigit(code) {
    if (code >= 48 && code <= 57) return code - 22; // 0-9 → 26-35
    if (code >= 65 && code <= 90) return code - 65; // A-Z → 0-25
    if (code >= 97 && code <= 122) return code - 97; // a-z → 0-25
    return PUNYCODE_BASE;
  }

  function punycodeAdapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / PUNYCODE_DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    for (
      ;
      delta > ((PUNYCODE_BASE - 1) * PUNYCODE_TMAX) >> 1;
      k += PUNYCODE_BASE
    ) {
      delta = Math.floor(delta / (PUNYCODE_BASE - 1));
    }
    return Math.floor(
      k + ((PUNYCODE_BASE - 1 + 1) * delta) / (delta + PUNYCODE_SKEW)
    );
  }

  /// RFC 3492 decoder for one label (without the `xn--` prefix). Returns null
  /// on malformed input rather than throwing.
  function punycodeDecode(input) {
    try {
      const output = [];
      const length = input.length;
      let i = 0;
      let n = PUNYCODE_INITIAL_N;
      let bias = PUNYCODE_INITIAL_BIAS;
      const basic = input.lastIndexOf("-");
      let index = 0;
      for (let j = 0; j < (basic < 0 ? 0 : basic); j++) {
        if (input.charCodeAt(j) >= 0x80) return null;
        output.push(input.charCodeAt(j));
      }
      index = basic < 0 ? 0 : basic + 1;
      while (index < length) {
        const oldi = i;
        let w = 1;
        for (let k = PUNYCODE_BASE; ; k += PUNYCODE_BASE) {
          if (index >= length) return null;
          const digit = punycodeBasicToDigit(input.charCodeAt(index++));
          if (digit >= PUNYCODE_BASE) return null;
          i += digit * w;
          const t =
            k <= bias
              ? PUNYCODE_TMIN
              : k >= bias + PUNYCODE_TMAX
                ? PUNYCODE_TMAX
                : k - bias;
          if (digit < t) break;
          w *= PUNYCODE_BASE - t;
        }
        const outLength = output.length + 1;
        bias = punycodeAdapt(i - oldi, outLength, oldi === 0);
        n += Math.floor(i / outLength);
        i %= outLength;
        output.splice(i++, 0, n);
      }
      return String.fromCodePoint.apply(null, output);
    } catch (e) {
      return null;
    }
  }

  function charScript(codePoint) {
    const ch = String.fromCodePoint(codePoint);
    if (/\p{Script=Latin}/u.test(ch)) return "Latin";
    if (/\p{Script=Cyrillic}/u.test(ch)) return "Cyrillic";
    if (/\p{Script=Greek}/u.test(ch)) return "Greek";
    if (/\p{Script=Hebrew}/u.test(ch)) return "Hebrew";
    if (/\p{Script=Arabic}/u.test(ch)) return "Arabic";
    if (/\p{Script=Han}/u.test(ch)) return "Han";
    if (/\p{Script=Hiragana}/u.test(ch)) return "Hiragana";
    if (/\p{Script=Katakana}/u.test(ch)) return "Katakana";
    if (/\p{Script=Hangul}/u.test(ch)) return "Hangul";
    return "Other";
  }

  /// Assess a hostname for lookalike risk. Returns
  /// `{ level, reasons, unicode }` where level is "warn" when the host uses a
  /// punycode label or mixes scripts.
  function hostRisk(hostname) {
    const host = String(hostname || "").toLowerCase();
    const reasons = [];
    let unicode = host;
    if (!host) return { level: "none", reasons, unicode };

    const labels = host.split(".");
    const decodedLabels = [];
    for (const label of labels) {
      if (!label.startsWith("xn--")) {
        decodedLabels.push(label);
        continue;
      }
      reasons.push("punycode");
      const decoded = punycodeDecode(label.slice(4));
      decodedLabels.push(decoded || label);
    }
    unicode = decodedLabels.join(".");

    // Mixed-script detection over the decoded host. A Latin base with any
    // other letter script is the homograph signature.
    const scripts = new Set();
    for (const ch of unicode) {
      if (/\p{L}/u.test(ch)) scripts.add(charScript(ch.codePointAt(0)));
    }
    const nonLatin = [...scripts].filter((s) => s !== "Latin" && s !== "Other");
    if (scripts.has("Latin") && nonLatin.length > 0) {
      reasons.push("mixed-script");
    }

    // Only mixed-script is a warning. A single-script punycode label is a
    // legitimate internationalized domain (münchen.de, 日本.jp) and flagging
    // every one would train users to ignore the warning.
    const unique = [...new Set(reasons)];
    return {
      level: unique.includes("mixed-script") ? "warn" : "none",
      reasons: unique,
      unicode
    };
  }

  function fieldIsFuzzyMatch(field, checkOptions) {
    if (!field || !checkOptions || !checkOptions.length) {
      return false;
    }

    const fuzzyCriteria = [
      field.htmlName,
      field.htmlId,
      field.title,
      field["label-tag"],
      field["data-stripe"],
      field.placeholder,
      field["label-left"],
      field["label-top"]
    ].filter(Boolean);

    for (const criteria of fuzzyCriteria) {
      const normalizedCriteria = criteria.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
      for (const option of checkOptions) {
        const normalizedOption = option.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
        if (normalizedCriteria.includes(normalizedOption) || normalizedOption.includes(normalizedCriteria)) {
          return true;
        }
      }
    }

    return false;
  }

  function isFieldMatch(value, names, nameValues) {
    if (!value) {
      return false;
    }

    const normalizedValue = value.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();

    for (const name of names) {
      const normalizedName = name.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
      if (normalizedValue === normalizedName) {
        return true;
      }
    }

    if (nameValues && nameValues.length) {
      for (const nameValue of nameValues) {
        const normalizedNameValue = nameValue.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
        if (normalizedValue === normalizedNameValue) {
          return true;
        }
      }
    }

    return false;
  }

  function nodeIsElement(node) {
    if (!node) {
      return false;
    }
    return node?.nodeType === Node.ELEMENT_NODE;
  }

  function elementIsInputElement(element) {
    return nodeIsElement(element) && element.tagName.toLowerCase() === "input";
  }

  function elementIsSelectElement(element) {
    return nodeIsElement(element) && element.tagName.toLowerCase() === "select";
  }

  function elementIsTextAreaElement(element) {
    return nodeIsElement(element) && element.tagName.toLowerCase() === "textarea";
  }

  function elementIsFormElement(element) {
    return nodeIsElement(element) && element.tagName.toLowerCase() === "form";
  }

  function elementIsSpanElement(element) {
    return nodeIsElement(element) && element.tagName.toLowerCase() === "span";
  }

  function elementIsLabelElement(element) {
    return nodeIsElement(element) && element.tagName.toLowerCase() === "label";
  }

  function nodeIsFormElement(node) {
    return nodeIsElement(node) && elementIsFormElement(node);
  }

  function getPropertyOrAttribute(element, attributeName) {
    if (attributeName in element) {
      return element[attributeName] ?? null;
    }
    return element.getAttribute(attributeName);
  }

  function getAttributeBoolean(element, attributeName, checkString = false) {
    if (checkString) {
      return getPropertyOrAttribute(element, attributeName) === "true";
    }
    return Boolean(getPropertyOrAttribute(element, attributeName));
  }

  function getSubmitButtonKeywordsSet(element) {
    const keywords = [
      element.textContent,
      element.getAttribute("type"),
      element.getAttribute("value"),
      element.getAttribute("aria-label"),
      element.getAttribute("aria-labelledby"),
      element.getAttribute("aria-describedby"),
      element.getAttribute("title"),
      element.getAttribute("id"),
      element.getAttribute("name"),
      element.getAttribute("class")
    ];

    const keywordsSet = new Set();
    for (let i = 0; i < keywords.length; i++) {
      const keyword = keywords[i];
      if (typeof keyword === "string") {
        keyword
          .toLowerCase()
          .replace(/[-\s]/g, "")
          .split(/[^\p{L}]+/gu)
          .forEach((splitKeyword) => {
            if (splitKeyword) {
              keywordsSet.add(splitKeyword);
            }
          });
      }
    }

    return keywordsSet;
  }

  function throttle(callback, limit) {
    let waitingDelay = false;
    return function (...args) {
      if (waitingDelay) {
        return;
      }
      callback.apply(this, args);
      waitingDelay = true;
      setTimeout(() => (waitingDelay = false), limit);
    };
  }

  function debounce(callback, delay, immediate = false) {
    let timeout = null;

    return function (...args) {
      const callImmediately = !!immediate && !timeout;

      if (timeout) {
        clearTimeout(timeout);
      }
      timeout = setTimeout(() => {
        timeout = null;
        if (!callImmediately) {
          callback.apply(this, args);
        }
      }, delay);

      if (callImmediately) {
        callback.apply(this, args);
      }
    };
  }

  if (typeof globalThis !== "undefined") {
    globalThis.VelaAutofill = {
      AutoFillConstants,
      CreditCardAutoFillConstants,
      IdentityAutoFillConstants,
      SubmitLoginButtonNames,
      SubmitChangePasswordButtonNames,
      generateRandomChars,
      generateRandomCustomElementName,
      siteKey,
      hostRisk,
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
      setupExtensionDisconnectAction
    };
  }
})();
