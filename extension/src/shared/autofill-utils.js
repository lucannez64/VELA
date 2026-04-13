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

  function generateDomainMatchPatterns(url) {
    try {
      const extensionUrlPattern = /^(chrome|chrome-extension|moz-extension|safari-web-extension):\/\/\/?/;
      if (extensionUrlPattern.test(url)) {
        return [];
      }

      const urlPattern = /^(https?|file):\/\/\/?/;
      if (!urlPattern.test(url)) {
        url = `https://${url}`;
      }

      let protocolGlob = "*://";
      if (url.startsWith("file:///")) {
        protocolGlob = "*:///";
      }

      const parsedUrl = new URL(url);
      const originMatchPattern = `${protocolGlob}${parsedUrl.hostname}/*`;

      const splitHost = parsedUrl.hostname.split(".");
      const domain = splitHost.slice(-2).join(".");
      const subDomainMatchPattern = `${protocolGlob}*.${domain}/*`;

      return [originMatchPattern, subDomainMatchPattern];
    } catch {
      return [];
    }
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
      generateDomainMatchPatterns,
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
