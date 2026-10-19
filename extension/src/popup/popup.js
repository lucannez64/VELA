const { runtime, tabs } = browser;
const { siteKey, hostRisk } = globalThis.VelaAutofill || {};

const mainContent = document.getElementById("mainContent");
const statusIndicator = document.getElementById("statusIndicator");
const statusText = document.getElementById("statusText");
const loadingSpinner = document.getElementById("loadingSpinner");
const openVaultBtn = document.getElementById("openVaultBtn");
const settingsBtn = document.getElementById("settingsBtn");

const aliasSection = document.getElementById("aliasSection");
const aliasToggle = document.getElementById("aliasToggle");
const aliasBadge = document.getElementById("aliasBadge");
const aliasBody = document.getElementById("aliasBody");
const aliasProvider = document.getElementById("aliasProvider");
const aliasConfigRows = document.getElementById("aliasConfigRows");
const aliasActions = document.getElementById("aliasActions");
const aliasKeyLabel = document.getElementById("aliasKeyLabel");
const aliasKey = document.getElementById("aliasKey");
const aliasKeyHint = document.getElementById("aliasKeyHint");
const aliasBase = document.getElementById("aliasBase");
const aliasSave = document.getElementById("aliasSave");
const aliasDisconnect = document.getElementById("aliasDisconnect");
const aliasStatus = document.getElementById("aliasStatus");

const genSection = document.getElementById("genSection");
const genToggle = document.getElementById("genToggle");
const genBadge = document.getElementById("genBadge");
const genBody = document.getElementById("genBody");
const genOutput = document.getElementById("genOutput");
const genStrengthFill = document.getElementById("genStrengthFill");
const genStrengthLabel = document.getElementById("genStrengthLabel");
const genModeRandom = document.getElementById("genModeRandom");
const genModePassphrase = document.getElementById("genModePassphrase");
const genRegenerate = document.getElementById("genRegenerate");
const genCopy = document.getElementById("genCopy");
const genLength = document.getElementById("genLength");
const genLengthVal = document.getElementById("genLengthVal");
const genWords = document.getElementById("genWords");
const genWordsVal = document.getElementById("genWordsVal");
const genSeparator = document.getElementById("genSeparator");
const genUpper = document.getElementById("genUpper");
const genLower = document.getElementById("genLower");
const genNumbers = document.getElementById("genNumbers");
const genSymbols = document.getElementById("genSymbols");
const genAvoidAmbiguous = document.getElementById("genAvoidAmbiguous");
const genCapitalize = document.getElementById("genCapitalize");
const genIncludeNumber = document.getElementById("genIncludeNumber");
const genRandomOptions = document.getElementById("genRandomOptions");
const genPassphraseOptions = document.getElementById("genPassphraseOptions");
const genHistoryEl = document.getElementById("genHistory");
const genHistoryList = document.getElementById("genHistoryList");

const siteSection = document.getElementById("siteSection");
const siteToggle = document.getElementById("siteToggle");
const siteBadge = document.getElementById("siteBadge");
const siteBody = document.getElementById("siteBody");
const siteAutoFill = document.getElementById("siteAutoFill");
const siteNeverAutofill = document.getElementById("siteNeverAutofill");
const siteNeverSave = document.getElementById("siteNeverSave");
const siteStatus = document.getElementById("siteStatus");
const phishWarning = document.getElementById("phishWarning");
const phishWarningText = document.getElementById("phishWarningText");

let currentTabUrl = null;
let availableLogins = [];
let inCoreLoginCandidates = [];
let totpPopupTimer = null;

async function init() {
  await checkDesktopConnection();
  await getCurrentTab();
  await loadInCoreLoginCandidates();
  await loadLogins();
  setupEventListeners();
  setupSiteSettings();
  renderPhishWarning();
}

function setupEventListeners() {
  openVaultBtn.addEventListener("click", () => {
    sendMessage({ command: "openVault" });
  });

  settingsBtn.addEventListener("click", () => {
    sendMessage({ command: "openSettings" });
  });

  setupAliasSettings();
  setupGenerator();
}

// ── Email alias settings ────────────────────────────────────────────────────
//
// Tokens live in `storage.local` and the per-provider host permission is
// requested here, from the popup, while the connect click is still a user
// gesture — the background cannot ask on its own (service workers have no
// user gesture), and the generator on a web page must never be the place an
// API token is typed: the page's own JavaScript can read anything in the
// page DOM, including VELA's injected overlays.

const ALIAS_PROVIDER_META = {
  addyio: { label: "addy.io", defaultBase: "https://app.addy.io", keyLabel: "API token", keyHint: "addy.io → Settings → API → create a token" },
  simplelogin: { label: "SimpleLogin", defaultBase: "https://app.simplelogin.io", keyLabel: "API key", keyHint: "SimpleLogin → Settings → API keys" },
  relay: { label: "Firefox Relay", defaultBase: "https://relay.firefox.com", keyLabel: "API token", keyHint: "relay.firefox.com → Settings → generate an API token" }
};
const ALIAS_CONFIG_KEY = "velaAliasConfig";

function setupAliasSettings() {
  aliasToggle.addEventListener("click", () => {
    const open = aliasBody.hidden;
    aliasBody.hidden = !open;
    aliasSection.classList.toggle("open", open);
  });

  aliasProvider.addEventListener("change", () => {
    const meta = ALIAS_PROVIDER_META[aliasProvider.value];
    aliasConfigRows.hidden = !meta;
    aliasActions.hidden = !meta;
    if (meta) {
      aliasKeyLabel.textContent = meta.keyLabel;
      aliasKey.placeholder = meta.keyLabel;
      aliasKeyHint.textContent = meta.keyHint;
      aliasBase.placeholder = `Official server (${meta.defaultBase})`;
    }
    setAliasStatus("");
  });

  aliasSave.addEventListener("click", saveAliasProvider);
  aliasDisconnect.addEventListener("click", clearAliasProvider);

  loadAliasConfig();
}

async function loadAliasConfig() {
  try {
    const data = await browser.storage.local.get(ALIAS_CONFIG_KEY);
    const config = data[ALIAS_CONFIG_KEY];
    if (config && config.provider) {
      aliasProvider.value = config.provider;
      aliasProvider.dispatchEvent(new Event("change"));
      aliasSave.textContent = "Save";
      setAliasStatus(`Connected to ${ALIAS_PROVIDER_META[config.provider].label}`, "ok");
      aliasBadge.textContent = ALIAS_PROVIDER_META[config.provider].label;
      aliasBadge.classList.add("connected");
    }
  } catch (e) {
    console.log("[VELA Popup] alias config load failed:", e.message);
  }
}

async function saveAliasProvider() {
  const provider = aliasProvider.value;
  const meta = ALIAS_PROVIDER_META[provider];
  const apiKey = aliasKey.value.trim();
  if (!meta || !apiKey) {
    setAliasStatus("Enter your API token first.", "err");
    return;
  }

  const baseUrl = (aliasBase.value.trim().replace(/\/+$/, "")) || meta.defaultBase;
  let origin;
  try {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "https:") throw new Error("not https");
    origin = parsed.origin;
  } catch (_) {
    setAliasStatus("The server URL must be a valid https:// address.", "err");
    return;
  }

  aliasSave.disabled = true;
  try {
    // Hold the provider origin only, only once, and only because the user
    // just asked for it. Reversible in this popup or in the browser's own
    // permissions UI.
    const granted = await browser.permissions.request({ origins: [`${origin}/*`] });
    if (!granted) {
      setAliasStatus("Permission to reach the provider was refused.", "err");
      return;
    }
    await browser.storage.local.set({
      [ALIAS_CONFIG_KEY]: { provider, apiKey, baseUrl: origin }
    });
    aliasKey.value = "";
    aliasSave.textContent = "Save";
    setAliasStatus(`Connected to ${meta.label}. Create aliases from the password generator.`, "ok");
    aliasBadge.textContent = meta.label;
    aliasBadge.classList.add("connected");
  } catch (e) {
    setAliasStatus(`Could not connect: ${e.message}`, "err");
  } finally {
    aliasSave.disabled = false;
  }
}

async function clearAliasProvider() {
  try {
    await browser.storage.local.remove(ALIAS_CONFIG_KEY);
    aliasProvider.value = "";
    aliasProvider.dispatchEvent(new Event("change"));
    aliasSave.textContent = "Connect";
    aliasBadge.textContent = "Off";
    aliasBadge.classList.remove("connected");
    setAliasStatus("Provider disconnected.", "ok");
  } catch (e) {
    setAliasStatus(`Could not disconnect: ${e.message}`, "err");
  }
}

function setAliasStatus(message, kind = "") {
  aliasStatus.textContent = message;
  aliasStatus.className = `alias-status${kind ? ` ${kind}` : ""}`;
}

// ── Password generator ──────────────────────────────────────────────────────
//
// Two modes: a random string (charset/length controls, optional look-alike
// exclusion) and a Diceware-style passphrase over the bundled EFF word list.
// Options persist in `storage.local`; the recent values live only for the
// browser session. Generation runs entirely here — nothing is sent anywhere.

const GENERATOR_OPTIONS_KEY = "velaGeneratorOptions";
const GENERATOR_HISTORY_KEY = "velaGeneratorHistory";
const GENERATOR_HISTORY_MAX = 5;

const GEN_SETS = {
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower: "abcdefghijklmnopqrstuvwxyz",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{}|;:,.<>?"
};
const GEN_AMBIGUOUS = /[O0oIl1|`'"~;:.,]/g;

let genOptions = {
  mode: "random",
  length: 20,
  upper: true,
  lower: true,
  numbers: true,
  symbols: true,
  avoidAmbiguous: false,
  words: 5,
  separator: "-",
  capitalize: false,
  includeNumber: false
};
let genHistory = [];

function setupGenerator() {
  genToggle.addEventListener("click", () => {
    const open = genBody.hidden;
    genBody.hidden = !open;
    genSection.classList.toggle("open", open);
  });

  genModeRandom.addEventListener("click", () => setGenMode("random"));
  genModePassphrase.addEventListener("click", () => setGenMode("passphrase"));
  genRegenerate.addEventListener("click", regenerate);
  genCopy.addEventListener("click", () => {
    if (genOutput.textContent) {
      copyToClipboard(genOutput.textContent);
      showNotification("Password copied!");
    }
  });

  genLength.addEventListener("input", () => {
    genOptions.length = Number(genLength.value);
    genLengthVal.textContent = String(genOptions.length);
    regenerate();
  });
  genWords.addEventListener("input", () => {
    genOptions.words = Number(genWords.value);
    genWordsVal.textContent = String(genOptions.words);
    regenerate();
  });
  genSeparator.addEventListener("change", () => {
    genOptions.separator = genSeparator.value;
    regenerate();
  });
  for (const [element, key] of [
    [genUpper, "upper"],
    [genLower, "lower"],
    [genNumbers, "numbers"],
    [genSymbols, "symbols"],
    [genAvoidAmbiguous, "avoidAmbiguous"],
    [genCapitalize, "capitalize"],
    [genIncludeNumber, "includeNumber"]
  ]) {
    element.addEventListener("change", () => {
      genOptions[key] = element.checked;
      regenerate();
    });
  }

  loadGeneratorState();
}

async function loadGeneratorState() {
  try {
    const data = await browser.storage.local.get(GENERATOR_OPTIONS_KEY);
    if (data[GENERATOR_OPTIONS_KEY]) {
      genOptions = { ...genOptions, ...data[GENERATOR_OPTIONS_KEY] };
    }
  } catch (e) {}
  try {
    const saved = await browser.storage.session?.get(GENERATOR_HISTORY_KEY);
    if (saved && Array.isArray(saved[GENERATOR_HISTORY_KEY])) {
      genHistory = saved[GENERATOR_HISTORY_KEY];
    }
  } catch (e) {}
  applyGeneratorOptionsToUI();
  regenerate();
}

function persistGeneratorOptions() {
  try {
    browser.storage.local.set({ [GENERATOR_OPTIONS_KEY]: genOptions });
  } catch (e) {}
}

function applyGeneratorOptionsToUI() {
  genLength.value = String(genOptions.length);
  genLengthVal.textContent = String(genOptions.length);
  genWords.value = String(genOptions.words);
  genWordsVal.textContent = String(genOptions.words);
  genUpper.checked = genOptions.upper;
  genLower.checked = genOptions.lower;
  genNumbers.checked = genOptions.numbers;
  genSymbols.checked = genOptions.symbols;
  genAvoidAmbiguous.checked = genOptions.avoidAmbiguous;
  genCapitalize.checked = genOptions.capitalize;
  genIncludeNumber.checked = genOptions.includeNumber;
  genSeparator.value = genOptions.separator;
  setGenMode(genOptions.mode, false);
}

function setGenMode(mode, regenerateNow = true) {
  genOptions.mode = mode === "passphrase" ? "passphrase" : "random";
  genModeRandom.classList.toggle("active", genOptions.mode === "random");
  genModePassphrase.classList.toggle("active", genOptions.mode === "passphrase");
  genRandomOptions.hidden = genOptions.mode !== "random";
  genPassphraseOptions.hidden = genOptions.mode !== "passphrase";
  genBadge.textContent = genOptions.mode === "passphrase" ? "Passphrase" : "Random";
  if (regenerateNow) {
    persistGeneratorOptions();
    regenerate();
  }
}

// Uniform index in [0, max) via 32-bit rejection sampling, so no modulo bias.
function randomIndex(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);
  let value;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % max;
}

function pickFrom(characters) {
  return characters.charAt(randomIndex(characters.length));
}

function generateRandom() {
  const enabled = [];
  if (genOptions.upper) enabled.push(GEN_SETS.upper);
  if (genOptions.lower) enabled.push(GEN_SETS.lower);
  if (genOptions.numbers) enabled.push(GEN_SETS.numbers);
  if (genOptions.symbols) enabled.push(GEN_SETS.symbols);
  if (!enabled.length) enabled.push(GEN_SETS.lower);

  const pools = enabled
    .map((set) => (genOptions.avoidAmbiguous ? set.replace(GEN_AMBIGUOUS, "") : set))
    .filter((set) => set.length > 0);
  const pool = pools.join("");
  const length = Math.max(4, genOptions.length);

  const characters = [];
  // Guarantee at least one character from each enabled set, then fill.
  for (const set of pools) characters.push(pickFrom(set));
  while (characters.length < length) characters.push(pickFrom(pool));
  // Fisher-Yates with crypto randomness so the guaranteed characters are not
  // always at the front.
  for (let i = characters.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [characters[i], characters[j]] = [characters[j], characters[i]];
  }

  const value = characters.slice(0, length).join("");
  return { value, bits: length * Math.log2(pool.length) };
}

function generatePassphrase() {
  const list = globalThis.VELA_WORDLIST || [];
  if (!list.length) return { value: "", bits: 0 };
  const count = Math.max(2, genOptions.words);
  const separator = genOptions.separator || "-";

  const words = [];
  for (let i = 0; i < count; i++) {
    let word = list[randomIndex(list.length)];
    if (genOptions.capitalize) {
      word = word.charAt(0).toUpperCase() + word.slice(1);
    }
    words.push(word);
  }
  if (genOptions.includeNumber) {
    const index = randomIndex(words.length);
    words[index] += String(randomIndex(10));
  }

  let bits = count * Math.log2(list.length);
  if (genOptions.includeNumber) bits += Math.log2(10 * count);
  return { value: words.join(separator), bits };
}

function regenerate() {
  const result = genOptions.mode === "passphrase" ? generatePassphrase() : generateRandom();
  genOutput.textContent = result.value;
  updateStrength(result.bits);
  persistGeneratorOptions();
  pushHistory(result.value);
}

function updateStrength(bits) {
  let percent;
  let label;
  let color;
  if (bits < 40) {
    percent = 25;
    label = "Weak";
    color = "#ffb4ab";
  } else if (bits < 60) {
    percent = 50;
    label = "Fair";
    color = "#ffd28a";
  } else if (bits < 80) {
    percent = 75;
    label = "Good";
    color = "#73db9a";
  } else {
    percent = 100;
    label = "Strong";
    color = "#73db9a";
  }
  genStrengthFill.style.width = `${percent}%`;
  genStrengthFill.style.background = color;
  genStrengthLabel.textContent = `${label} · ${Math.round(bits)} bits`;
}

function pushHistory(value) {
  if (!value) return;
  genHistory = [value, ...genHistory.filter((entry) => entry !== value)].slice(
    0,
    GENERATOR_HISTORY_MAX
  );
  try {
    browser.storage.session?.set({ [GENERATOR_HISTORY_KEY]: genHistory });
  } catch (e) {}
  renderHistory();
}

function renderHistory() {
  if (!genHistory.length) {
    genHistoryEl.hidden = true;
    return;
  }
  genHistoryEl.hidden = false;
  genHistoryList.innerHTML = genHistory
    .map(
      (value) => `
        <div class="gen-history-item" data-value="${escapeHtml(value)}" title="Copy">
          <span>${escapeHtml(value)}</span>
          <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor"><path d="M8 3a2 2 0 00-2 2v8a2 2 0 002 2h6a2 2 0 002-2V5a2 2 0 00-2-2H8z"/><path d="M4 7a2 2 0 00-2 2v8a2 2 0 002 2h6a2 2 0 002-2v-1H8a3 3 0 01-3-3V7H4z"/></svg>
        </div>`
    )
    .join("");
  genHistoryList.querySelectorAll(".gen-history-item").forEach((element) => {
    element.addEventListener("click", () => {
      copyToClipboard(element.dataset.value);
      showNotification("Password copied!");
    });
  });
}

// ── Per-site autofill settings + lookalike warning ──────────────────────────
//
// Autofill preferences are keyed by the normalized host (no `www.`) so they
// match the content script's `siteKey`. The never-save blocklist keeps the
// raw hostname, which is what the content script has always used.

const SITE_SETTINGS_KEY = "velaSiteSettings";
const NEVER_SAVE_KEY = "velaNeverSaveDomains";
let currentSiteKey = "";

function currentHostname() {
  if (!currentTabUrl) return "";
  try {
    return new URL(currentTabUrl).hostname;
  } catch (e) {
    return "";
  }
}

function setupSiteSettings() {
  siteToggle.addEventListener("click", () => {
    const open = siteBody.hidden;
    siteBody.hidden = !open;
    siteSection.classList.toggle("open", open);
  });
  siteAutoFill.addEventListener("change", () =>
    updateSiteSettings({ autoFillOnLoad: siteAutoFill.checked })
  );
  siteNeverAutofill.addEventListener("change", () =>
    updateSiteSettings({ neverAutofill: siteNeverAutofill.checked })
  );
  siteNeverSave.addEventListener("change", updateNeverSave);
  loadSiteSettings();
}

function renderPhishWarning() {
  if (!hostRisk) {
    phishWarning.hidden = true;
    return;
  }
  const host = currentHostname();
  const risk = host ? hostRisk(host) : { level: "none" };
  if (risk.level !== "warn") {
    phishWarning.hidden = true;
    return;
  }
  phishWarningText.textContent =
    risk.unicode && risk.unicode !== host
      ? `This site's address mixes writing systems and may be impersonating another. It decodes to ${risk.unicode}.`
      : "This site's address mixes writing systems and may be impersonating another.";
  phishWarning.hidden = false;
}

async function loadSiteSettings() {
  currentSiteKey = siteKey ? siteKey(currentTabUrl) : "";
  if (!currentSiteKey) {
    siteSection.hidden = true;
    return;
  }
  siteSection.hidden = false;
  siteBadge.textContent = currentSiteKey;
  try {
    const data = await browser.storage.local.get([SITE_SETTINGS_KEY, NEVER_SAVE_KEY]);
    const all = data[SITE_SETTINGS_KEY] || {};
    const site = all[currentSiteKey] || {};
    siteAutoFill.checked = site.autoFillOnLoad === true;
    siteNeverAutofill.checked = site.neverAutofill === true;
    const neverSave = data[NEVER_SAVE_KEY] || [];
    siteNeverSave.checked = Array.isArray(neverSave) && neverSave.includes(currentHostname());
  } catch (e) {
    setSiteStatus("Could not load site settings.", "err");
  }
}

async function updateSiteSettings(patch) {
  if (!currentSiteKey) return;
  try {
    const data = await browser.storage.local.get(SITE_SETTINGS_KEY);
    const all = data[SITE_SETTINGS_KEY] || {};
    all[currentSiteKey] = { ...(all[currentSiteKey] || {}), ...patch };
    await browser.storage.local.set({ [SITE_SETTINGS_KEY]: all });
    notifyActiveTab();
    setSiteStatus(patch.neverAutofill ? "Autofill disabled for this site." : "Saved.", "ok");
  } catch (e) {
    setSiteStatus("Could not save.", "err");
  }
}

async function updateNeverSave() {
  const host = currentHostname();
  if (!host) return;
  try {
    const data = await browser.storage.local.get(NEVER_SAVE_KEY);
    let list = Array.isArray(data[NEVER_SAVE_KEY]) ? data[NEVER_SAVE_KEY] : [];
    if (siteNeverSave.checked) {
      if (!list.includes(host)) list = [...list, host];
    } else {
      list = list.filter((domain) => domain !== host);
    }
    await browser.storage.local.set({ [NEVER_SAVE_KEY]: list });
    notifyActiveTab();
    setSiteStatus(siteNeverSave.checked ? "Will not prompt to save here." : "Saved.", "ok");
  } catch (e) {
    setSiteStatus("Could not save.", "err");
  }
}

function notifyActiveTab() {
  tabs
    .query({ active: true, currentWindow: true })
    .then((found) => {
      if (found && found[0] && found[0].id) {
        tabs.sendMessage(found[0].id, { command: "siteSettingsChanged" }).catch(() => {});
      }
    })
    .catch(() => {});
}

function setSiteStatus(message, kind = "") {
  siteStatus.textContent = message;
  siteStatus.className = `alias-status${kind ? ` ${kind}` : ""}`;
}

async function checkDesktopConnection() {
  try {
    const response = await sendMessage({ command: "checkDesktopConnection" });
    console.log("[VELA Popup] Connection response:", JSON.stringify(response));
    if (response && response.connected) {
      setConnectedStatus();
    } else {
      setDisconnectedStatus("Desktop app not connected");
    }
  } catch (e) {
    console.log("[VELA Popup] Connection error:", e);
    setDisconnectedStatus("Connection failed");
  }
}

function setConnectedStatus() {
  statusIndicator.classList.remove("disconnected");
  statusIndicator.classList.add("connected");
  statusText.textContent = "Connected to VELA Desktop";
}

function setDisconnectedStatus(reason = "Desktop app not connected") {
  statusIndicator.classList.remove("connected");
  statusIndicator.classList.add("disconnected");
  statusText.textContent = reason;
}

function retryConnection() {
  setDisconnectedStatus("Retrying...");
  setTimeout(() => {
    checkDesktopConnection();
  }, 500);
}

async function getCurrentTab() {
  try {
    const queryTabs = await tabs.query({ active: true, currentWindow: true });
    if (queryTabs && queryTabs.length > 0) {
      currentTabUrl = queryTabs[0].url;
    }
  } catch (e) {
    currentTabUrl = null;
  }
}

async function loadLogins() {
  if (!currentTabUrl) {
    showEmptyState("No active tab", "Navigate to a website to see saved logins.");
    return;
  }

  try {
    const response = await sendMessage({
      command: "getAvailableLogins",
      url: currentTabUrl,
      userInitiated: true
    });

    if (response && response.logins && response.logins.length > 0) {
      availableLogins = response.logins;
      renderLogins();
    } else if (response && response.ignored) {
      showEmptyState("Unsupported page", "VELA autofill works on HTTP and HTTPS websites.");
    } else if (response && response.requires_biometric) {
      showApprovalRequiredState();
    } else {
      showNoLoginsState();
    }
  } catch (e) {
    showEmptyState("Error loading logins", e.message || "Could not load logins from desktop app.");
  }
}

/// Shown when the desktop would not release a plaintext password.
///
/// The in-core login section is rendered here too, and this is the case it was
/// built for: a machine that will not hand over the password can still sign the
/// user in, because that path never needed the password released in the first
/// place.
function showApprovalRequiredState() {
  mainContent.innerHTML = `
    ${renderInCoreLoginSection()}
    <div class="empty-state">
      <svg class="empty-state-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M10 1a4 4 0 00-4 4v2H5a2 2 0 00-2 2v7a2 2 0 002 2h10a2 2 0 002-2V9a2 2 0 00-2-2h-1V5a4 4 0 00-4-4zm2 6V5a2 2 0 10-4 0v2h4z" clip-rule="evenodd" />
      </svg>
      <div class="empty-state-title">Unlock VELA Desktop</div>
      <div class="empty-state-text" style="margin-bottom:14px;">Open VELA Desktop and unlock your vault, then retry.</div>
      <button id="openDesktopBtn" style="
        display:inline-flex;align-items:center;gap:6px;
        padding:8px 18px;
        background:linear-gradient(135deg,#73db9a 0%,#1c8f56 100%);
        color:#00391d;
        border:none;border-radius:10px;cursor:pointer;
        font-size:13px;font-weight:600;font-family:inherit;
      ">
        Open VELA Desktop
      </button>
      <button id="retryLoginsBtn" style="
        display:inline-flex;align-items:center;gap:6px;
        margin-left:8px;padding:8px 18px;
        background:transparent;color:#73db9a;
        border:1px solid rgba(115,219,154,0.45);border-radius:10px;cursor:pointer;
        font-size:13px;font-weight:600;font-family:inherit;
      ">
        Retry
      </button>
    </div>
  `;

  wireInCoreLoginSection();

  const openBtn = mainContent.querySelector("#openDesktopBtn");
  if (openBtn) {
    openBtn.addEventListener("click", async () => {
      await sendMessage({ command: "openVault" });
      window.close();
    });
  }

  const retryBtn = mainContent.querySelector("#retryLoginsBtn");
  if (retryBtn) {
    retryBtn.addEventListener("click", () => {
      mainContent.innerHTML = `<div class="empty-state"><div class="empty-state-title">Loading...</div></div>`;
      loadLogins();
    });
  }
}

function renderLogins() {
  if (!availableLogins || availableLogins.length === 0) {
    showEmptyState("No logins found", "No saved logins for this website.");
    return;
  }

  const loginsHtml = availableLogins.map((login) => {
    const name = login.name || extractDomain(login.url) || "Unknown";
    const initial = name.charAt(0).toUpperCase();
    const domain = login.url ? extractDomain(login.url) : "";
    const totpButton = login.totp
      ? `<button class="icon-btn" title="Authenticator code" data-action="totp" data-login-id="${escapeHtml(login.id || "")}">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M10 2a8 8 0 100 16 8 8 0 000-16zM9 6a1 1 0 112 0v4a1 1 0 01-.293.707l-2.5 2.5a1 1 0 01-1.414-1.414L9 9.586V6z" clip-rule="evenodd" />
            </svg>
          </button>`
      : "";

    return `
      <li class="login-item" data-login-id="${escapeHtml(login.id || "")}">
        <div class="login-icon">${escapeHtml(initial)}</div>
        <div class="login-info">
          <div class="login-name">${escapeHtml(name)}</div>
          <div class="login-url">${escapeHtml(domain)}</div>
        </div>
        <div class="login-actions">
          <button class="icon-btn" title="Copy Username" data-action="copy-username" data-login-id="${escapeHtml(login.id || "")}">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
            </svg>
          </button>
          <button class="icon-btn" title="Copy Password" data-action="copy-password" data-login-id="${escapeHtml(login.id || "")}">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
            </svg>
          </button>
          ${totpButton}
          <button class="icon-btn" title="Auto-fill" data-action="autofill" data-login-id="${escapeHtml(login.id || "")}">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>
      </li>
    `;
  }).join("");

  mainContent.innerHTML = `
    ${renderInCoreLoginSection()}
    <div class="section-title">Logins for this page</div>
    <ul class="login-list">
      ${loginsHtml}
    </ul>
  `;

  wireInCoreLoginSection();

  const loginItems = mainContent.querySelectorAll(".login-item");
  loginItems.forEach((item) => {
    item.addEventListener("click", (e) => {
      const action = e.target.closest("[data-action]")?.dataset.action;
      const loginId = e.target.closest("[data-login-id]")?.dataset.loginId;
      if (action && loginId) {
        handleLoginAction(action, loginId);
      }
    });
  });
}

// ── In-core login (M9a) ──────────────────────────────────────────────────────
//
// The button below does something different from "Auto-fill": the password is
// never sent to the page. VELA Desktop signs in over its own connection and the
// browser receives only the session cookies. What that is worth depends on the
// site — a session expires and can be revoked where a password does neither,
// but at a site that lets a session change the account password it is not much
// weaker than the password itself. The desktop says which case applies and the
// toast repeats it, because the user is the only one who can act on it.

async function loadInCoreLoginCandidates() {
  if (!currentTabUrl) {
    return;
  }
  try {
    const response = await sendMessage({ command: "inCoreLoginCandidates" });
    inCoreLoginCandidates = response?.candidates || [];
  } catch (e) {
    inCoreLoginCandidates = [];
  }
}

function renderInCoreLoginSection() {
  if (inCoreLoginCandidates.length === 0) {
    return "";
  }

  const buttons = inCoreLoginCandidates
    .map((candidate) => {
      const who = candidate.username || candidate.name || "this account";
      // Said before the click, not after. This item permits answering a
      // security-key prompt with a TOTP code, and somebody about to press the
      // button is the person who should know that.
      const downgrades = candidate.allow_second_factor_downgrade
        ? `<span style="display:block;margin-top:4px;font-size:11px;opacity:0.85;">
             ⚠ May answer a security-key prompt with your authenticator code
           </span>`
        : "";
      // A site whose login is a recipe gated by a captcha: the human has to
      // solve it on the page, and VELA picks the token up from there. Named
      // as such, so the click is not a surprise and the flow is understood.
      const captchaMode = candidate.login_mode === "recipe_captcha";
      const label = captchaMode
        ? `Solve the captcha, then sign in as ${escapeHtml(who)}`
        : `Sign in as ${escapeHtml(who)} without filling the password`;
      return `
        <button class="in-core-login-btn" data-item-id="${escapeHtml(candidate.item_id || "")}"
                data-login-mode="${escapeHtml(candidate.login_mode || "form")}"
                style="display:block;width:100%;text-align:left;margin-bottom:6px;padding:8px 12px;
                       background:#2a2d2e;color:#e2e2e5;border:1px solid #444748;border-radius:10px;
                       font-size:12px;cursor:pointer;">
          ${label}
          ${downgrades}
        </button>`;
    })
    .join("");

  return `
    <div class="section-title">Sign in from VELA</div>
    <div style="padding:0 12px 10px;">
      ${buttons}
      <div style="font-size:11px;opacity:0.7;line-height:1.4;">
        VELA Desktop signs in over its own connection. The page receives a
        session, never your password.
        ${inCoreLoginCandidates.some((c) => c.login_mode === "recipe_captcha")
          ? " For captcha-protected sites, solve the captcha in the tab and VELA finishes the sign-in."
          : ""}
        Some sites are signed in through a disposable browser window VELA opens
        and closes on its own.
      </div>
    </div>
  `;
}

function wireInCoreLoginSection() {
  mainContent.querySelectorAll(".in-core-login-btn").forEach((button) => {
    button.addEventListener("click", () => startInCoreLogin(button));
  });
}

async function startInCoreLogin(button) {
  const itemId = button.dataset.itemId;
  const mode = button.dataset.loginMode || "form";
  if (!itemId) {
    return;
  }
  button.disabled = true;
  button.textContent = "Waiting for your approval in VELA Desktop…";

  try {
    // The cookie permission is optional and asked for here, on a click, for one
    // origin: `permissions.request` needs a user gesture, and the popup is the
    // only place in this flow that has one. Being able to write cookies for
    // every site the user visits is not something the extension should hold
    // just in case.
    if (!(await ensureCookiePermission())) {
      showNotification("VELA needs permission to set cookies for this site");
      button.disabled = false;
      button.textContent = "Sign in without filling the password";
      return;
    }

    const response = await sendMessage({ command: "inCoreLogin", itemId, mode });
    if (!response?.success) {
      showNotification(response?.error || "Sign-in failed");
      button.disabled = false;
      button.textContent = "Sign in without filling the password";
      return;
    }

    // A captcha-gated recipe: the token can only be minted by a human solving
    // the widget on the page, which means the popup has to get out of the way.
    // Tell them what to do and close; the background finishes the sign-in.
    if (response.waitingForCaptcha) {
      showNotification(
        "Complete the captcha on the page — VELA will finish the sign-in automatically."
      );
      setTimeout(() => window.close(), 2800);
      return;
    }

    // Three outcomes, and they must not be blurred together. The site can
    // still be holding a gate no vault can open — a security key, a push —
    // in which case the password was accepted, the tab has been taken to the
    // challenge, and the user finishes by hand. Calling that "signed in" is
    // the bug the first real GitHub run exposed.
    if (response.awaitingSecondFactor) {
      showNotification(
        `Password accepted. Finish with ${response.awaitingSecondFactor}.`
      );
    } else if (response.looksAuthenticated) {
      // A disposable browser window was used for this login (bot-walled
      // sites). Say so, and that a second factor may have needed finishing
      // there.
      const browserNote = response.usedBrowser
        ? " (a VELA browser window opened to complete it)"
        : "";
      showNotification(
        (response.secondFactorDowngraded
          ? "Signed in using your authenticator code instead of the security key this site asked for."
          : response.residualNote || "Signed in.") + browserNote
      );
    } else {
      showNotification("VELA sent the sign-in, but the site did not clearly accept it.");
    }
    setTimeout(() => window.close(), 3200);
  } catch (e) {
    showNotification(e.message || "Sign-in failed");
    button.disabled = false;
    button.textContent = "Sign in without filling the password";
  }
}

function ensureCookiePermission() {
  const origin = new URL(currentTabUrl).origin + "/*";
  const request = { permissions: ["cookies"], origins: [origin] };
  // `permissions.request` must run inside the click's user gesture. Awaiting
  // `contains` first can drop that gesture on some Chromium builds (the error
  // "permissions.request may only be called from a user input handler").
  // Calling `request` directly is safe: it resolves immediately when the
  // permission is already held, and only prompts when it is not.
  return browser.permissions.request(request);
}

function handleLoginAction(action, loginId) {
  const login = availableLogins.find((l) => String(l.id) === loginId);
  if (!login) {
    return;
  }

  switch (action) {
    case "copy-username":
      if (login.username) {
        copyToClipboard(login.username);
        showNotification("Username copied!");
      }
      break;
    case "copy-password":
      if (login.password) {
        copyToClipboard(login.password);
        showNotification("Password copied!");
      }
      break;
    case "autofill":
      triggerAutofill(login);
      break;
    case "totp":
      showTotpCode(login);
      break;
  }
}

// The code is fetched from the desktop (never derived here), so the popup
// shows the same value the desktop would use and never sees the seed. The
// panel lives as a sibling of the login row and refreshes each second until
// the popup closes.
function showTotpCode(login) {
  const item = Array.from(document.querySelectorAll(".login-item")).find(
    (el) => el.dataset.loginId === String(login.id || "")
  );
  if (!item) return;

  const existing = item.nextElementSibling;
  if (existing && existing.classList.contains("totp-panel")) {
    existing.remove();
    return;
  }

  const panel = document.createElement("div");
  panel.className = "totp-panel";
  panel.innerHTML = `
    <span class="totp-code">······</span>
    <span class="totp-count"></span>
    <button class="totp-copy" type="button">Copy</button>
  `;
  item.parentNode.insertBefore(panel, item.nextSibling);

  const codeEl = panel.querySelector(".totp-code");
  const countEl = panel.querySelector(".totp-count");
  const copyBtn = panel.querySelector(".totp-copy");

  let current = "";
  let remaining = 0;

  const tick = async () => {
    if (!document.body.contains(panel)) {
      clearInterval(totpPopupTimer);
      totpPopupTimer = null;
      return;
    }
    if (remaining <= 0) {
      const response = await sendMessage({
        command: "getTotpCode",
        loginId: login.id,
        url: currentTabUrl
      });
      if (response && response.success && response.code) {
        current = response.code;
        remaining = Number(response.remainingSecs) || 30;
        codeEl.textContent = formatTotpCode(current);
      } else {
        codeEl.textContent = "unavailable";
        countEl.textContent = response?.error ? "—" : "";
      }
    } else {
      remaining -= 1;
    }
    countEl.textContent = current ? `${remaining}s` : "";
  };

  copyBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (current) {
      copyToClipboard(current);
      showNotification("Authenticator code copied!");
    }
  });

  if (totpPopupTimer) clearInterval(totpPopupTimer);
  tick();
  totpPopupTimer = setInterval(tick, 1000);
}

function formatTotpCode(code) {
  const value = String(code || "");
  if (value.length === 6) return `${value.slice(0, 3)} ${value.slice(3)}`;
  if (value.length === 8) return `${value.slice(0, 4)} ${value.slice(4)}`;
  return value;
}

async function triggerAutofill(login) {
  try {
    await sendMessage({
      command: "triggerAutofillWithLogin",
      login
    });
    window.close();
  } catch (e) {
    showNotification("Autofill failed");
  }
}

function copyToClipboard(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text);
  } else {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }
}

function showNoLoginsState() {
  const domain = currentTabUrl ? extractDomain(currentTabUrl) : "this site";
  mainContent.innerHTML = `
    <div class="empty-state">
      <svg class="empty-state-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
      </svg>
      <div class="empty-state-title">No logins for ${escapeHtml(domain)}</div>
      <div class="empty-state-text" style="margin-bottom:14px;">No saved logins for this website.</div>
      <button id="addToVaultBtn" style="
        display:inline-flex;align-items:center;gap:6px;
        padding:8px 18px;
        background:linear-gradient(135deg,#73db9a 0%,#1c8f56 100%);
        color:#00391d;
        border:none;border-radius:10px;cursor:pointer;
        font-size:13px;font-weight:600;font-family:inherit;
        transition:opacity 0.15s, box-shadow 0.15s;
      ">
        <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/></svg>
        Add to VELA vault
      </button>
    </div>
  `;
  const addBtn = mainContent.querySelector("#addToVaultBtn");
  if (addBtn) {
    addBtn.addEventListener("click", () => triggerSaveDialog());
    addBtn.addEventListener("mouseover", () => { addBtn.style.opacity = "0.88"; addBtn.style.boxShadow = "0 0 14px rgba(115,219,154,0.35)"; });
    addBtn.addEventListener("mouseout", () => { addBtn.style.opacity = "1"; addBtn.style.boxShadow = "none"; });
  }
}

async function triggerSaveDialog() {
  try {
    const queryTabs = await tabs.query({ active: true, currentWindow: true });
    if (!queryTabs || !queryTabs.length) return;
    await tabs.sendMessage(queryTabs[0].id, { command: "showSaveDialog", username: "", password: "" });
  } catch {}
  window.close();
}

function showEmptyState(title, text) {
  mainContent.innerHTML = `
    <div class="empty-state">
      <svg class="empty-state-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
      </svg>
      <div class="empty-state-title">${escapeHtml(title)}</div>
      <div class="empty-state-text">${escapeHtml(text)}</div>
    </div>
  `;
}

function showNotification(message) {
  const existingNotification = document.querySelector(".notification-toast");
  if (existingNotification) {
    existingNotification.remove();
  }

  const notification = document.createElement("div");
  notification.className = "notification-toast";
  notification.style.cssText = `
    position: fixed;
    bottom: 60px;
    left: 50%;
    transform: translateX(-50%);
    background: #333537;
    color: #e2e2e5;
    border: 1px solid #444748;
    padding: 8px 16px;
    border-radius: 10px;
    font-size: 12px;
    font-weight: 500;
    z-index: 1000;
    white-space: nowrap;
    animation: fadeIn 0.2s ease;
    box-shadow: 0 4px 16px rgba(0,0,0,0.4);
  `;
  notification.textContent = message;
  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.opacity = "0";
    notification.style.transition = "opacity 0.2s ease";
    setTimeout(() => notification.remove(), 200);
  }, 2000);
}

/// Escape for both text and attribute contexts.
///
/// The previous implementation round-tripped through `textContent`/`innerHTML`,
/// which escapes `&`, `<` and `>` but **not quotes** — fine for text, unsafe the
/// moment the result lands inside an attribute. Everything interpolated into the
/// popup's markup comes from the vault, i.e. from whatever a website put in a
/// saved item's name or id, so a single `"` was enough to break out of an
/// attribute in privileged popup context (audit E-2).
function escapeHtml(text) {
  return String(text ?? "").replace(
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

function extractDomain(url) {
  if (!url) {
    return "";
  }
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (e) {
    return url;
  }
}

function sendMessage(message) {
  return runtime.sendMessage(message);
}

document.addEventListener("DOMContentLoaded", init);
