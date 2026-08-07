const { runtime, tabs } = browser;

const mainContent = document.getElementById("mainContent");
const statusIndicator = document.getElementById("statusIndicator");
const statusText = document.getElementById("statusText");
const loadingSpinner = document.getElementById("loadingSpinner");
const openVaultBtn = document.getElementById("openVaultBtn");
const settingsBtn = document.getElementById("settingsBtn");

let currentTabUrl = null;
let availableLogins = [];
let inCoreLoginCandidates = [];

async function init() {
  await checkDesktopConnection();
  await getCurrentTab();
  await loadInCoreLoginCandidates();
  await loadLogins();
  setupEventListeners();
}

function setupEventListeners() {
  openVaultBtn.addEventListener("click", () => {
    sendMessage({ command: "openVault" });
  });

  settingsBtn.addEventListener("click", () => {
    sendMessage({ command: "openSettings" });
  });
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
      return `
        <button class="in-core-login-btn" data-item-id="${escapeHtml(candidate.item_id || "")}"
                style="display:block;width:100%;text-align:left;margin-bottom:6px;padding:8px 12px;
                       background:#2a2d2e;color:#e2e2e5;border:1px solid #444748;border-radius:10px;
                       font-size:12px;cursor:pointer;">
          Sign in as ${escapeHtml(who)} without filling the password
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

    const response = await sendMessage({ command: "inCoreLogin", itemId });
    if (!response?.success) {
      showNotification(response?.error || "Sign-in failed");
      button.disabled = false;
      button.textContent = "Sign in without filling the password";
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
      showNotification(response.residualNote || "Signed in.");
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

async function ensureCookiePermission() {
  const origin = new URL(currentTabUrl).origin + "/*";
  const request = { permissions: ["cookies"], origins: [origin] };
  if (await browser.permissions.contains(request)) {
    return true;
  }
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
  }
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
