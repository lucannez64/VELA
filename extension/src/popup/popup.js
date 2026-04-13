const { runtime, tabs } = browser;

const mainContent = document.getElementById("mainContent");
const statusIndicator = document.getElementById("statusIndicator");
const statusText = document.getElementById("statusText");
const loadingSpinner = document.getElementById("loadingSpinner");
const openVaultBtn = document.getElementById("openVaultBtn");
const settingsBtn = document.getElementById("settingsBtn");

let currentTabUrl = null;
let availableLogins = [];

async function init() {
  await checkDesktopConnection();
  await getCurrentTab();
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
      url: currentTabUrl
    });

    if (response && response.logins && response.logins.length > 0) {
      availableLogins = response.logins;
      renderLogins();
    } else {
      showNoLoginsState();
    }
  } catch (e) {
    showEmptyState("Error loading logins", e.message || "Could not load logins from desktop app.");
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
      <li class="login-item" data-login-id="${login.id || ""}">
        <div class="login-icon">${initial}</div>
        <div class="login-info">
          <div class="login-name">${escapeHtml(name)}</div>
          <div class="login-url">${escapeHtml(domain)}</div>
        </div>
        <div class="login-actions">
          <button class="icon-btn" title="Copy Username" data-action="copy-username" data-login-id="${login.id || ""}">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" />
            </svg>
          </button>
          <button class="icon-btn" title="Copy Password" data-action="copy-password" data-login-id="${login.id || ""}">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
            </svg>
          </button>
          <button class="icon-btn" title="Auto-fill" data-action="autofill" data-login-id="${login.id || ""}">
            <svg viewBox="0 0 20 20" fill="currentColor" width="16" height="16">
              <path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd" />
            </svg>
          </button>
        </div>
      </li>
    `;
  }).join("");

  mainContent.innerHTML = `
    <div class="section-title">Logins for this page</div>
    <ul class="login-list">
      ${loginsHtml}
    </ul>
  `;

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

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
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
