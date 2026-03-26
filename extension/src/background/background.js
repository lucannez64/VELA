const AUTOFILL_PORT = "injected-script";
const NATIVEMessaging_PORT = "vela-desktop";

let desktopConnection = null;
let activeTabId = null;

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
    return {
      secret,
      algorithm: algMap[alg] || "SHA-1",
      digits: parseInt(parsed.searchParams.get("digits") || "6", 10),
      period: parseInt(parsed.searchParams.get("period") || "30", 10)
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
  chrome.runtime.onConnect.addListener((port) => {
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

function setupContextMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "vela-autofill",
      title: "Auto-fill with VELA",
      contexts: ["all"]
    });

    chrome.contextMenus.create({
      id: "vela-copy-username",
      title: "Copy Username",
      contexts: ["all"]
    });

    chrome.contextMenus.create({
      id: "vela-copy-password",
      title: "Copy Password",
      contexts: ["all"]
    });

    chrome.contextMenus.create({
      id: "vela-open-vault",
      title: "Open VELA Vault",
      contexts: ["all"]
    });
  });

  chrome.contextMenus.onClicked.addListener((info, tab) => {
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
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
      handleGetLogins(data, sendResponse);
      break;
    case "getAvailableLogins":
      handleGetAvailableLogins(data, sendResponse);
      break;
    case "nativeMessage":
      handleNativeMessage(data, sendResponse);
      break;
    case "checkDesktopConnection":
      checkDesktopConnection(sendResponse);
      return true;
    case "saveCredentials":
      handleSaveCredentials(data, sendResponse);
      break;
    case "triggerAutofillWithLogin":
      handleTriggerAutofillWithLogin(data, sender, sendResponse);
      return true;
    default:
      sendResponse({ success: false, error: "Unknown command" });
  }
}

function setupCommandListeners() {
  chrome.commands.onCommand.addListener((command, tab) => {
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
      chrome.tabs.sendMessage(tabId, {
        command: "performFill",
        fillScript
      }, (response) => {
        sendResponse(response || { success: false });
      });
    } else {
      sendResponse({ success: false, error: "No tab found" });
    }
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

async function handleGetLogins(data, sendResponse) {
  try {
    const { url } = data;
    console.log("[VELA] handleGetLogins for URL:", url);
    let domain;
    try { domain = new URL(url).hostname.replace(/^www\./, ""); } catch (_) { domain = url; }
    const response = await sendHttpMessage({
      msg_type: "AutofillRequest",
      payload: { domain }
    });
    console.log("[VELA] handleGetLogins response:", JSON.stringify(response));

    if (response && response.msg_type === "AutofillResponse") {
      const items = response.payload?.items || [];
      const logins = await Promise.all(
        items.filter(item => item.item_type === "login").map(async item => ({
          id: item.id,
          name: item.name,
          username: item.username,
          password: item.password,
          totp: await computeLoginTOTP(item),
          url: item.url
        }))
      );
      sendResponse({ success: true, logins });
    } else {
      sendResponse({ success: false, logins: [] });
    }
  } catch (error) {
    console.log("[VELA] handleGetLogins error:", error.message);
    sendResponse({ success: false, error: error.message, logins: [] });
  }
}

async function handleGetAvailableLogins(data, sendResponse) {
  try {
    const { url } = data;
    console.log("[VELA] handleGetAvailableLogins for URL:", url);
    let domain;
    try { domain = new URL(url).hostname.replace(/^www\./, ""); } catch (_) { domain = url; }
    const response = await sendHttpMessage({
      msg_type: "AutofillRequest",
      payload: { domain }
    });
    console.log("[VELA] handleGetAvailableLogins response:", JSON.stringify(response));

    if (response && (response.msg_type === "AutofillResponse" || response.msg_type === "autofill_response")) {
      const items = response.payload?.items || [];
      const logins = await Promise.all(
        items.filter(item => item.item_type === "login").map(async item => ({
          id: item.id,
          name: item.name,
          username: item.username,
          password: item.password,
          totp: await computeLoginTOTP(item),
          url: item.url
        }))
      );
      console.log("[VELA] Found logins:", logins.length);
      sendResponse({ success: true, logins });
    } else {
      console.log("[VELA] No AutofillResponse in response");
      sendResponse({ success: false, logins: [] });
    }
  } catch (error) {
    console.log("[VELA] handleGetAvailableLogins error:", error.message);
    sendResponse({ success: false, error: error.message, logins: [] });
  }
}

async function handleNativeMessage(data, sendResponse) {
  try {
    const response = await sendNativeMessage(data);
    sendResponse(response || { success: false });
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

async function handleTriggerAutofillWithLogin(data, sender, sendResponse) {
  const { login } = data;
  if (!login) { sendResponse({ success: false }); return; }

  // Use sender tab if available, otherwise query active tab
  const tabId = sender?.tab?.id || await new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      resolve(tabs && tabs.length ? tabs[0].id : null);
    });
  });

  if (!tabId) { sendResponse({ success: false, error: "No tab found" }); return; }

  chrome.tabs.sendMessage(tabId, { command: "fillWithLogin", login }, (response) => {
    sendResponse(response || { success: true });
  });
}

async function handleSaveCredentials(data, sendResponse) {
  try {
    const response = await sendHttpMessage({
      msg_type: "SaveCredentials",
      payload: {
        name: data.name || "",
        username: data.username || "",
        password: data.password || "",
        url: data.url || ""
      }
    });

    if (response && (response.success || response.msg_type === "SaveCredentialsResponse")) {
      sendResponse({ success: true });
    } else {
      // Fallback to native messaging
      const nativeResp = await sendNativeMessage({ action: "saveCredentials", ...data });
      sendResponse(nativeResp || { success: false });
    }
  } catch (error) {
    sendResponse({ success: false, error: error.message });
  }
}

function checkDesktopConnection(sendResponse) {
  if (desktopConnection && desktopConnection.disconnected === false) {
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
      desktopConnection = { disconnected: false };
      sendResponse({ connected: true });
    }
  };
  
  checkHttpConnection().then(checkResult);
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

async function checkHttpConnection() {
  console.log("[VELA] Trying HTTP connection to port 14597...");
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    
    const response = await fetch("http://localhost:14597/ping", {
      method: "GET",
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    console.log("[VELA] HTTP response status:", response.status);
    
    if (response.ok) {
      const data = await response.json().catch(() => ({}));
      console.log("[VELA] HTTP response data:", JSON.stringify(data));
      return { success: true, ...data };
    }
    return { success: false };
  } catch (err) {
    console.log("[VELA] HTTP connection error:", err.message);
    return { success: false };
  }
}

function sendNativeMessage(message) {
  console.log("[VELA] Trying native messaging...");
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      console.log("[VELA] Native messaging timeout");
      resolve({ success: false, error: "Native messaging timeout" });
    }, 10000);

    const tryNativeMessaging = () => {
      try {
        const runtime = typeof browser !== "undefined" ? browser.runtime : chrome.runtime;
        const sendNative = runtime?.sendNativeMessage?.bind(runtime);
        
        if (sendNative) {
          sendNative("vela-desktop", message, (response) => {
            clearTimeout(timeoutId);
            console.log("[VELA] Native messaging response:", JSON.stringify(response));
            if (runtime.lastError) {
              console.log("[VELA] Native messaging error:", runtime.lastError.message);
              resolve({ success: false, error: runtime.lastError.message });
            } else {
              resolve(response || { success: false });
            }
          });
          return true;
        }
      } catch (error) {
        console.log("[VELA] Native messaging exception:", error.message);
      }
      return false;
    };

    if (!tryNativeMessaging()) {
      console.log("[VELA] Native messaging not available, trying HTTP...");
      clearTimeout(timeoutId);
      sendHttpMessage(message).then(resolve).catch(() => {
        resolve({ success: false, error: "Communication failed" });
      });
    }
  });
}

async function sendHttpMessage(message) {
  console.log("[VELA] Sending HTTP message:", JSON.stringify(message));
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch("http://localhost:14597/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    console.log("[VELA] HTTP POST response status:", response.status);
    
    if (response.ok) {
      const data = await response.json().catch(() => ({ success: true }));
      console.log("[VELA] HTTP POST response data:", JSON.stringify(data));
      return data;
    }
    return { success: false, error: `HTTP ${response.status}` };
  } catch (error) {
    console.log("[VELA] HTTP POST error:", error.message);
    return { success: false, error: error.message };
  }
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
    case "getNativeMessage":
      sendNativeMessage(data).then((response) => {
        port.postMessage({ command: "nativeMessageResponse", ...response });
      });
      break;
  }
}

function triggerAutofill(tabId) {
  chrome.tabs.sendMessage(tabId, { command: "triggerAutofill" }, (response) => {
  });
}

function copyUsername(tabId) {
  chrome.tabs.sendMessage(tabId, { command: "copyUsername" }, (response) => {
  });
}

function copyPassword(tabId) {
  chrome.tabs.sendMessage(tabId, { command: "copyPassword" }, (response) => {
  });
}

function openVault() {
  chrome.action.openPopup();
}

function openPopup() {
  chrome.action.openPopup().catch(() => {
    chrome.tabs.create({ url: "src/popup/popup.html" });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  init();
});

chrome.runtime.onStartup.addListener(() => {
  init();
});

init();
