// Injected by the eval server into every fixture page (and its iframes).
// Reports what the page's fields hold, so the same scoring works whether the
// page is driven by Playwright, a phone browser, or an in-app WebView. It
// never changes the page: no attributes, no listeners that stop propagation.
(function () {
  "use strict";
  const script = document.currentScript;
  const params = new URL(script ? script.src : location.href).searchParams;
  const pageId = params.get("page") || "unknown";
  const run = params.get("run") || "";
  const live = params.get("live") === "1"; // snapshot only, never POST
  const history = new Map(); // key -> Set of non-empty values seen
  const initial = new Map(); // key -> value at first sight (page prefill)
  const firstChange = new Map(); // key -> ms since load of first non-initial value
  const t0 = performance.now();

  function isVelaUi(el) {
    return !!(el.closest && el.closest("[data-vela-ui]"));
  }

  function visible(el) {
    if (el.type === "hidden") return false;
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    if (r.right < 0 || r.bottom < 0 || r.left > Math.max(innerWidth, document.documentElement.scrollWidth) || r.top > document.documentElement.scrollHeight) return false;
    return true;
  }

  function labelFor(el) {
    if (el.labels && el.labels.length) return el.labels[0].textContent.trim().slice(0, 80);
    return el.getAttribute("aria-label") || "";
  }

  function collect(root, prefix, out) {
    for (const el of root.querySelectorAll("input,select,textarea")) {
      if (isVelaUi(el)) continue;
      if (el.tagName === "INPUT" && ["hidden", "submit", "button", "checkbox", "radio", "image", "reset", "file"].includes(el.type)) continue;
      const id = el.id || el.name;
      if (!id) continue;
      const key = prefix + id;
      const tag = el.tagName.toLowerCase();
      const value = el.value;
      const r = el.getBoundingClientRect();
      const entry = {
        value, tag, type: tag === "input" ? el.type : tag,
        name: el.name || "", id: el.id || "", autocomplete: el.getAttribute("autocomplete") || "",
        placeholder: el.getAttribute("placeholder") || "", label: labelFor(el),
        visible: visible(el),
        rect: { x: r.left, y: r.top, w: r.width, h: r.height },
      };
      if (tag === "select") {
        const opt = el.options[el.selectedIndex];
        entry.text = opt ? opt.text.trim() : "";
        entry.defaultSelected = el.selectedIndex <= 0 && (!opt || opt.value === "" || /^(—|-|select|mm|yyyy)/i.test(opt.text.trim()));
      }
      if (!initial.has(key)) initial.set(key, value);
      entry.prefilled = value !== "" && value === initial.get(key) && el.defaultValue === value;
      if (value) {
        if (!history.has(key)) history.set(key, new Set());
        history.get(key).add(value);
        if (value !== initial.get(key) && !firstChange.has(key)) firstChange.set(key, Math.round(performance.now() - t0));
      }
      out[key] = entry;
    }
    for (const host of root.querySelectorAll("*")) {
      if (host.shadowRoot && host.id) collect(host.shadowRoot, prefix + host.id + "/", out);
    }
  }

  function frames() {
    return Array.from(document.querySelectorAll("iframe")).map((f) => {
      const r = f.getBoundingClientRect();
      return { id: f.id || "", src: f.src, rect: { x: r.left, y: r.top, w: r.width, h: r.height } };
    });
  }

  function snapshot() {
    const fields = {};
    collect(document, "", fields);
    const hist = {};
    for (const [k, set] of history) hist[k] = Array.from(set);
    return {
      run, page: pageId, url: location.href, ts: Date.now(),
      sinceLoadMs: Math.round(performance.now() - t0),
      fields, history: hist, firstChangeMs: Object.fromEntries(firstChange), frames: frames(),
      viewport: {
        innerWidth, innerHeight, devicePixelRatio,
        offsetLeft: visualViewport ? visualViewport.offsetLeft : 0,
        offsetTop: visualViewport ? visualViewport.offsetTop : 0,
        scale: visualViewport ? visualViewport.scale : 1,
      },
      // A dropdown the extension drew into this document: counts as an offer.
      velaUi: !!document.querySelector(".vela-inline-dropdown,.vela-field-icon,#vela-gen-modal"),
      velaDropdown: !!document.querySelector(".vela-inline-dropdown"),
    };
  }

  let lastSig = "";
  let pending = null;
  function signature(s) {
    const parts = [];
    for (const [k, f] of Object.entries(s.fields)) parts.push(k + "=" + f.value + "@" + Math.round(f.rect.y));
    return parts.join("|") + "|" + s.velaUi + s.frames.map((f) => f.src + Math.round(f.rect.y)).join();
  }
  function report(force) {
    if (live) return;
    const s = snapshot();
    const sig = signature(s);
    if (!force && sig === lastSig) return;
    lastSig = sig;
    const body = JSON.stringify(s);
    try {
      fetch("/__eval/report", { method: "POST", body, keepalive: body.length < 60000, headers: { "content-type": "application/json" } }).catch(() => {});
    } catch (_) {}
  }
  function schedule() {
    if (pending) return;
    pending = setTimeout(() => { pending = null; report(false); }, 60);
  }

  globalThis.__velaEval = { pageId, run, snapshot, report: () => report(true) };
  document.addEventListener("input", schedule, true);
  document.addEventListener("change", schedule, true);
  document.addEventListener("focusin", schedule, true);
  // Autofill on some platforms sets values without events; poll as well.
  setInterval(() => report(false), 250);
  setInterval(() => report(true), 3000);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => report(true));
  else report(true);
  addEventListener("pagehide", () => report(true));
})();
