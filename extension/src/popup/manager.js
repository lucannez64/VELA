/* Dedicated extension page: no content-script access, plaintext storage or telemetry. */
"use strict";
const $ = id => document.getElementById(id);
let snapshot = { items: [], collections: { enabled: false, organization: {} } };
let filter = null, editing = null, selected = new Set(), collection = null, busy = false, secretTimer, editorDirty = false;
const labels = { login: "Login", creditcard: "Card", creditCard: "Card", securenote: "Note", secureNote: "Note", identity: "Identity", passkey: "Passkey" };
const org = () => snapshot.collections.organization;
const folders = () => org().folders || [];
const tags = () => org().tags || [];
function node(tag, text, className) { const el = document.createElement(tag); if (text != null) el.textContent = text; if (className) el.className = className; return el; }
function button(text, action, className) { const el = node("button", text, className); el.type = "button"; el.addEventListener("click", action); return el; }
function message(text, error = false) { $("status").textContent = text; $("status").style.color = error ? "var(--error)" : ""; }
function path(id) {
  const parts = [], seen = new Set();
  while (id && !seen.has(id) && seen.size < 16) { seen.add(id); const f = folders().find(f => f.id === id); if (!f) break; parts.unshift(f.name); id = f.parentId; }
  return parts.join(" / ");
}
async function request(operation, payload = {}) {
  if (busy) throw new Error("Wait for the current action to finish");
  busy = true; const disabled = new Map([...document.querySelectorAll("button")].map(el => [el, el.disabled]));
  disabled.forEach((_, el) => el.disabled = true);
  message(operation === "list" ? "Loading vault metadata…" : "Approve this action in VELA Desktop…");
  try {
    const response = await browser.runtime.sendMessage({ command: "vaultManage", request: { operation, ...payload } });
    if (!response?.success) throw new Error(response?.error || "Update and unlock VELA Desktop, then try again");
    message("Connected to VELA Desktop");
    return response.data;
  } finally { busy = false; disabled.forEach((wasDisabled, el) => { if (el.isConnected) el.disabled = wasDisabled; }); }
}
function run(action) { return async () => { try { await action(); } catch (e) { message(e.message, true); } }; }
async function refresh() { snapshot = await request("list"); selected = new Set([...selected].filter(id => snapshot.items.some(i => i.id === id))); render(); }
function options(select, entries, first) {
  // Re-rendering must not silently change what the user picked (a bulk Move
  // would otherwise fall back to "Unfiled").
  const previous = select.value;
  const unselected = select.options.length > 0 && select.selectedIndex < 0;
  select.replaceChildren(); if (first) select.add(new Option(first[1], first[0])); entries.forEach(([id, name]) => select.add(new Option(name, id)));
  if (unselected) select.selectedIndex = -1;
  else if (previous) select.value = previous; // A deleted destination stays unselected, never silently Unfiled.
}
function setFilter(next) { filter = next; render(); }
function render() {
  $("activation").hidden = snapshot.collections.enabled;
  $("folders").replaceChildren(); $("tags").replaceChildren();
  for (const [kind, records] of [["folder", folders()], ["tag", tags()]]) for (const record of records) {
    const row = node("div", null, "collection-row");
    row.append(button(kind === "folder" ? path(record.id) : "# " + record.name, () => setFilter({ kind, id: record.id }), filter?.id === record.id ? "active" : ""), button("•••", () => editCollection(kind, record)));
    $(kind === "folder" ? "folders" : "tags").append(row);
  }
  $("newFolder").disabled = $("newTag").disabled = !snapshot.collections.enabled;
  $("scope").textContent = !filter ? "All items" : filter.kind === "folder" ? path(filter.id) : filter.kind === "tag" ? "# " + tags().find(t => t.id === filter.id)?.name : "Unfiled";
  const query = $("search").value.toLocaleLowerCase();
  const list = snapshot.items.filter(item => item.name.toLocaleLowerCase().includes(query) && (!filter || (filter.kind === "tag" ? (item.tagIds || []).includes(filter.id) : filter.kind === "unfiled" ? !folders().some(f => f.id === item.folderId) : item.folderId === filter.id || path(item.folderId).startsWith(path(filter.id) + " / "))));
  $("items").replaceChildren();
  for (const item of list) {
    const row = node("div", null, "item-row"), check = node("input"); check.type = "checkbox"; check.checked = selected.has(item.id); check.disabled = item.readOnly; check.setAttribute("aria-label", "Select " + item.name);
    check.addEventListener("change", () => { check.checked ? selected.add(item.id) : selected.delete(item.id); renderBulk(); });
    const open = button(item.name, run(async () => {
      editing = null; $("editor").replaceChildren(node("p", "Waiting for desktop approval…"));
      const result = await request("read", { id: item.id }); editing = result.item; renderEditor(result.readOnly);
    }));
    open.append(node("span", labels[item.kind] || item.kind, "kind")); row.append(check, open); $("items").append(row);
  }
  if (!list.length) $("items").append(node("p", "No items in this view.", "empty"));
  renderBulk();
}
function renderBulk() {
  $("bulk").hidden = !selected.size || !snapshot.collections.enabled;
  $("selectedCount").textContent = selected.size + " selected";
  options($("bulkFolder"), folders().map(f => [f.id, path(f.id)]), ["", "Unfiled"]);
  options($("bulkTag"), tags().map(t => [t.id, t.name]));
}
function editCollection(kind, record = null) {
  collection = { kind, record }; $("collectionTitle").textContent = (record ? "Edit " : "New ") + kind;
  $("collectionName").value = record?.name || ""; $("parentLabel").hidden = kind !== "folder";
  options($("collectionParent"), folders().filter(f => f.id !== record?.id).map(f => [f.id, path(f.id)]), ["", "No parent"]);
  $("collectionParent").value = record?.parentId || "";
  const existing = $("collectionForm").querySelector(".danger"); existing?.remove();
  if (record) $("collectionForm").append(button("Delete " + kind, run(async () => {
    if (!confirm("Delete this " + kind + "? Items will be kept.")) return;
    $("collectionDialog").close();
    await request("mutate", { action: { operation: kind === "folder" ? "deleteFolder" : "deleteTag", id: record.id } }); await refresh();
  }), "danger"));
  $("collectionDialog").showModal();
}
function input(parent, label, object, key, type = "text") {
  const wrap = node("label", label), el = node(type === "textarea" ? "textarea" : "input");
  if (type !== "textarea") el.type = type; el.value = object[key] ?? "";
  if (type === "password") el.dataset.secret = "true";
  el.addEventListener("input", () => object[key] = el.value); wrap.append(el);
  if (type === "password") wrap.append(button("Show", event => {
    el.type = el.type === "password" ? "text" : "password";
    event.currentTarget.textContent = el.type === "password" ? "Show" : "Hide";
  }));
  parent.append(wrap); return el;
}
function richEditor(form, item) {
  form.append(node("h3", "Organisation"));
  const folderLabel = node("label", "Folder"), folder = node("select"); options(folder, folders().map(f => [f.id, path(f.id)]), ["", "Unfiled"]); folder.value = item.folderId || "";
  folder.addEventListener("change", () => item.folderId = folder.value); folderLabel.append(folder); form.append(folderLabel);
  const tagList = node("div", null, "tags");
  for (const tag of tags()) { const label = node("label", null, "check"), check = node("input"); check.type = "checkbox"; check.checked = (item.tagIds || []).includes(tag.id); check.addEventListener("change", () => { const ids = new Set(item.tagIds || []); check.checked ? ids.add(tag.id) : ids.delete(tag.id); item.tagIds = [...ids]; }); label.append(check, node("span", tag.name)); tagList.append(label); }
  form.append(tagList, node("h3", "Custom fields"));
  const typeSelect = node("select"); options(typeSelect, [["text", "Text"], ["concealed", "Secret"], ["boolean", "Boolean"]]); typeSelect.setAttribute("aria-label", "New custom field type");
  form.append(typeSelect);
  records(form, item, "customFields", field => {
    const card = node("div");
    if (!["text", "concealed", "boolean"].includes(field.type)) { card.append(node("p", "Unsupported field type — kept unchanged.")); return card; }
    input(card, "Label", field, "label");
    if (field.type === "boolean") { const label = node("label", null, "check"), check = node("input"); check.type = "checkbox"; check.checked = field.value === true; check.addEventListener("change", () => field.value = check.checked); label.append(check, node("span", "Enabled")); card.append(label); }
    else input(card, field.type === "concealed" ? "Secret value" : "Value", field, "value", field.type === "concealed" ? "password" : "text");
    return card;
  }, () => ({ id: crypto.randomUUID(), label: "", type: typeSelect.value, value: typeSelect.value === "boolean" ? false : "" }));
  if (item.item_type === "login") {
    form.append(node("h3", "Additional websites"), node("p", "Stored with this login. Autofill approval remains specific to the destination site."));
    records(form, item, "additionalUrls", entry => { const card = node("div"); if (!["exact", "origin"].includes(entry.match)) { card.append(node("p", "Unsupported URL rule — kept unchanged.")); return card; } input(card, "HTTPS URL", entry, "url", "url"); const label = node("label", "Match"), mode = node("select"); options(mode, [["origin", "Whole origin"], ["exact", "Exact address"]]); mode.value = entry.match; mode.addEventListener("change", () => entry.match = mode.value); label.append(mode); card.append(label); return card; }, () => ({ id: crypto.randomUUID(), url: "", match: "origin" }));
  }
}
function records(parent, item, key, renderRecord, create) {
  const list = node("div");
  const draw = () => { list.replaceChildren(); (item[key] || []).forEach((record, index) => { const card = renderRecord(record); card.classList.add("record"); card.append(button("Remove", () => { item[key].splice(index, 1); draw(); }, "danger")); list.append(card); }); };
  draw(); parent.append(list, button(key === "addresses" ? "Add address" : key === "additionalUrls" ? "Add website" : "Add field", () => { (item[key] ||= []).push(create()); draw(); }));
}
function renderEditor(readOnly = false, isNew = false) {
  const item = editing; if (!item) return; editorDirty = false; resetSecretTimer(); const root = $("editor"); root.replaceChildren();
  const form = node("form"); root.append(form); form.append(node("h2", isNew ? "New item" : "Edit item"));
  input(form, "Name", item, "name").required = true;
  if (isNew) { const label = node("label", "Type"), kind = node("select"); options(kind, [["login", "Login"], ["creditCard", "Card"], ["secureNote", "Note"], ["identity", "Identity"]]); kind.value = item.item_type; kind.addEventListener("change", () => newItem(kind.value)); label.append(kind); form.append(label); }
  const type = item.item_type;
  const supported = ["login", "creditCard", "secureNote", "identity"].includes(type);
  const base = type === "login" ? [["url", "Website", "url"], ["username", "Username"], ["password", "Password", "password"], ["totp", "TOTP secret", "password"]] : type === "creditCard" ? [["cardholder_name", "Cardholder"], ["number", "Card number", "password"], ["exp", "Expiry"], ["cvv", "Security code", "password"], ["pin", "PIN", "password"]] : type === "identity" ? [["first_name", "First name"], ["last_name", "Last name"], ["ssn", "SSN", "password"]] : type === "secureNote" ? [["content", "Note", "textarea"]] : [];
  base.forEach(([key, label, kind]) => input(form, label, item, key, kind));
  input(form, "Notes", item, "notes", "textarea");
  if (type === "identity") {
    const details = item.identityDetails ||= {}; form.append(node("h3", "Contact details"));
    for (const [key, label] of [["middleName", "Middle name"], ["preferredName", "Preferred name"], ["email", "Email"], ["phone", "Phone"], ["company", "Company"], ["jobTitle", "Job title"]]) input(form, label, details, key);
    form.append(node("h3", "Addresses"));
    records(form, details, "addresses", address => { const card = node("div"); for (const [key, label] of [["label", "Label"], ["line1", "Street"], ["line2", "Address line 2"], ["city", "City"], ["region", "Region"], ["postalCode", "Postal code"], ["countryCode", "Country code (e.g. FR)"]]) input(card, label, address, key); return card; }, () => ({ id: crypto.randomUUID() }));
  }
  if (snapshot.collections.enabled) richEditor(form, item);
  if (!supported) form.append(node("p", "Use VELA Desktop to edit this item type. Folder/tag assignment is available through the list selection."));
  if (readOnly) form.append(node("p", "Received shared items are read-only."));
  if (!readOnly && supported) {
    const save = node("button", isNew ? "Create item" : "Save changes", "primary"); save.type = "submit"; form.append(save);
    if (!isNew) form.append(button("Delete item", run(async () => { if (!confirm("Delete this item?")) return; await request("delete", { id: item.id }); editing = null; root.replaceChildren(node("p", "Item deleted.")); await refresh(); }), "danger"));
  } else { form.querySelectorAll("input,select,textarea,button").forEach(el => el.disabled = true); }
  form.addEventListener("submit", event => { event.preventDefault(); run(async () => { if (readOnly || !supported) return; if (type === "secureNote") item.title = item.name; await request(isNew ? "create" : "update", { item }); editing = null; editorDirty = false; root.replaceChildren(node("p", "Saved to your vault.")); await refresh(); })(); });
}
function newItem(type = "login") {
  const now = new Date().toISOString();
  editing = { item_type: type, id: crypto.randomUUID(), name: "", createdAt: now, updatedAt: now, favorite: false, shared: false,
    ...(type === "login" ? { url: "", username: "", password: "", totp: null } : type === "creditCard" ? { number: "", exp: "", cvv: "" } : type === "identity" ? { first_name: "", last_name: "", ssn: "" } : { title: "", content: "" }) };
  renderEditor(false, true);
}
$("refresh").addEventListener("click", run(refresh)); $("search").addEventListener("input", render);
$("allItems").addEventListener("click", () => setFilter(null)); $("unfiled").addEventListener("click", () => setFilter({ kind: "unfiled" }));
$("newFolder").addEventListener("click", () => editCollection("folder")); $("newTag").addEventListener("click", () => editCollection("tag"));
$("newItem").addEventListener("click", () => newItem()); $("activate").addEventListener("click", run(async () => { await request("activate"); await refresh(); }));
$("collectionCancel").addEventListener("click", () => $("collectionDialog").close());
$("collectionForm").addEventListener("submit", event => { event.preventDefault(); run(async () => {
  const { kind, record } = collection;
  const action = { operation: kind === "folder" ? record ? "updateFolder" : "createFolder" : record ? "renameTag" : "createTag", name: $("collectionName").value };
  if (record) action.id = record.id; if (kind === "folder") action.parentId = $("collectionParent").value || null;
  $("collectionDialog").close(); await request("mutate", { action }); await refresh();
})(); });
const assign = changes => run(async () => { await request("assign", { changes: { ids: [...selected], folderId: null, addTags: [], removeTags: [], ...changes } }); await refresh(); });
$("move").addEventListener("click", () => {
  if ($("bulkFolder").selectedIndex < 0) { message("Choose a destination folder.", true); return; }
  assign({ folderId: $("bulkFolder").value })();
});
$("tagAdd").addEventListener("click", () => { if ($("bulkTag").value) assign({ addTags: [$("bulkTag").value] })(); });
$("tagRemove").addEventListener("click", () => { if ($("bulkTag").value) assign({ removeTags: [$("bulkTag").value] })(); });
$("theme").addEventListener("change", () => VelaInstrument.setTheme($("theme").value));
$("openDesktop").addEventListener("click", () => browser.runtime.sendMessage({ command: "openVault" }));
run(refresh)();

function clearEditor() {
  editing = null; editorDirty = false; clearTimeout(secretTimer);
  $("editor").replaceChildren(node("p", "Editor cleared. Choose an item again to continue.", "empty"));
}
function maskSecrets() {
  $("editor").querySelectorAll("[data-secret]").forEach(el => {
    el.type = "password";
    const toggle = el.nextElementSibling; if (toggle?.tagName === "BUTTON") toggle.textContent = "Show";
  });
}
// Idle: an untouched editor is cleared; unsaved work is kept with secrets masked.
function onEditorIdle() {
  if (!editorDirty) { clearEditor(); return; }
  maskSecrets();
  message("Secrets hidden after 2 minutes idle. Your unsaved changes are kept.");
}
function resetSecretTimer() { clearTimeout(secretTimer); if (editing) secretTimer = setTimeout(onEditorIdle, 120000); }
for (const type of ["input", "change"]) document.addEventListener(type, event => {
  if ($("editor").contains(event.target)) editorDirty = true;
  resetSecretTimer();
});
document.addEventListener("click", event => {
  const button = event.target.closest?.("button");
  if (button && $("editor").contains(button) && !["Show", "Hide"].includes(button.textContent)) editorDirty = true;
}, true); // Capture removals before their handlers detach the edited record.
window.addEventListener("beforeunload", event => { if (editing && editorDirty) event.preventDefault(); });
document.addEventListener("click", resetSecretTimer);
window.addEventListener("pagehide", clearEditor);
