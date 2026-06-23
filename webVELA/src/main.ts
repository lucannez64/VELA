import './styles.css';
import QRCode from 'qrcode';
import {
  initVela,
  generateEphemeralKeypair,
  generateSigningKeypair,
  createAuthSignature,
  openShare,
  decryptVaultChunk,
  encryptVaultChunk,
  bytesToB64,
  b64ToBytes,
  randomB64,
  argon2Wrap,
  argon2Unwrap,
} from './vela';
import { startSession, pollSession, getChallenge, getSessionToken, AuthedSession, type PollResponse } from './api';

// ── In-memory session secrets (never persisted) ─────────────────────────────────
let shareDk = '';
let signingSk = '';
let rmsB64 = '';
let sessionId = '';
let linkPayload = { ephemeral_pk: '', web_vk: '', link_nonce: '' };
let polling = false;

// RW state
let authed: AuthedSession | null = null;
let items: Record<string, unknown>[] = [];
let dirty = false;
let rwExpiresAt: string | undefined;

// RW reload survival (design §8.1): the RMS + signing key are Argon2id-wrapped
// under a user PIN in sessionStorage (per-tab, cleared on close), so a reload can
// resume without re-linking from the phone.
const RW_STORE_KEY = 'vela.rw.v1';
function clearRwStore() {
  sessionStorage.removeItem(RW_STORE_KEY);
}
function persistRw(pin: string) {
  const payload = btoa(JSON.stringify({ rms: rmsB64, sk: signingSk, sid: sessionId, exp: rwExpiresAt ?? '' }));
  sessionStorage.setItem(RW_STORE_KEY, argon2Wrap(pin, payload));
}
async function restoreRw(pin: string): Promise<boolean> {
  const blob = sessionStorage.getItem(RW_STORE_KEY);
  if (!blob) return false;
  let data: { rms: string; sk: string; sid: string; exp: string };
  try {
    data = JSON.parse(atob(argon2Unwrap(pin, blob)));
  } catch {
    return false; // wrong PIN
  }
  rmsB64 = data.rms;
  signingSk = data.sk;
  sessionId = data.sid;
  rwExpiresAt = data.exp || undefined;
  try {
    await loadReadWrite(rwExpiresAt);
    return true;
  } catch {
    clearRwStore(); // session expired / revoked
    return false;
  }
}

// Vault chunking — must match the apps (Android `VaultSyncManager` / desktop sync):
// the vault JSON is split across `vault-data-NNNNNN` chunks (≤ 1 MiB − 4 KiB each),
// with `vault-main` as a legacy single chunk and `vault` as the iOS single chunk.
const VAULT_CHUNK_PLAINTEXT_SIZE = 1024 * 1024 - 4096;
const DATA_PREFIX = 'vault-data-';
function dataChunkId(i: number): string {
  return DATA_PREFIX + String(i).padStart(6, '0');
}
function splitUtf8(s: string, maxBytes: number): string[] {
  const enc = new TextEncoder();
  const out: string[] = [];
  let cur = '';
  let curBytes = 0;
  for (const ch of s) {
    const b = enc.encode(ch).length;
    if (cur && curBytes + b > maxBytes) {
      out.push(cur);
      cur = '';
      curBytes = 0;
    }
    cur += ch;
    curBytes += b;
  }
  if (cur || out.length === 0) out.push(cur);
  return out;
}

const app = document.getElementById('app')!;

/** Drop the in-memory secrets (keys / RMS / token) but keep what's on screen. */
function wipeKeys() {
  shareDk = '';
  signingSk = '';
  rmsB64 = '';
  authed = null;
}
/** Full wipe: secrets and the decrypted vault. */
function wipe() {
  wipeKeys();
  items = [];
}
window.addEventListener('beforeunload', wipe);

// ── DOM helpers ─────────────────────────────────────────────────────────────────
function el(html: string): HTMLElement {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild as HTMLElement;
}
function render(node: HTMLElement) {
  app.replaceChildren(node);
}
function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}
function toast(msg: string) {
  document.querySelector('.toast')?.remove();
  const t = el(`<div class="toast">${esc(msg)}</div>`);
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2200);
}
const brand = `<div class="brand"><div class="mark">V</div><div class="name">VE<span>LA</span></div></div>`;

// ── Screens ─────────────────────────────────────────────────────────────────────

function showSplash(text: string) {
  render(el(`<div class="splash"><div><div class="mark-lg">V</div><p class="spinner">${esc(text)}</p></div></div>`));
}

function showError(message: string) {
  polling = false;
  const node = el(`<div>${brand}
    <h1>Web Access</h1>
    <div class="card"><p class="error">${esc(message)}</p></div>
    <button class="primary" id="retry">Start over</button>
  </div>`);
  render(node);
  node.querySelector<HTMLButtonElement>('#retry')!.onclick = () => location.reload();
}

async function showLinkScreen() {
  // The QR carries only the short session id; the app fetches the key from the
  // server, keeping the QR easy to scan.
  const qrDataUrl = await QRCode.toDataURL(sessionId, { errorCorrectionLevel: 'M', margin: 1, width: 232 });
  const node = el(`<div>${brand}
    <h1>Open your vault here</h1>
    <p class="sub">Temporary, expiring, revocable access — no install, no permanent device.</p>
    <div class="card">
      <h2>In the VELA app</h2>
      <p class="muted">Open <b>Devices&nbsp;/&nbsp;Settings → Web access</b>, scan this code (or paste it), pick a duration, and approve.</p>
      <div class="qr"><img src="${qrDataUrl}" alt="link code" /></div>
      <div style="height:14px"></div>
      <div class="code" id="code">${esc(sessionId)}</div>
      <div style="height:12px"></div>
      <button class="small" id="copy">Copy code</button>
    </div>
    <div class="card center"><span class="spinner">Waiting for approval…</span></div>
  </div>`);
  render(node);
  node.querySelector<HTMLButtonElement>('#copy')!.onclick = async () => {
    await navigator.clipboard.writeText(sessionId);
    node.querySelector<HTMLButtonElement>('#copy')!.textContent = 'Copied ✓';
  };
}

// ── Item rendering (shared by RO and RW) ────────────────────────────────────────

function displayName(it: Record<string, unknown>): string {
  const meta = it.meta as Record<string, unknown> | undefined;
  return (meta?.name as string) ?? (it.name as string) ?? (it.title as string) ?? '(item)';
}
function itemType(it: Record<string, unknown>): string {
  return (it.type as string) ?? (it.kind as string) ?? Object.keys(it).find((k) => k !== 'meta') ?? 'item';
}
const SECRET = /pass|pin|cvv|secret|totp|seed|key|cvc/i;
// Internal/metadata fields — never shown or edited (only real content is).
const META_HIDE = new Set([
  'id', 'type', 'kind', 'item_type', 'createdat', 'updatedat', 'created_at', 'updated_at',
  'lastmodifieddevice', 'last_modified_device', 'favorite', 'shared', 'sharerecipient',
  'share_recipient', 'version', 'lamport', 'conflictrefs', 'conflict_refs',
]);

interface Leaf { path: string; key: string; value: string; isString: boolean; }
function leaves(it: Record<string, unknown>): Leaf[] {
  const out: Leaf[] = [];
  const visit = (obj: Record<string, unknown>, prefix: string) => {
    for (const [k, v] of Object.entries(obj)) {
      if (META_HIDE.has(k.toLowerCase())) continue;
      const path = prefix ? `${prefix}.${k}` : k;
      if (typeof v === 'string' || typeof v === 'number') {
        if (String(v).length) out.push({ path, key: k, value: String(v), isString: typeof v === 'string' });
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        visit(v as Record<string, unknown>, path);
      }
    }
  };
  visit(it, '');
  return out;
}
function setByPath(obj: Record<string, unknown>, path: string, value: string) {
  const segs = path.split('.');
  let cur: Record<string, unknown> = obj;
  for (let i = 0; i < segs.length - 1; i++) cur = cur[segs[i]] as Record<string, unknown>;
  cur[segs[segs.length - 1]] = value;
}

/** Stamp an edited item so the apps' merge (which compares `updatedAt`) keeps it. */
function touchItem(it: Record<string, unknown>) {
  const now = new Date().toISOString();
  const meta = it.meta as Record<string, unknown> | undefined;
  if ('updatedAt' in it) it.updatedAt = now;
  if (meta && 'updatedAt' in meta) meta.updatedAt = now;
  if ('lastModifiedDevice' in it) it.lastModifiedDevice = 'web';
  if (meta && 'lastModifiedDevice' in meta) meta.lastModifiedDevice = 'web';
}

function fieldRow(ii: number, leaf: Leaf, editable: boolean): string {
  const secret = SECRET.test(leaf.key);
  const id = `f${ii}_${leaf.path.replace(/\W/g, '_')}`;
  if (editable && leaf.isString) {
    return `<div class="field">
      <span class="k">${esc(leaf.key)}</span>
      <input class="v" id="${id}" type="${secret ? 'password' : 'text'}" value="${esc(leaf.value)}"
             data-ii="${ii}" data-path="${esc(leaf.path)}" autocomplete="off" spellcheck="false" />
      ${secret ? `<button class="small ghost reveal" data-for="${id}">👁</button>` : ''}
    </div>`;
  }
  const shown = secret ? '••••••••' : esc(leaf.value);
  return `<div class="field">
    <span class="k">${esc(leaf.key)}</span>
    <span class="v" id="${id}" data-secret="${esc(leaf.value)}" data-masked="${secret}">${shown}</span>
    ${secret ? `<button class="small ghost reveal" data-for="${id}">Reveal</button>` : ''}
    <button class="small ghost copy" data-for="${id}">Copy</button>
  </div>`;
}

function itemCard(it: Record<string, unknown>, ii: number, editable: boolean): string {
  const name = displayName(it);
  const fields = leaves(it);
  const sub = fields.find((f) => /user|email|url|login/i.test(f.key) && !SECRET.test(f.key))?.value ?? itemType(it);
  return `<div class="item" data-name="${esc(name.toLowerCase())} ${esc(sub.toLowerCase())}">
    <div class="item-head">
      <div class="avatar">${esc((name[0] ?? '?').toUpperCase())}</div>
      <div class="item-main"><div class="item-name">${esc(name)}</div><div class="item-sub">${esc(sub)}</div></div>
      <div class="chev">›</div>
    </div>
    <div class="item-body">${fields.map((f) => fieldRow(ii, f, editable)).join('')}</div>
  </div>`;
}

function wireItemEvents(node: HTMLElement, editable: boolean, onDirty: () => void) {
  node.querySelectorAll<HTMLElement>('.item-head').forEach((h) => {
    h.onclick = () => h.parentElement!.classList.toggle('open');
  });
  node.querySelectorAll<HTMLButtonElement>('.reveal').forEach((b) => {
    b.onclick = (e) => {
      e.stopPropagation();
      const v = node.querySelector<HTMLElement>(`#${b.dataset.for}`)!;
      if (v instanceof HTMLInputElement) {
        v.type = v.type === 'password' ? 'text' : 'password';
      } else {
        const masked = v.dataset.masked === 'true';
        v.textContent = masked ? v.dataset.secret! : '••••••••';
        v.dataset.masked = masked ? 'false' : 'true';
        b.textContent = masked ? 'Hide' : 'Reveal';
      }
    };
  });
  node.querySelectorAll<HTMLButtonElement>('.copy').forEach((b) => {
    b.onclick = async (e) => {
      e.stopPropagation();
      const v = node.querySelector<HTMLElement>(`#${b.dataset.for}`)!;
      await navigator.clipboard.writeText(v.dataset.secret ?? v.textContent ?? '');
      toast('Copied');
    };
  });
  if (editable) {
    node.querySelectorAll<HTMLInputElement>('input.v').forEach((inp) => {
      inp.onclick = (e) => e.stopPropagation();
      inp.oninput = () => {
        const ii = Number(inp.dataset.ii);
        setByPath(items[ii], inp.dataset.path!, inp.value);
        touchItem(items[ii]);
        onDirty();
      };
    });
  }
}

function showVault(opts: { editable: boolean; expiresAt?: string }) {
  const until = opts.expiresAt ? new Date(opts.expiresAt).toLocaleTimeString() : '';
  const node = el(`<div>${brand}
    <div class="banner ${opts.editable ? 'rw' : ''}">
      <span class="pill"><span class="dot"></span>${opts.editable ? 'Read &amp; write' : 'Read-only'}${until ? ` · until ${esc(until)}` : ''}</span>
      <span class="actions">
        ${opts.editable ? '<button class="small ghost" id="keep" title="Resume this session after a reload">🔒 Keep</button>' : ''}
        ${opts.editable ? '<button class="small primary" id="save" disabled>Saved</button>' : ''}
        <button class="small ghost" id="end">End</button>
      </span>
    </div>
    <h1>Your vault</h1>
    <input class="search" id="search" placeholder="Search…" autocomplete="off" />
    <div class="card" id="list">${
      items.length ? items.map((it, i) => itemCard(it, i, opts.editable)).join('') : '<p class="muted">This vault has no items.</p>'
    }</div>
  </div>`);
  render(node);

  node.querySelector<HTMLButtonElement>('#end')!.onclick = () => {
    clearRwStore();
    wipe();
    location.reload();
  };
  node.querySelector<HTMLButtonElement>('#keep')?.addEventListener('click', () => {
    const pin = window.prompt('Set a PIN (min 4 chars) to resume this session if the page reloads:');
    if (pin && pin.length >= 4) {
      persistRw(pin);
      toast('This session will resume on reload');
    } else if (pin !== null) {
      toast('PIN must be at least 4 characters');
    }
  });
  const search = node.querySelector<HTMLInputElement>('#search')!;
  search.oninput = () => {
    const q = search.value.trim().toLowerCase();
    node.querySelectorAll<HTMLElement>('.item').forEach((it) => {
      it.style.display = !q || (it.dataset.name ?? '').includes(q) ? '' : 'none';
    });
  };

  const saveBtn = node.querySelector<HTMLButtonElement>('#save');
  const markDirty = () => {
    dirty = true;
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save';
    }
  };
  wireItemEvents(node, opts.editable, markDirty);

  if (saveBtn) {
    saveBtn.onclick = async () => {
      if (!dirty) return;
      saveBtn.disabled = true;
      saveBtn.textContent = 'Saving…';
      try {
        await saveVault();
        dirty = false;
        saveBtn.textContent = 'Saved';
        toast('Vault saved');
      } catch (e) {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save';
        toast((e as Error).message);
      }
    };
  }
}

// ── RW: authenticate, fetch live vault, save ────────────────────────────────────

async function loadReadWrite(expiresAt?: string) {
  rwExpiresAt = expiresAt;
  showSplash('Connecting to your vault…');
  const challenge = await getChallenge();
  const signature = createAuthSignature(signingSk, sessionId, challenge);
  const tok = await getSessionToken(sessionId, challenge, signature);
  authed = new AuthedSession(tok.token);

  const man = await authed.manifest();

  // Read the chunks the user's apps actually wrote (current → legacy → iOS).
  const dataIds = [...man.keys()].filter((k) => k.startsWith(DATA_PREFIX)).sort();
  let readIds: string[];
  if (dataIds.length) readIds = dataIds;
  else if (man.has('vault-main')) readIds = ['vault-main'];
  else if (man.has('vault')) readIds = ['vault'];
  else readIds = [];

  let json = '';
  for (const id of readIds) {
    const ct = await authed.getChunk(id);
    if (ct) json += decryptVaultChunk(rmsB64, id, bytesToB64(ct));
  }
  items = json ? ((JSON.parse(json) as { items?: Record<string, unknown>[] }).items ?? []) : [];
  showVault({ editable: true, expiresAt });
}

async function saveVault() {
  if (!authed) throw new Error('Session ended');
  const man = await authed.manifest(); // fresh versions for optimistic concurrency
  const pieces = splitUtf8(JSON.stringify({ items, tombstones: [] }), VAULT_CHUNK_PLAINTEXT_SIZE);

  let lamport = Math.max(0, ...[...man.values()].map((m) => m.lamport));
  for (let i = 0; i < pieces.length; i++) {
    const id = dataChunkId(i);
    const ct = b64ToBytes(encryptVaultChunk(rmsB64, id, pieces[i]));
    const existing = man.get(id);
    lamport = Math.max(lamport, existing?.lamport ?? 0) + 1;
    await authed.putChunk(id, ct, existing?.version ?? 0, lamport);
  }

  // Drop stale chunks: extra data chunks if the vault shrank, plus any legacy /
  // iOS single chunks so future reads resolve to `vault-data-*`.
  for (const [id, meta] of man) {
    if (id.startsWith(DATA_PREFIX)) {
      const idx = parseInt(id.slice(DATA_PREFIX.length), 10);
      if (idx >= pieces.length) await authed.deleteChunk(id, meta.version);
    } else if (id === 'vault-main' || id === 'vault') {
      await authed.deleteChunk(id, meta.version);
    }
  }
}

// ── Flow ────────────────────────────────────────────────────────────────────────

async function onGranted(res: PollResponse) {
  if (!res.capsule) return showError('No capsule delivered — try again.');
  let envelope: { mode: string; vault?: { items?: Record<string, unknown>[] }; rms_b64?: string };
  try {
    envelope = JSON.parse(openShare(shareDk, res.capsule));
  } catch (e) {
    return showError(`Could not open your vault: ${(e as Error).message}`);
  }

  if (envelope.mode === 'rw') {
    rmsB64 = envelope.rms_b64 ?? '';
    shareDk = ''; // KEM key no longer needed
    if (!rmsB64) return showError('Read-write grant was missing the vault key.');
    try {
      await loadReadWrite(res.expires_at);
    } catch (e) {
      showError((e as Error).message);
    }
  } else {
    items = (envelope.vault?.items ?? []) as Record<string, unknown>[];
    wipeKeys(); // RO snapshot is self-contained — drop keys but keep the items
    showVault({ editable: false, expiresAt: res.expires_at });
  }
}

async function pollLoop() {
  polling = true;
  while (polling) {
    let res: PollResponse;
    try {
      res = await pollSession(sessionId);
    } catch {
      await sleep(2500);
      continue;
    }
    if (res.status === 'pending') {
      await sleep(2000);
      continue;
    }
    polling = false;
    if (res.status === 'revoked') return showError('This request was declined.');
    if (res.status === 'expired') return showError('This request expired. Start over.');
    if (res.status === 'granted') return onGranted(res);
  }
}

function showResumeScreen(errorMsg?: string) {
  const node = el(`<div>${brand}
    <h1>Resume your session</h1>
    <p class="sub">Enter the PIN you set to continue your read &amp; write session.</p>
    <div class="card">
      ${errorMsg ? `<p class="error">${esc(errorMsg)}</p><div style="height:12px"></div>` : ''}
      <input class="search" id="pin" type="password" placeholder="Session PIN" autocomplete="off" />
      <div style="height:14px"></div>
      <button class="primary" id="go">Resume</button>
      <div style="height:8px"></div>
      <button class="ghost" id="fresh">Start a new session</button>
    </div>
  </div>`);
  render(node);
  const pin = node.querySelector<HTMLInputElement>('#pin')!;
  const submit = async () => {
    if (!pin.value) return;
    showSplash('Resuming…');
    if (!(await restoreRw(pin.value))) showResumeScreen('Wrong PIN, or the session has expired.');
  };
  node.querySelector<HTMLButtonElement>('#go')!.onclick = submit;
  pin.onkeydown = (e) => {
    if (e.key === 'Enter') submit();
  };
  node.querySelector<HTMLButtonElement>('#fresh')!.onclick = () => {
    clearRwStore();
    location.reload();
  };
}

async function start() {
  showSplash('Loading secure core…');
  try {
    await initVela();
    if (sessionStorage.getItem(RW_STORE_KEY)) {
      return showResumeScreen();
    }
    const kem = generateEphemeralKeypair();
    const sign = generateSigningKeypair();
    shareDk = kem.share_dk_b64;
    signingSk = sign.sk_b64;
    linkPayload = { ephemeral_pk: kem.share_ek_b64, web_vk: sign.vk_b64, link_nonce: randomB64(32) };
    sessionId = await startSession(linkPayload);
    await showLinkScreen();
    void pollLoop();
  } catch (e) {
    showError((e as Error).message);
  }
}

void start();
