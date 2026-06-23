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
let chunkVersion = 0;
let chunkLamport = 0;
let dirty = false;

const app = document.getElementById('app')!;

function wipe() {
  shareDk = '';
  signingSk = '';
  rmsB64 = '';
  authed = null;
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

interface Leaf { path: string; key: string; value: string; isString: boolean; }
function leaves(it: Record<string, unknown>): Leaf[] {
  const out: Leaf[] = [];
  const visit = (obj: Record<string, unknown>, prefix: string) => {
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'id' || k === 'type' || k === 'kind') continue;
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
    wipe();
    location.reload();
  };
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
  showSplash('Connecting to your vault…');
  const challenge = await getChallenge();
  const signature = createAuthSignature(signingSk, sessionId, challenge);
  const tok = await getSessionToken(sessionId, challenge, signature);
  authed = new AuthedSession(tok.token);

  const chunk = await authed.getVaultChunk();
  if (chunk) {
    const vaultJson = decryptVaultChunk(rmsB64, 'vault', bytesToB64(chunk.ciphertext));
    const store = JSON.parse(vaultJson) as { items?: Record<string, unknown>[] };
    items = store.items ?? [];
    chunkVersion = chunk.version;
    chunkLamport = chunk.lamport;
  } else {
    items = [];
    chunkVersion = 0;
    chunkLamport = 0;
  }
  showVault({ editable: true, expiresAt });
}

async function saveVault() {
  if (!authed) throw new Error('Session ended');
  const store = JSON.stringify({ items, tombstones: [] });
  const ctB64 = encryptVaultChunk(rmsB64, 'vault', store);
  const ct = b64ToBytes(ctB64);
  chunkVersion = await authed.putVaultChunk(ct, chunkVersion, chunkLamport + 1);
  chunkLamport += 1;
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
    wipe();
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

async function start() {
  showSplash('Loading secure core…');
  try {
    await initVela();
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
