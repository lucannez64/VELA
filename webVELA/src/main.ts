import './styles.css';
import QRCode from 'qrcode';
import { initVela, generateEphemeralKeypair, openShare, randomB64 } from './vela';
import { startSession, pollSession, type PollResponse } from './api';

// ── In-memory session secrets (never persisted in this build) ───────────────────
// Phase 4b is read-only: we send no signing key, so the server can only grant RO.
// Read-write (RMS in memory + live sync) arrives in phase 4c.
let shareDk = ''; // ephemeral KEM secret key, to decapsulate the snapshot capsule
let sessionId = '';
let linkPayload = { ephemeral_pk: '', link_nonce: '' };
let polling = false;

const app = document.getElementById('app')!;

function wipe() {
  shareDk = '';
}
window.addEventListener('beforeunload', wipe);

// ── Tiny DOM helpers ────────────────────────────────────────────────────────────
function el(html: string): HTMLElement {
  const t = document.createElement('template');
  t.innerHTML = html.trim();
  return t.content.firstElementChild as HTMLElement;
}
function render(node: HTMLElement) {
  app.replaceChildren(node);
}
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );
}
function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// ── Screens ─────────────────────────────────────────────────────────────────────

function showError(message: string) {
  polling = false;
  const node = el(`<div>
    <h1>VELA — Web Access</h1>
    <div class="card"><p class="error">${escapeHtml(message)}</p>
    <button class="primary" id="retry">Start over</button></div>
  </div>`);
  render(node);
  node.querySelector<HTMLButtonElement>('#retry')!.onclick = () => location.reload();
}

async function showLinkScreen() {
  const qrPayload = JSON.stringify({
    session_id: sessionId,
    ephemeral_pk: linkPayload.ephemeral_pk,
    link_nonce: linkPayload.link_nonce,
  });
  const qrDataUrl = await QRCode.toDataURL(qrPayload, { errorCorrectionLevel: 'M', margin: 2, width: 240 });

  const node = el(`<div>
    <h1>Open your vault here</h1>
    <p class="muted">Temporary, expiring, revocable access — no install, no permanent device.</p>
    <div class="card">
      <h2>1. In the VELA app</h2>
      <p class="muted">Go to <b>Devices / Settings → Web access</b>, then scan this QR (Android) or paste the code below (desktop / iOS). Pick a duration and approve.</p>
      <div class="qr"><img src="${qrDataUrl}" alt="link code" /></div>
      <h2>Or paste this code</h2>
      <div class="code" id="code">${escapeHtml(qrPayload)}</div>
      <p style="margin-top:10px"><button class="small" id="copy">Copy code</button></p>
    </div>
    <div class="card center"><span class="spinner" id="wait">Waiting for approval…</span></div>
  </div>`);
  render(node);
  node.querySelector<HTMLButtonElement>('#copy')!.onclick = async () => {
    await navigator.clipboard.writeText(qrPayload);
    node.querySelector<HTMLButtonElement>('#copy')!.textContent = 'Copied ✓';
  };
}

function displayName(item: Record<string, unknown>): string {
  const meta = item.meta as Record<string, unknown> | undefined;
  return (
    (meta?.name as string) ?? (item.name as string) ?? (item.title as string) ?? '(item)'
  );
}

function itemType(item: Record<string, unknown>): string {
  return (
    (item.type as string) ??
    (item.kind as string) ??
    Object.keys(item).find((k) => k !== 'meta') ??
    'item'
  );
}

/** Pull renderable leaf string/number fields out of an item (shallow + nested meta). */
function itemFields(item: Record<string, unknown>): [string, string][] {
  const out: [string, string][] = [];
  const visit = (obj: Record<string, unknown>) => {
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'id' || k === 'type' || k === 'kind') continue;
      if (typeof v === 'string' || typeof v === 'number') {
        if (String(v).length) out.push([k, String(v)]);
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        visit(v as Record<string, unknown>);
      }
    }
  };
  visit(item);
  return out;
}

function fieldRow(key: string, value: string): string {
  const secret = /pass|pin|cvv|secret|totp|seed|key/i.test(key);
  const vid = `v${Math.random().toString(36).slice(2)}`;
  const shown = secret ? '••••••••' : escapeHtml(value);
  return `<div class="field">
    <span class="k">${escapeHtml(key)}</span>
    <span class="v" id="${vid}" data-secret="${escapeHtml(value)}" data-masked="${secret}">${shown}</span>
    ${secret ? `<button class="small reveal" data-for="${vid}">Reveal</button>` : ''}
    <button class="small copy" data-for="${vid}">Copy</button>
  </div>`;
}

function showVault(items: Record<string, unknown>[], expiresAt?: string) {
  const until = expiresAt ? new Date(expiresAt).toLocaleString() : '';
  const list = items.length
    ? items
        .map(
          (it) => `<div class="item">
            <div class="item-head"><span class="item-name">${escapeHtml(displayName(it))}</span>
              <span class="item-type">${escapeHtml(itemType(it))}</span></div>
            <div class="item-body">${itemFields(it).map(([k, v]) => fieldRow(k, v)).join('')}</div>
          </div>`,
        )
        .join('')
    : '<p class="muted">This vault has no items.</p>';

  const node = el(`<div>
    <div class="banner"><span>🔒 Read-only${until ? ` · expires ${escapeHtml(until)}` : ''}</span>
      <button class="small" id="end">End session</button></div>
    <h1>Your vault</h1>
    <div class="card">${list}</div>
  </div>`);
  render(node);

  node.querySelector<HTMLButtonElement>('#end')!.onclick = () => location.reload();
  node.querySelectorAll<HTMLElement>('.item-head').forEach((h) => {
    h.onclick = () => h.parentElement!.classList.toggle('open');
  });
  node.querySelectorAll<HTMLButtonElement>('.reveal').forEach((b) => {
    b.onclick = () => {
      const v = node.querySelector<HTMLElement>(`#${b.dataset.for}`)!;
      const masked = v.dataset.masked === 'true';
      v.textContent = masked ? v.dataset.secret! : '••••••••';
      v.dataset.masked = masked ? 'false' : 'true';
      b.textContent = masked ? 'Hide' : 'Reveal';
    };
  });
  node.querySelectorAll<HTMLButtonElement>('.copy').forEach((b) => {
    b.onclick = async () => {
      const v = node.querySelector<HTMLElement>(`#${b.dataset.for}`)!;
      await navigator.clipboard.writeText(v.dataset.secret!);
      b.textContent = 'Copied ✓';
      setTimeout(() => (b.textContent = 'Copy'), 1500);
    };
  });
}

// ── Flow ────────────────────────────────────────────────────────────────────────

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
    if (res.status === 'granted') {
      if (!res.capsule) return showError('No capsule delivered — try again.');
      try {
        const inner = openShare(shareDk, res.capsule);
        const envelope = JSON.parse(inner) as { mode: string; vault?: { items?: unknown[] } };
        wipe(); // we now hold a plaintext snapshot; the KEM key is no longer needed
        if (envelope.mode !== 'ro') {
          return showError('Read-write web sessions are not supported yet; ask for read-only.');
        }
        showVault((envelope.vault?.items ?? []) as Record<string, unknown>[], res.expires_at);
      } catch (e) {
        showError(`Could not open your vault: ${(e as Error).message}`);
      }
      return;
    }
  }
}

async function start() {
  render(el(`<div class="center"><h1>VELA</h1><p class="spinner">Loading secure core…</p></div>`));
  try {
    await initVela();
    const kem = generateEphemeralKeypair();
    shareDk = kem.share_dk_b64;
    linkPayload = { ephemeral_pk: kem.share_ek_b64, link_nonce: randomB64(32) };
    sessionId = await startSession({
      ephemeral_pk: linkPayload.ephemeral_pk,
      link_nonce: linkPayload.link_nonce,
    });
    await showLinkScreen();
    void pollLoop();
  } catch (e) {
    showError((e as Error).message);
  }
}

void start();
