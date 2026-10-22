// Recipient page for a one-off VELA share link.
//
// The decryption key arrives in the URL fragment (`#…`), which the browser never
// sends to the server. We strip it from the address bar immediately, fetch the
// opaque ciphertext, and decrypt locally in WASM. The server cannot read either
// half.
import { initVela, openLink } from './vela';
import './send.css';

interface SendPayload {
  ciphertext: string;
  has_passphrase: boolean;
  kdf_salt?: string;
  view_once: boolean;
  max_views?: number;
  views_remaining?: number;
  expires_at: string;
}

interface Secret {
  custom_fields?: {label:string;type:string;value:unknown}[];
  additional_urls?: {url:string;match:string}[];
  v?: number;
  kind?: string;
  name?: string;
  username?: string;
  password?: string;
  url?: string;
  notes?: string;
  totp?: string;
}

const app = document.getElementById('app')!;

const params = new URLSearchParams(location.search);
const id = params.get('id') ?? '';
let linkKey = location.hash.replace(/^#/, '');

// Never leave the key in the address bar or the browser's session history.
if (linkKey) {
  history.replaceState(null, '', location.pathname + location.search);
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { class: className, ...rest } = props as Record<string, unknown>;
  if (className) node.className = className as string;
  Object.assign(node, rest);
  for (const child of children) {
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

function brand(): HTMLElement {
  return el('div', { class: 'brand' }, [
    el('span', { innerHTML: '<svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7l-9-5z" fill="currentColor"/></svg>' }),
    el('span', { class: 'brand-name' }, ['VELA']),
  ]);
}

function card(...children: (Node | string)[]): HTMLElement {
  return el('div', { class: 'card' }, [brand(), ...children]);
}

function render(...children: (Node | string)[]): void {
  app.replaceChildren(card(...children));
}

function renderMessage(title: string, message: string, isError = false): void {
  render(
    el('h1', { class: 'title' }, [title]),
    el('p', { class: isError ? 'error' : 'subtitle' }, [message]),
  );
}

function field(label: string, value: string, opts: { secret?: boolean; copy?: boolean } = {}): HTMLElement {
  const valueEl = el('span', { class: opts.secret ? 'field-value secret' : 'field-value' });
  valueEl.textContent = value;

  if (opts.copy) {
    const btn = el('button', { class: 'ghost', type: 'button' }, ['Copy']);
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value);
        btn.textContent = 'Copied';
        setTimeout(() => (btn.textContent = 'Copy'), 1500);
      } catch {
        /* clipboard unavailable; the value is visible to select manually */
      }
    });
    valueEl.append(btn);
  }

  return el('div', { class: 'field' }, [
    el('div', { class: 'field-label' }, [label]),
    valueEl,
  ]);
}

function renderSecret(secret: Secret, meta: SendPayload): void {
  const children: (Node | string)[] = [];
  const title = secret.name || secret.username || 'Shared secret';
  children.push(el('h1', { class: 'title' }, [title]));
  children.push(
    el('p', { class: 'subtitle' }, ['This is a secret shared with you through VELA. It stays encrypted until this page opens it, in your browser.']),
  );

  if (secret.username) children.push(field('Username', secret.username, { copy: true }));
  if (secret.password) children.push(field('Password', secret.password, { secret: true, copy: true }));
  if (secret.totp) children.push(field('One-time code secret', secret.totp, { secret: true, copy: true }));
  if (secret.url) {
    const link = el('a', { class: 'field-value secret', href: secret.url, rel: 'noopener noreferrer', target: '_blank' });
    link.textContent = secret.url;
    children.push(el('div', { class: 'field' }, [el('div', { class: 'field-label' }, ['Website']), link]));
  }
  if (secret.notes) children.push(field('Notes', secret.notes));
  for (const entry of secret.custom_fields ?? []) {
    if (['text','concealed','boolean'].includes(entry.type)) {
      const node=field(entry.label,entry.type==='concealed'?'••••••••':String(entry.value ?? ''),{copy:entry.type!=='concealed'});
      if(entry.type==='concealed'){const reveal=el('button',{type:'button',class:'ghost'},['Reveal']);let shown=false;reveal.onclick=()=>{shown=!shown;node.querySelector('.field-value')!.textContent=shown?String(entry.value ?? ''):'••••••••';reveal.textContent=shown?'Hide':'Reveal';};node.append(reveal);}
      children.push(node);
    }
  }
  for (const site of secret.additional_urls ?? []) children.push(field(`Additional site (${site.match})`,site.url,{copy:true}));

  const notices: string[] = [];
  if (meta.view_once) notices.push('This link was view-once, so the server has already deleted it.');
  else if (typeof meta.views_remaining === 'number') notices.push(`This link allows ${meta.views_remaining} more view(s).`);
  notices.push(`Expires ${new Date(meta.expires_at).toLocaleString()}.`);
  children.push(el('div', { class: 'notice' }, [notices.join(' ')]));

  render(...children);
}

async function load(): Promise<void> {
  if (!id || !linkKey) {
    renderMessage(
      'Link is incomplete',
      'This share link is missing its key or id. Ask the sender for a fresh link — the part after "#" is required.',
      true,
    );
    return;
  }

  render(el('h1', { class: 'title' }, ['Loading shared secret…']), el('div', { class: 'spinner' }));

  let payload: SendPayload;
  try {
    const response = await fetch(`/send/${encodeURIComponent(id)}`);
    if (response.status === 404) {
      renderMessage(
        'Link unavailable',
        'This link has expired, been revoked, or already been viewed. Ask the sender for a new one.',
        true,
      );
      return;
    }
    if (!response.ok) {
      renderMessage('Could not load', `The server returned HTTP ${response.status}.`, true);
      return;
    }
    payload = (await response.json()) as SendPayload;
  } catch {
    renderMessage('Could not load', 'The server could not be reached. Check your connection and try again.', true);
    return;
  }

  try {
    await initVela();
  } catch {
    renderMessage('Cannot open', 'This browser could not start the VELA decryption module.', true);
    return;
  }

  const tryDecrypt = (passphrase: string | null): Secret | null => {
    try {
      const json = openLink(linkKey, passphrase, payload.kdf_salt ?? null, payload.ciphertext);
      return JSON.parse(json) as Secret;
    } catch {
      return null;
    }
  };

  if (!payload.has_passphrase) {
    const secret = tryDecrypt(null);
    if (secret) renderSecret(secret, payload);
    else
      renderMessage(
        'Cannot decrypt',
        'The key in this link does not match the encrypted secret. Ask the sender for a new link.',
        true,
      );
    return;
  }

  // Passphrase-protected: prompt, and retry locally against the ciphertext we
  // already hold (a wrong passphrase does not refetch).
  const input = el('input', { type: 'password', placeholder: 'Passphrase' });
  const error = el('p', { class: 'error hidden' }, ['That passphrase did not work.']);
  const submit = el('button', { class: 'primary', type: 'button' }, ['Decrypt']);
  const attempt = () => {
    const secret = tryDecrypt(input.value);
    if (secret) {
      renderSecret(secret, payload);
    } else {
      error.classList.remove('hidden');
      input.focus();
    }
  };
  submit.addEventListener('click', attempt);
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') attempt();
  });

  render(
    el('h1', { class: 'title' }, ['Protected link']),
    el('p', { class: 'subtitle' }, ['The sender protected this secret with a passphrase. Enter it to decrypt.']),
    el('div', { class: 'field' }, [input]),
    error,
    el('div', { class: 'actions' }, [submit]),
  );
  input.focus();
}

void load();
