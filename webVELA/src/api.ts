// Server calls for the ephemeral web session. The SPA is served same-origin as
// the API, so all paths are relative (`connect-src 'self'` in the CSP).
//
// For local dev against a remote server, set `VITE_API_BASE`.
const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '';

export interface StartRequest {
  ephemeral_pk: string;
  web_vk?: string;
  link_nonce: string;
}

export async function startSession(body: StartRequest): Promise<string> {
  const r = await fetch(`${BASE}/web-session/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`Could not start session (HTTP ${r.status})`);
  return ((await r.json()) as { session_id: string }).session_id;
}

export interface PollResponse {
  status: 'pending' | 'granted' | 'revoked' | 'expired';
  mode?: 'ro' | 'rw';
  capsule?: string;
  expires_at?: string;
}

export async function pollSession(id: string): Promise<PollResponse> {
  const r = await fetch(`${BASE}/web-session/${id}`);
  if (!r.ok) throw new Error(`Poll failed (HTTP ${r.status})`);
  return (await r.json()) as PollResponse;
}

export async function getChallenge(): Promise<string> {
  const r = await fetch(`${BASE}/auth/challenge`);
  if (!r.ok) throw new Error(`Challenge failed (HTTP ${r.status})`);
  return ((await r.json()) as { challenge: string }).challenge;
}

export interface TokenResponse {
  token: string;
  user_id: string;
  expires_at: string;
}

export async function getSessionToken(id: string, challenge: string, signature: string): Promise<TokenResponse> {
  const r = await fetch(`${BASE}/web-session/${id}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge, signature }),
  });
  if (!r.ok) throw new Error(`Token request failed (HTTP ${r.status})`);
  return (await r.json()) as TokenResponse;
}

// ── Authenticated vault sync (RW) ───────────────────────────────────────────────
//
// A tiny session that carries the PASETO bearer and adopts a rotated token from
// the `X-New-Token` response header.

export interface ChunkMeta {
  version: number;
  lamport: number;
}

export class AuthedSession {
  constructor(public token: string) {}

  private async req(method: string, path: string, body?: BodyInit, headers: Record<string, string> = {}) {
    const r = await fetch(`${BASE}${path}`, {
      method,
      headers: { Authorization: `Bearer ${this.token}`, ...headers },
      body,
    });
    const renewed = r.headers.get('X-New-Token');
    if (renewed) this.token = renewed;
    return r;
  }

  /** All vault chunks the server holds, keyed by chunk id. */
  async manifest(): Promise<Map<string, ChunkMeta>> {
    const r = await this.req('GET', '/vault/sync');
    if (!r.ok) throw new Error(`Sync failed (HTTP ${r.status})`);
    const m = (await r.json()) as { chunks: { chunk_id: string; version: number; lamport_clock: number }[] };
    const out = new Map<string, ChunkMeta>();
    for (const c of m.chunks) out.set(c.chunk_id, { version: c.version, lamport: c.lamport_clock });
    return out;
  }

  /** Fetch a chunk's raw ciphertext bytes (null on 404). */
  async getChunk(chunkId: string): Promise<Uint8Array | null> {
    const r = await this.req('GET', `/vault/chunk/${chunkId}`);
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`Chunk fetch failed (HTTP ${r.status})`);
    return new Uint8Array(await r.arrayBuffer());
  }

  /** Upload a chunk (raw ciphertext bytes). Returns the new version. */
  async putChunk(chunkId: string, ciphertext: Uint8Array, ifMatch: number, lamport: number): Promise<number> {
    const r = await this.req('PUT', `/vault/chunk/${chunkId}`, ciphertext as BodyInit, {
      'Content-Type': 'application/octet-stream',
      'If-Match': String(ifMatch),
      'X-Lamport-Clock': String(lamport),
    });
    if (r.status === 409) throw new Error('The vault changed on another device — reload to get the latest.');
    if (!r.ok) throw new Error(`Save failed (HTTP ${r.status})`);
    const body = (await r.json().catch(() => ({}))) as { version?: number };
    return body.version ?? ifMatch + 1;
  }

  /** Delete a stale chunk (best-effort). */
  async deleteChunk(chunkId: string, ifMatch: number): Promise<void> {
    await this.req('DELETE', `/vault/chunk/${chunkId}`, undefined, { 'If-Match': String(ifMatch) });
  }
}
