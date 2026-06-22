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
