// Thin typed wrappers over the `vela-wasm-bridge` (JSON-in/JSON-out). The VELA
// core runs entirely in this browser tab; the server never sees plaintext.
import init, {
  generate_ephemeral_keypair,
  generate_signing_keypair,
  create_auth_signature_json,
  open_share_json,
  argon2_wrap_json,
  argon2_unwrap_json,
} from './wasm/vela_wasm_bridge.js';

let ready: Promise<void> | null = null;

/** Instantiate the WebAssembly module (idempotent). */
export function initVela(): Promise<void> {
  if (!ready) ready = init().then(() => undefined);
  return ready;
}

function parse<T>(json: string): T {
  const v = JSON.parse(json) as T & { error?: string };
  if (v.error) throw new Error(v.error);
  return v;
}

export function generateEphemeralKeypair(): { share_ek_b64: string; share_dk_b64: string } {
  return parse(generate_ephemeral_keypair());
}

export function generateSigningKeypair(): { vk_b64: string; sk_b64: string } {
  return parse(generate_signing_keypair());
}

export function createAuthSignature(skB64: string, deviceId: string, challengeB64: string): string {
  return parse<{ signature_b64: string }>(
    create_auth_signature_json(JSON.stringify({ sk_b64: skB64, device_id: deviceId, challenge_b64: challengeB64 })),
  ).signature_b64;
}

/** Decapsulate a sealed capsule (RO snapshot or RW RMS) → the inner JSON string. */
export function openShare(shareDkB64: string, capsuleB64: string): string {
  return parse<{ item_json: string }>(
    open_share_json(JSON.stringify({ share_dk_b64: shareDkB64, capsule_b64: capsuleB64 })),
  ).item_json;
}

/** Argon2id-wrap bytes under a PIN (RW reload survival, design §8.1). */
export function argon2Wrap(pin: string, plaintextB64: string): string {
  return parse<{ blob_b64: string }>(argon2_wrap_json(JSON.stringify({ pin, plaintext_b64: plaintextB64 }))).blob_b64;
}

export function argon2Unwrap(pin: string, blobB64: string): string {
  return parse<{ plaintext_b64: string }>(argon2_unwrap_json(JSON.stringify({ pin, blob_b64: blobB64 }))).plaintext_b64;
}

/** A cryptographically-random base64 string of `n` bytes (browser RNG). */
export function randomB64(n: number): string {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
