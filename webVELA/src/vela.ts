// Thin typed wrappers over the `vela-wasm-bridge` (JSON-in/JSON-out). The VELA
// core runs entirely in this browser tab; the server never sees plaintext.
import init, {
  generate_ephemeral_keypair,
  generate_signing_keypair,
  create_auth_signature_json,
  open_share_json,
  encrypt_vault_chunk_json,
  decrypt_vault_chunk_json,
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

/** Decapsulate a sealed capsule (RO snapshot or RW chunk keys) → the inner JSON string. */
export function openShare(shareDkB64: string, capsuleB64: string): string {
  return parse<{ item_json: string }>(
    open_share_json(JSON.stringify({ share_dk_b64: shareDkB64, capsule_b64: capsuleB64 })),
  ).item_json;
}

// The chunk key is the one the approver granted for that exact chunk id; this
// browser never holds the RMS the keys are derived from (audit D-2).

/** Decrypt a vault chunk → its `VaultStore` JSON (RW live read). */
export function decryptVaultChunk(chunkKeyB64: string, ciphertextB64: string): string {
  return parse<{ vault_json: string }>(
    decrypt_vault_chunk_json(JSON.stringify({ chunk_key_b64: chunkKeyB64, ciphertext_b64: ciphertextB64 })),
  ).vault_json;
}

/** Encrypt a vault chunk for upload → base64 ciphertext (RW save). */
export function encryptVaultChunk(chunkKeyB64: string, vaultJson: string): string {
  return parse<{ ciphertext_b64: string }>(
    encrypt_vault_chunk_json(JSON.stringify({ chunk_key_b64: chunkKeyB64, vault_json: vaultJson })),
  ).ciphertext_b64;
}

/** base64 ↔ bytes helpers for the raw chunk wire format. */
export function bytesToB64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
// The `ArrayBuffer` type argument is what lets callers hand the result straight
// to WebCrypto: a plain `Uint8Array` is generic over `ArrayBufferLike`, which
// `BufferSource` rejects because it could be a `SharedArrayBuffer`. This one
// never is.
export function b64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** A cryptographically-random base64 string of `n` bytes (browser RNG). */
export function randomB64(n: number): string {
  const bytes = new Uint8Array(n);
  crypto.getRandomValues(bytes);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
