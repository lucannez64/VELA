// Thin typed wrappers over the `vela-wasm-bridge` (JSON-in/JSON-out). The VELA
// core runs entirely in this browser tab; the server never sees plaintext.
import init, {
  generate_ephemeral_keypair,
  generate_signing_keypair,
  create_auth_signature_json,
  open_share_json,
  open_link_json,
  encrypt_vault_chunk_json,
  decrypt_admitted_vault_chunk_json,
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

/**
 * Open a one-off share-link payload → the inner JSON string.
 *
 * The `linkKeyB64` came from the URL fragment, which the server never received;
 * a passphrase-protected link additionally needs the passphrase.
 */
export function openLink(
  linkKeyB64: string,
  passphrase: string | null,
  saltB64: string | null,
  ciphertextB64: string,
): string {
  return parse<{ secret_json: string }>(
    open_link_json(
      JSON.stringify({
        link_key_b64: linkKeyB64,
        passphrase,
        salt_b64: saltB64,
        ciphertext_b64: ciphertextB64,
      }),
    ),
  ).secret_json;
}

// The chunk key is the one the approver granted for that exact chunk id; this
// browser never holds the RMS the keys are derived from (audit D-2).

/**
 * Admit and decrypt a vault chunk → its `VaultStore` JSON (RW live read).
 *
 * This is the only download entry point: the Rust bridge refuses unsealed
 * legacy blobs (they bind neither chunk nor revision), pins the first vault key
 * epoch this tab admits and refuses any other epoch, and refuses a revision
 * below the highest one it already admitted for this chunk. `chunkId`,
 * `lamportClock` and `epoch` are the labels the server put on the chunk; the
 * AAD check and the verified policies are what make them trustworthy.
 *
 * The epoch pin and the per-chunk floors live in WASM memory only — the web
 * client has no durable store, so a reload is a new first contact.
 */
export function admitVaultChunk(
  chunkKeyB64: string,
  ciphertextB64: string,
  chunkId: string,
  lamportClock: number,
  epoch: number,
): { vaultJson: string; lamportClock: number } {
  const admitted = parse<{ vault_json: string; lamport_clock: number }>(
    decrypt_admitted_vault_chunk_json(
      JSON.stringify({
        chunk_key_b64: chunkKeyB64,
        ciphertext_b64: ciphertextB64,
        chunk_id: chunkId,
        lamport_clock: lamportClock,
        key_epoch: epoch,
      }),
    ),
  );
  return { vaultJson: admitted.vault_json, lamportClock: admitted.lamport_clock };
}

/**
 * Encrypt a vault chunk for upload → base64 ciphertext (RW save).
 *
 * `chunkId` and `lamportClock` are sealed into the ciphertext so the server
 * cannot serve an older revision back as if it were current (audit C-2, rollout
 * step 3). `lamportClock` must be the clock actually sent with the upload, or
 * the result will not decrypt.
 */
export function encryptVaultChunk(
  chunkKeyB64: string,
  vaultJson: string,
  chunkId: string,
  lamportClock: number,
  epoch: number,
): string {
  return parse<{ ciphertext_b64: string }>(
    encrypt_vault_chunk_json(
      JSON.stringify({
        chunk_key_b64: chunkKeyB64,
        vault_json: vaultJson,
        chunk_id: chunkId,
        lamport_clock: lamportClock,
        epoch,
      }),
    ),
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
