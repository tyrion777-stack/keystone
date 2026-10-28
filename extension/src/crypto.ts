import { ed25519 } from '@noble/curves/ed25519';
import { blake3 } from '@noble/hashes/blake3';
import { argon2id } from '@noble/hashes/argon2';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

// Argon2id: 64 MiB, 3 passes. Stronger than keystone-core, which uses the argon2 crate's
// defaults (19 MiB, 2 passes); the two blob formats are not interchangeable either way.
const ARGON2_PARAMS = { m: 65536, t: 3, p: 1, dkLen: 32 };

// Blob formats (decoded):
//   v1 (PBKDF2 legacy): salt(16) || nonce(12) || ciphertext(48) = 76 bytes, no marker
//   v2 (Argon2id):      0x02 || salt(16) || nonce(12) || ciphertext(48) = 77 bytes
const V1_LEN = 76;
const V2_MARKER = 0x02;

export function needsMigration(b64: string): boolean {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).length === V1_LEN;
}

// --- Key generation & derivation ---

export function generateSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export function getPublicKeyHex(seed: Uint8Array): string {
  return bytesToHex(ed25519.getPublicKey(seed));
}

export function seedFromHex(hex: string): Uint8Array {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) throw new Error('Private key must be 32 bytes (64 hex chars)');
  return bytes;
}

// --- Signing ---
// Mirrors Identity::sign() in keystone-core/src/identity.rs exactly:
//   1. Blake3 hash the challenge string
//   2. Hex-encode the hash
//   3. Ed25519 sign the hex string as UTF-8 bytes

export function signChallenge(seed: Uint8Array, challenge: string): string {
  const hashBytes = blake3(new TextEncoder().encode(challenge));
  const hashHex = bytesToHex(hashBytes);
  const sig = ed25519.sign(new TextEncoder().encode(hashHex), seed);
  return bytesToHex(sig);
}

// --- Encrypted key storage ---

export async function encryptSeed(seed: Uint8Array, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const rawKey = argon2id(new TextEncoder().encode(password), salt, ARGON2_PARAMS);
  const aesKey = await crypto.subtle.importKey('raw', new Uint8Array(rawKey), 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, new Uint8Array(seed))
  );
  // v2 blob: 0x02 marker || salt(16) || nonce(12) || ciphertext
  const blob = new Uint8Array(1 + 16 + 12 + ct.length);
  blob[0] = V2_MARKER;
  blob.set(salt, 1);
  blob.set(nonce, 17);
  blob.set(ct, 29);
  return btoa(String.fromCharCode(...blob));
}

export async function decryptSeed(b64: string, password: string): Promise<Uint8Array> {
  const blob = Uint8Array.from(atob(b64), c => c.charCodeAt(0));

  if (blob.length === V1_LEN) {
    return decryptV1Pbkdf2(blob, password);
  }

  if (blob[0] !== V2_MARKER) throw new Error('Unknown key format');
  const salt = blob.slice(1, 17);
  const nonce = blob.slice(17, 29);
  const ct = blob.slice(29);
  const rawKey = argon2id(new TextEncoder().encode(password), salt, ARGON2_PARAMS);
  const aesKey = await crypto.subtle.importKey('raw', new Uint8Array(rawKey), 'AES-GCM', false, ['decrypt']);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ct);
    return new Uint8Array(pt);
  } catch {
    throw new Error('Wrong password or corrupted key');
  }
}

// One-time migration path: decrypt legacy PBKDF2-SHA256 blobs
async function decryptV1Pbkdf2(blob: Uint8Array, password: string): Promise<Uint8Array> {
  const salt = blob.slice(0, 16);
  const nonce = blob.slice(16, 28);
  const ct = blob.slice(28);
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'],
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new Uint8Array(salt), iterations: 300_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ct);
    return new Uint8Array(pt);
  } catch {
    throw new Error('Wrong password or corrupted key');
  }
}
