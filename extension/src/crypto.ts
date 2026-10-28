import { ed25519 } from '@noble/curves/ed25519';
import { blake3 } from '@noble/hashes/blake3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

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
// Format: base64( salt(16) || nonce(12) || AES-256-GCM ciphertext )
// KDF: PBKDF2-SHA256, 300k iterations
// Compatible only with extension storage — not the Argon2id .keystone file format.
// Import from .keystone file (Argon2id) is Layer 3.

export async function encryptSeed(seed: Uint8Array, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, new Uint8Array(seed))
  );
  const blob = new Uint8Array(28 + ct.length);
  blob.set(salt, 0);
  blob.set(nonce, 16);
  blob.set(ct, 28);
  return btoa(String.fromCharCode(...blob));
}

export async function decryptSeed(b64: string, password: string): Promise<Uint8Array> {
  const blob = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt = blob.slice(0, 16);
  const nonce = blob.slice(16, 28);
  const ct = blob.slice(28);
  const key = await deriveKey(password, salt);
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ct);
    return new Uint8Array(pt);
  } catch {
    throw new Error('Wrong password or corrupted key');
  }
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new Uint8Array(salt), iterations: 300_000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
