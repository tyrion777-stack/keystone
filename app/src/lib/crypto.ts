import { ed25519 } from '@noble/curves/ed25519.js';
import { blake3 } from '@noble/hashes/blake3.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

// 32 MB on mobile — lighter than extension (64 MB) for lower-end devices
const ARGON2_PARAMS = { m: 32768, t: 3, p: 1, dkLen: 32 };

// Blob: 0x02 || salt(16) || nonce(12) || ciphertext+tag(48) — stored as hex
const V2_MARKER = 0x02;

export function generateSeed(): Uint8Array {
	return crypto.getRandomValues(new Uint8Array(32));
}

export function getPublicKeyHex(seed: Uint8Array): string {
	return bytesToHex(ed25519.getPublicKey(seed));
}

export function seedFromHex(hex: string): Uint8Array {
	const bytes = hexToBytes(hex);
	if (bytes.length !== 32) throw new Error('Must be 64 hex characters (32 bytes)');
	return bytes;
}

// Mirrors Identity::sign() in keystone-core exactly:
//   blake3(challenge) → hex → ed25519.sign(utf8(hex), seed)
export function signChallenge(seed: Uint8Array, challenge: string): string {
	const hashHex = bytesToHex(blake3(new TextEncoder().encode(challenge)));
	return bytesToHex(ed25519.sign(new TextEncoder().encode(hashHex), seed));
}

export function encryptSeed(seed: Uint8Array, password: string): string {
	const salt  = crypto.getRandomValues(new Uint8Array(16));
	const nonce = crypto.getRandomValues(new Uint8Array(12));
	const key   = argon2id(new TextEncoder().encode(password), salt, ARGON2_PARAMS);
	const ct    = gcm(key, nonce).encrypt(seed);
	const blob  = new Uint8Array(1 + 16 + 12 + ct.length);
	blob[0] = V2_MARKER;
	blob.set(salt,  1);
	blob.set(nonce, 17);
	blob.set(ct,    29);
	return bytesToHex(blob);
}

export function decryptSeed(hex: string, password: string): Uint8Array {
	const blob  = hexToBytes(hex);
	if (blob[0] !== V2_MARKER) throw new Error('Unknown key format');
	const salt  = blob.slice(1,  17);
	const nonce = blob.slice(17, 29);
	const ct    = blob.slice(29);
	const key   = argon2id(new TextEncoder().encode(password), salt, ARGON2_PARAMS);
	try {
		return gcm(key, nonce).decrypt(ct);
	} catch {
		throw new Error('Wrong password');
	}
}
