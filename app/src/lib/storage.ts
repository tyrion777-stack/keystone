const KEY_SEED   = 'ks_encrypted_seed';
const KEY_PUBKEY = 'ks_pubkey_hex';

export function hasKey(): boolean {
	return !!localStorage.getItem(KEY_SEED);
}

export function saveKey(encryptedHex: string, pubkeyHex: string): void {
	localStorage.setItem(KEY_SEED,   encryptedHex);
	localStorage.setItem(KEY_PUBKEY, pubkeyHex);
}

export function loadEncryptedSeed(): string | null {
	return localStorage.getItem(KEY_SEED);
}

export function loadPubkey(): string | null {
	return localStorage.getItem(KEY_PUBKEY);
}

export function clearKey(): void {
	localStorage.removeItem(KEY_SEED);
	localStorage.removeItem(KEY_PUBKEY);
}
