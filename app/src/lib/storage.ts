import type { Pins } from './requests';

const KEY_SEED   = 'ks_encrypted_seed';
const KEY_PUBKEY = 'ks_pubkey_hex';
const KEY_PINS   = 'ks_service_pins';

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

// Service keys pinned per origin (requests.ts). Unreadable means none: every service is new
// again, which asks more of the person, never less.
export function loadPins(): Pins {
	try {
		const pins = JSON.parse(localStorage.getItem(KEY_PINS) ?? '{}');
		return typeof pins === 'object' && pins !== null ? (pins as Pins) : {};
	} catch {
		return {};
	}
}

export function savePins(pins: Pins): void {
	localStorage.setItem(KEY_PINS, JSON.stringify(pins));
}
