// Decrypted seed kept in memory only — never written to storage
let _seed:   Uint8Array | null = $state(null);
let _pubkey: string | null     = $state(null);

export const session = {
	get seed()   { return _seed; },
	get pubkey() { return _pubkey; },
	get locked() { return _seed === null; },

	unlock(seed: Uint8Array, pubkey: string) {
		_seed   = seed;
		_pubkey = pubkey;
	},
	lock() {
		_seed   = null;
		_pubkey = null;
	},
};
