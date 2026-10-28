<script lang="ts">
	import { goto } from '$app/navigation';
	import { generateSeed, encryptSeed, getPublicKeyHex, seedFromHex } from '$lib/crypto';
	import { saveKey } from '$lib/storage';
	import { session } from '$lib/session.svelte';

	type Mode = 'choose' | 'generate' | 'import';
	let mode      = $state<Mode>('choose');
	let password  = $state('');
	let confirm   = $state('');
	let importHex = $state('');
	let loading   = $state(false);
	let error     = $state('');

	function validate(): boolean {
		if (password.length < 8) { error = 'Password must be at least 8 characters.'; return false; }
		if (password !== confirm) { error = 'Passwords do not match.'; return false; }
		return true;
	}

	async function handleGenerate() {
		if (!validate()) return;
		error = ''; loading = true;
		await tick();
		try {
			const seed      = generateSeed();
			const encrypted = encryptSeed(seed, password);
			const pubkey    = getPublicKeyHex(seed);
			saveKey(encrypted, pubkey);
			session.unlock(seed, pubkey);
			goto('/home');
		} catch (e: unknown) {
			error = e instanceof Error ? e.message : 'Setup failed.';
		} finally {
			loading = false;
		}
	}

	async function handleImport() {
		if (!validate()) return;
		error = ''; loading = true;
		await tick();
		try {
			const seed      = seedFromHex(importHex.trim().toLowerCase());
			const encrypted = encryptSeed(seed, password);
			const pubkey    = getPublicKeyHex(seed);
			saveKey(encrypted, pubkey);
			session.unlock(seed, pubkey);
			goto('/home');
		} catch (e: unknown) {
			error = e instanceof Error ? e.message : 'Import failed.';
		} finally {
			loading = false;
		}
	}

	// Let the UI render the loading state before Argon2id blocks the thread
	function tick() { return new Promise(r => setTimeout(r, 30)); }
</script>

<div class="page">
	{#if mode === 'choose'}
		<h1>Keystone</h1>
		<p class="sub">Your cryptographic identity</p>
		<button onclick={() => mode = 'generate'}>Generate new identity</button>
		<button class="outline" onclick={() => mode = 'import'}>Import existing key</button>

	{:else}
		<h1>{mode === 'generate' ? 'New identity' : 'Import key'}</h1>
		{#if error}<p class="error">{error}</p>{/if}

		{#if mode === 'import'}
			<textarea
				bind:value={importHex}
				placeholder="64-character hex seed"
				rows="3"
				spellcheck="false"
				autocomplete="off"
			></textarea>
		{/if}

		<input type="password" bind:value={password} placeholder="Password (min 8 chars)" />
		<input type="password" bind:value={confirm}  placeholder="Confirm password" />

		{#if loading}
			<p class="hint">Securing key…</p>
		{:else}
			<button onclick={mode === 'generate' ? handleGenerate : handleImport}>
				{mode === 'generate' ? 'Create identity' : 'Import'}
			</button>
		{/if}

		<button class="ghost" onclick={() => { mode = 'choose'; error = ''; }}>← Back</button>
	{/if}
</div>

<style>
	.page {
		min-height: 100dvh;
		display: flex; flex-direction: column;
		align-items: center; justify-content: center;
		padding: 32px; gap: 14px;
	}
	h1 { font-size: 28px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; }
	.sub { font-size: 13px; color: #8888aa; margin-bottom: 16px; }
	input, textarea {
		width: 100%; max-width: 360px;
		border: 1px solid #2a2a50; border-radius: 8px;
		padding: 14px; background: #181835; color: #fff;
		font-family: inherit; font-size: 14px;
	}
	textarea { font-family: monospace; font-size: 12px; resize: none; }
	input::placeholder, textarea::placeholder { color: #8888aa; }
	button {
		width: 100%; max-width: 360px;
		background: #5c6bc0; color: #fff; border: none;
		border-radius: 8px; padding: 15px;
		font-family: inherit; font-size: 14px; font-weight: 700;
		letter-spacing: 1px; cursor: pointer;
	}
	button:hover { background: #6979d0; }
	button.outline {
		background: transparent; border: 1px solid #2a2a50; color: #8888aa;
	}
	button.ghost { background: none; color: #8888aa; font-weight: 400; }
	.error { color: #ef4444; font-size: 12px; }
	.hint  { color: #8888aa; font-size: 12px; }
</style>
