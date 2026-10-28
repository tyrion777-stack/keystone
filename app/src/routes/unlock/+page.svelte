<script lang="ts">
	import { goto } from '$app/navigation';
	import { decryptSeed } from '$lib/crypto';
	import { loadEncryptedSeed, loadPubkey, hasKey } from '$lib/storage';
	import { session } from '$lib/session.svelte';

	let password = $state('');
	let loading  = $state(false);
	let error    = $state('');

	$effect(() => {
		if (!hasKey()) goto('/setup', { replaceState: true });
	});

	async function unlock() {
		error = ''; loading = true;
		await tick();
		try {
			const encHex = loadEncryptedSeed();
			const pubkey = loadPubkey();
			if (!encHex || !pubkey) { goto('/setup', { replaceState: true }); return; }
			const seed = decryptSeed(encHex, password);
			session.unlock(seed, pubkey);
			goto('/home', { replaceState: true });
		} catch (e: unknown) {
			error = e instanceof Error ? e.message : 'Unlock failed.';
		} finally {
			loading = false;
		}
	}

	function tick() { return new Promise(r => setTimeout(r, 30)); }
</script>

<div class="page">
	<h1>Keystone</h1>
	<p class="sub">Unlock your identity</p>

	{#if error}<p class="error">{error}</p>{/if}

	<input
		type="password"
		bind:value={password}
		placeholder="Password"
		onkeydown={e => e.key === 'Enter' && unlock()}
	/>

	{#if loading}
		<p class="hint">Unlocking…</p>
	{:else}
		<button onclick={unlock}>Unlock</button>
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
	input {
		width: 100%; max-width: 360px;
		border: 1px solid #2a2a50; border-radius: 8px;
		padding: 14px; background: #181835; color: #fff;
		font-family: inherit; font-size: 14px;
	}
	input::placeholder { color: #8888aa; }
	button {
		width: 100%; max-width: 360px;
		background: #5c6bc0; color: #fff; border: none;
		border-radius: 8px; padding: 15px;
		font-family: inherit; font-size: 14px; font-weight: 700;
		letter-spacing: 1px; cursor: pointer;
	}
	button:hover { background: #6979d0; }
	.error { color: #ef4444; font-size: 12px; }
	.hint  { color: #8888aa; font-size: 12px; }
</style>
