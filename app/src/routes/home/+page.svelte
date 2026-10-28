<script lang="ts">
	import { goto } from '$app/navigation';
	import { session } from '$lib/session.svelte';
	import { clearKey } from '$lib/storage';

	let copied    = $state(false);
	let showFull  = $state(false);
	let confirmDelete = $state(false);

	$effect(() => {
		if (session.locked) goto('/unlock', { replaceState: true });
	});

	async function copyPubkey() {
		if (!session.pubkey) return;
		await navigator.clipboard.writeText(session.pubkey);
		copied = true;
		setTimeout(() => copied = false, 1800);
	}

	function lock() {
		session.lock();
		goto('/unlock', { replaceState: true });
	}

	function deleteIdentity() {
		clearKey();
		session.lock();
		goto('/setup', { replaceState: true });
	}
</script>

<div class="page">
	<h1>Keystone</h1>
	<p class="label">Your identity</p>

	<!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
	<div class="card" onclick={copyPubkey}>
		<p class="pubkey" class:full={showFull}>
			{session.pubkey ?? '—'}
		</p>
		<div class="card-footer">
			<button class="ghost small" onclick={(e) => { e.stopPropagation(); showFull = !showFull; }}>
				{showFull ? 'Show less' : 'Show full'}
			</button>
			<span class="copy-hint">{copied ? 'Copied ✓' : 'Tap to copy'}</span>
		</div>
	</div>

	<a href="/scan" class="btn">Scan to sign</a>

	<button class="outline" onclick={lock}>Lock</button>

	{#if !confirmDelete}
		<button class="danger-ghost" onclick={() => confirmDelete = true}>
			Delete identity from device
		</button>
	{:else}
		<p class="warning">Make sure you have a backup. This cannot be undone.</p>
		<div class="row">
			<button class="outline" onclick={() => confirmDelete = false}>Cancel</button>
			<button class="danger" onclick={deleteIdentity}>Delete</button>
		</div>
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
	.label { font-size: 11px; color: #8888aa; letter-spacing: 2px; text-transform: uppercase; }

	.card {
		width: 100%; max-width: 360px;
		background: #181835; border: 1px solid #2a2a50; border-radius: 12px;
		padding: 20px; cursor: pointer; margin-bottom: 8px;
	}
	.card:hover { border-color: #5c6bc0; }
	.pubkey {
		font-family: monospace; font-size: 12px; line-height: 1.7;
		color: #fff; word-break: break-all;
		display: -webkit-box; -webkit-box-orient: vertical;
		-webkit-line-clamp: 2; overflow: hidden;
	}
	.pubkey.full { -webkit-line-clamp: unset; overflow: visible; }
	.card-footer {
		display: flex; justify-content: space-between; align-items: center;
		margin-top: 12px;
	}
	.copy-hint { font-size: 10px; color: #8888aa; letter-spacing: 1px; text-transform: uppercase; }

	.btn {
		display: block; width: 100%; max-width: 360px; text-align: center;
		background: #5c6bc0; color: #fff; border: none; border-radius: 8px;
		padding: 15px; font-family: inherit; font-size: 14px; font-weight: 700;
		letter-spacing: 1px; cursor: pointer; text-decoration: none;
	}
	.btn:hover { background: #6979d0; }

	button {
		width: 100%; max-width: 360px;
		background: #5c6bc0; color: #fff; border: none; border-radius: 8px;
		padding: 15px; font-family: inherit; font-size: 14px; font-weight: 700;
		letter-spacing: 1px; cursor: pointer;
	}
	button.outline { background: transparent; border: 1px solid #2a2a50; color: #8888aa; }
	button.ghost   { background: none; color: #8888aa; font-weight: 400; padding: 4px 0; }
	button.small   { font-size: 10px; width: auto; padding: 4px 8px; }
	button.danger-ghost { background: none; color: #ef4444; font-weight: 400; font-size: 12px; margin-top: 8px; }
	button.danger  { background: #ef4444; width: auto; flex: 1; }

	.warning { font-size: 12px; color: #ef4444; text-align: center; max-width: 300px; }
	.row { display: flex; gap: 10px; width: 100%; max-width: 360px; }
	.row button { width: auto; flex: 1; }
</style>
