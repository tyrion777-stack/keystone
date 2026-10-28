<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { App } from '@capacitor/app';

	let { children } = $props();

	function handleDeepLink(url: string) {
		try {
			const parsed = new URL(url);
			if (parsed.hostname === 'sign') {
				goto(`/scan?${parsed.searchParams.toString()}`);
			}
		} catch { /* not a valid keystone deep link */ }
	}

	onMount(async () => {
		const launch = await App.getLaunchUrl().catch(() => null);
		if (launch?.url) handleDeepLink(launch.url);
		App.addListener('appUrlOpen', (e) => handleDeepLink(e.url));
	});
</script>

<svelte:head>
	<title>Keystone</title>
	<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
</svelte:head>

{@render children()}

<style>
	:global(*, *::before, *::after) { box-sizing: border-box; margin: 0; padding: 0; }
	:global(body) {
		background: #0d0d1f;
		color: #fff;
		font-family: -apple-system, 'Helvetica Neue', Arial, sans-serif;
		-webkit-font-smoothing: antialiased;
		min-height: 100dvh;
	}
</style>
