<script lang="ts">
	import { goto } from '$app/navigation';
	import { tick, onMount } from 'svelte';
	import { session } from '$lib/session.svelte';
	import { signChallenge, signMessage } from '$lib/crypto';
	import { loadPins, savePins } from '$lib/storage';
	import {
		contentToSign,
		parseLink,
		parseQr,
		pinAfterApproval,
		prepare,
		Refused,
		type Pending,
		type Scan
	} from '$lib/requests';

	let videoEl    = $state<HTMLVideoElement | undefined>(undefined);
	let scanning   = $state(false);
	let error      = $state('');
	let notice     = $state('');
	let pending    = $state<Pending | null>(null);
	let signed     = $state(false);
	let signature  = $state('');
	let relaying   = $state(false);
	let relayError = $state('');
	let returnUrl  = $state('');

	const purposeText = { link: 'Link your Keystone to', 'check-in': 'Check in at', sign: 'Sign this for' } as const;

	$effect(() => {
		if (session.locked) goto('/unlock');
	});

	function refusal(e: unknown): string {
		return e instanceof Refused ? e.message : 'Keystone could not check that request.';
	}

	async function show(scan: Scan) {
		try {
			pending = await prepare(scan, loadPins());
		} catch (e) {
			error = refusal(e);
		}
	}

	onMount(() => {
		const params = new URLSearchParams(window.location.search);
		// Only ever reopen a web page: a link could otherwise send the phone anywhere.
		const ret = params.get('return') ?? '';
		returnUrl = ret.startsWith('https://') ? ret : '';
		try {
			const scan = parseLink(params);
			if (scan) show(scan);
		} catch (e) {
			error = refusal(e);
		}
	});

	async function startCamera() {
		error = '';
		try {
			const stream = await navigator.mediaDevices.getUserMedia({
				video: { facingMode: 'environment' },
			});
			scanning = true;
			await tick();
			if (videoEl) {
				videoEl.srcObject = stream;
				await videoEl.play();
				scanLoop();
			}
		} catch (e: unknown) {
			scanning = false;
			error = e instanceof Error ? e.message : 'Camera access failed.';
		}
	}

	function stopCamera() {
		scanning = false;
		const stream = videoEl?.srcObject as MediaStream | null;
		stream?.getTracks().forEach(t => t.stop());
		if (videoEl) videoEl.srcObject = null;
	}

	async function scanLoop() {
		if (!videoEl || !scanning) return;

		// BarcodeDetector API — available in Chrome/Android WebView
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const detector = new (window as any).BarcodeDetector({ formats: ['qr_code'] });

		const detect = async () => {
			if (!scanning || !videoEl) return;
			try {
				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const codes = await detector.detect(videoEl) as any[];
				if (codes.length > 0) {
					handleQR(codes[0].rawValue as string);
					return;
				}
			} catch { /* detector not ready yet */ }
			requestAnimationFrame(detect);
		};
		requestAnimationFrame(detect);
	}

	function handleQR(data: string) {
		stopCamera();
		try {
			show(parseQr(data));
		} catch (e) {
			error = refusal(e);
		}
	}

	async function approve() {
		if (!pending || !session.seed || pending.kind === 'blocked') return;
		const p = pending;
		const pins = loadPins();

		let content: string;
		try {
			content = await contentToSign(p, pins);
		} catch (e) {
			error = refusal(e);
			return;
		}

		let relay: string | null;
		let channel: string | null;
		let message: object;
		if (p.kind === 'approve') {
			const approval = signMessage(session.seed, content);
			const pinned = pinAfterApproval(p, pins, Math.floor(Date.now() / 1000));
			if (pinned) savePins(pinned);
			[relay, channel, message] = [p.relay, p.channel, { type: 'ks_approval', approval }];
		} else {
			signature = signChallenge(session.seed, content);
			const id = p.kind === 'add-device' ? p.pairingId : p.requestId;
			[relay, channel, message] = [p.relay, id, { signature, pubkey: session.pubkey }];
		}
		signed = true;

		if (relay && channel) {
			relaying = true;
			relayError = '';
			try {
				await sendToRelay(relay, channel, message);
			} catch (e) {
				relayError = e instanceof Error ? e.message : 'Relay failed';
			} finally {
				relaying = false;
			}
		}
	}

	function sendToRelay(relayUrl: string, channel: string, message: object): Promise<void> {
		return new Promise((resolve, reject) => {
			const ws = new WebSocket(`${relayUrl}/${channel}`);
			const timeout = setTimeout(() => {
				ws.close();
				reject(new Error('Relay timed out'));
			}, 15000);

			ws.onopen = () => {
				ws.send(JSON.stringify(message));
			};
			ws.onclose = () => {
				clearTimeout(timeout);
				resolve();
			};
			ws.onerror = () => {
				clearTimeout(timeout);
				reject(new Error('Could not reach relay'));
			};
		});
	}

	// The person chose to forget a service's old key after seeing it change. Nothing is signed;
	// the next code from that origin is treated as new.
	function forgetOldKey() {
		if (pending?.kind !== 'blocked') return;
		const pins = loadPins();
		delete pins[pending.origin];
		savePins(pins);
		pending = null;
		notice = 'Old key forgotten. Scan the code again if you trust the new one.';
	}

	function deny() {
		pending = null;
		signed  = false;
	}

	function shownOrigin(p: Pending): string {
		return p.kind === 'approve' || p.kind === 'blocked' ? p.origin : p.claimedOrigin;
	}

	function date(seconds: number): string {
		return new Date(seconds * 1000).toLocaleDateString();
	}
</script>

<div class="page">
	<div class="header">
		<a href="/home" class="back">← Back</a>
		<h1>Scan to sign</h1>
	</div>

	{#if error}
		<p class="error">{error}</p>
		<button onclick={() => { error = ''; pending = null; signed = false; }}>Try again</button>

	{:else if pending?.kind === 'blocked'}
		<div class="card warning">
			<p class="label">Blocked: key changed</p>
			<p class="origin">{pending.origin}</p>
			<p class="hint left">This code names itself “{pending.service}”, but it is signed by a different key than this service used before ({date(pending.pinned.since)}). Nothing will be signed. Someone may be pretending to be this service.</p>
			<p class="key">Old: {pending.pinned.serviceKey}</p>
			<p class="key">New: {pending.serviceKey}</p>
		</div>
		<button class="outline" onclick={deny}>Close</button>
		<button class="danger" onclick={forgetOldKey}>Forget old key</button>

	{:else if signed && pending}
		<div class="card">
			<p class="origin">{shownOrigin(pending)}</p>
			{#if relaying}
				<p class="label">Sending…</p>
			{:else if relayError}
				<p class="label" style="color:#ef4444">Relay failed</p>
				<p class="hint">{relayError}</p>
				{#if pending.kind === 'legacy-sign' && !pending.relay}
					<p class="hint" style="margin-top:8px">Copy signature manually:</p>
					<textarea readonly rows="4">{signature}</textarea>
				{/if}
			{:else if pending.kind === 'add-device'}
				<p class="label">Device linked</p>
				<p class="hint">Your phone is now registered on {pending.claimedOrigin}.</p>
			{:else if pending.relay}
				<p class="label">Signed and sent</p>
			{:else}
				<p class="label">Signed — no relay</p>
				<p class="hint">Copy the signature and paste it on the desktop.</p>
				<textarea readonly rows="4">{signature}</textarea>
			{/if}
		</div>
		<button onclick={() => {
			if (returnUrl) window.open(returnUrl, '_system');
			else goto('/home');
		}}>Done</button>

	{:else if pending}
		<div class="card">
			{#if pending.kind === 'approve'}
				<p class="label">{purposeText[pending.purpose]}</p>
				<p class="origin">“{pending.service}”</p>
				<p class="site">{pending.origin}</p>
				{#if pending.payload !== null}
					<p class="payload">{pending.payload}</p>
				{/if}
				{#if pending.pinnedSince === null}
					<p class="hint left">✓ Signed by this service. First time Keystone sees it: only approve if you are really dealing with “{pending.service}” at {pending.origin}. Its key will be remembered.</p>
				{:else}
					<p class="hint left verified">✓ Signed by this service, with the same key as on {date(pending.pinnedSince)}.</p>
				{/if}
			{:else}
				<p class="label">{pending.kind === 'add-device' ? 'Add this device to' : 'Sign-in code says it is from'}</p>
				<p class="origin">{pending.claimedOrigin}</p>
				<p class="hint left">This older kind of code doesn't prove who made it. Only approve if you just asked to sign in there yourself.</p>
			{/if}
		</div>
		<button onclick={approve}>Approve</button>
		<button class="outline" onclick={deny}>Deny</button>

	{:else if scanning}
		<!-- svelte-ignore a11y_media_has_caption -->
		<video bind:this={videoEl} class="viewfinder" playsinline></video>
		<p class="hint">Point at a Keystone signing QR code</p>
		<button class="outline" onclick={stopCamera}>Cancel</button>

	{:else}
		{#if notice}<p class="hint">{notice}</p>{/if}
		<p class="hint">Scan a QR code from a Keystone-enabled site to sign in.</p>
		<button onclick={startCamera}>Start camera</button>
		<a href="/home" class="btn-outline">Back</a>
	{/if}
</div>

<style>
	.page {
		min-height: 100dvh;
		display: flex; flex-direction: column;
		align-items: center; padding: 32px; gap: 14px;
	}
	.header { width: 100%; max-width: 360px; margin-bottom: 8px; }
	.back { color: #8888aa; text-decoration: none; font-size: 13px; display: block; margin-bottom: 8px; }
	h1 { font-size: 22px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; }

	.viewfinder {
		width: 100%; max-width: 360px; aspect-ratio: 1;
		border-radius: 12px; object-fit: cover;
		border: 2px solid #5c6bc0;
	}

	.card {
		width: 100%; max-width: 360px;
		background: #181835; border: 1px solid #2a2a50; border-radius: 12px;
		padding: 20px; display: flex; flex-direction: column; gap: 8px;
	}
	.label { font-size: 10px; color: #8888aa; letter-spacing: 2px; text-transform: uppercase; }
	.origin { font-size: 16px; font-weight: 600; color: #fff; }
	.site { font-size: 12px; color: #8888aa; word-break: break-all; }
	.payload {
		white-space: pre-wrap; word-break: break-word; font-size: 13px; color: #fff;
		background: #0d0d1f; border: 1px solid #2a2a50; border-radius: 6px; padding: 10px;
		max-height: 160px; overflow-y: auto;
	}
	.card.warning { border-color: #7f1d1d; background: #2a1215; }
	.key { font-family: monospace; font-size: 10px; color: #8888aa; word-break: break-all; }
	.verified { color: #4ade80; }

	button {
		width: 100%; max-width: 360px;
		background: #5c6bc0; color: #fff; border: none; border-radius: 8px;
		padding: 15px; font-family: inherit; font-size: 14px; font-weight: 700;
		letter-spacing: 1px; cursor: pointer;
	}
	button:hover { background: #6979d0; }
	button.outline { background: transparent; border: 1px solid #2a2a50; color: #8888aa; }
	button.danger { background: transparent; border: 1px solid #7f1d1d; color: #f87171; }
	.btn-outline {
		display: block; text-align: center; width: 100%; max-width: 360px;
		background: transparent; border: 1px solid #2a2a50; color: #8888aa;
		border-radius: 8px; padding: 15px; font-size: 14px; text-decoration: none;
	}

	textarea {
		width: 100%; background: #0d0d1f; border: 1px solid #2a2a50; border-radius: 6px;
		color: #8888aa; font-family: monospace; font-size: 10px; padding: 10px; resize: none;
	}
	.error { color: #ef4444; font-size: 12px; }
	.hint  { color: #8888aa; font-size: 13px; text-align: center; max-width: 300px; }
	.hint.left { text-align: left; max-width: none; }
</style>
