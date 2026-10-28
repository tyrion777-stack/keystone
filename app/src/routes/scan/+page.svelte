<script lang="ts">
	import { goto } from '$app/navigation';
	import { tick, onMount } from 'svelte';
	import { session } from '$lib/session.svelte';
	import { signChallenge } from '$lib/crypto';

	interface SignRequest {
		type:       'ks_sign';
		challenge:  string;
		origin:     string;
		relay?:     string;
		requestId?: string;
	}

	interface AddDeviceRequest {
		type:      'ks_add_device';
		pairingId: string;
		challenge: string;
		relay:     string;
		origin:    string;
	}

	type PendingRequest = SignRequest | AddDeviceRequest;

	let videoEl    = $state<HTMLVideoElement | undefined>(undefined);
	let scanning   = $state(false);
	let error      = $state('');
	let pending    = $state<PendingRequest | null>(null);
	let signed     = $state(false);
	let signature  = $state('');
	let relaying   = $state(false);
	let relayError = $state('');
	let returnUrl  = $state('');

	$effect(() => {
		if (session.locked) goto('/unlock');
	});

	onMount(() => {
		const params = new URLSearchParams(window.location.search);
		const challenge  = params.get('challenge');
		const origin     = params.get('origin');
		const relay      = params.get('relay');
		const requestId  = params.get('requestId');
		returnUrl = params.get('return') ?? '';
		if (challenge && origin && relay && requestId) {
			pending = { type: 'ks_sign', challenge, origin, relay, requestId };
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
			const req = JSON.parse(data) as PendingRequest;
			if (req.type === 'ks_sign') {
				if (!req.challenge || !req.origin) throw new Error();
			} else if (req.type === 'ks_add_device') {
				if (!req.pairingId || !req.challenge || !req.relay || !req.origin) throw new Error();
			} else {
				throw new Error();
			}
			pending = req;
		} catch {
			error = 'Not a Keystone request.';
		}
	}

	async function approve() {
		if (!pending || !session.seed) return;

		if (pending.type === 'ks_add_device') {
			const sig = signChallenge(session.seed, pending.challenge);
			signed = true;
			relaying = true;
			relayError = '';
			try {
				await sendToRelay(pending.relay, pending.pairingId, sig, session.pubkey!);
			} catch (e) {
				relayError = e instanceof Error ? e.message : 'Relay failed';
			} finally {
				relaying = false;
			}
			return;
		}

		signature = signChallenge(session.seed, pending.challenge);
		signed = true;

		if (pending.relay && pending.requestId) {
			relaying = true;
			relayError = '';
			try {
				await sendToRelay(pending.relay, pending.requestId, signature, session.pubkey!);
			} catch (e) {
				relayError = e instanceof Error ? e.message : 'Relay failed';
			} finally {
				relaying = false;
			}
		}
	}

	function sendToRelay(relayUrl: string, requestId: string, sig: string, pubkey: string): Promise<void> {
		return new Promise((resolve, reject) => {
			const wsUrl = `${relayUrl}/${requestId}`;
			const ws = new WebSocket(wsUrl);
			const timeout = setTimeout(() => {
				ws.close();
				reject(new Error('Relay timed out'));
			}, 15000);

			ws.onopen = () => {
				ws.send(JSON.stringify({ signature: sig, pubkey }));
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

	function deny() {
		pending = null;
		signed  = false;
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

	{:else if signed && pending}
		<div class="card">
			<p class="origin">{pending.origin}</p>
			{#if relaying}
				<p class="label">Sending…</p>
			{:else if relayError}
				<p class="label" style="color:#ef4444">Relay failed</p>
				<p class="hint">{relayError}</p>
				{#if pending.type === 'ks_sign' && !pending.relay}
					<p class="hint" style="margin-top:8px">Copy signature manually:</p>
					<textarea readonly rows="4">{signature}</textarea>
				{/if}
			{:else if pending.type === 'ks_add_device'}
				<p class="label">Device linked</p>
				<p class="hint">Your phone is now registered on {pending.origin}.</p>
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
			{#if pending.type === 'ks_add_device'}
				<p class="label">Add this device to</p>
				<p class="origin">{pending.origin}</p>
				<p class="hint" style="margin-top:4px">Your phone's key will be registered so you can sign in here.</p>
			{:else}
				<p class="label">Signing request from</p>
				<p class="origin">{pending.origin}</p>
				<p class="challenge-label">Challenge</p>
				<p class="challenge">{pending.challenge.slice(0, 64)}…</p>
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
	.challenge-label { font-size: 10px; color: #8888aa; margin-top: 8px; }
	.challenge { font-family: monospace; font-size: 11px; color: #8888aa; word-break: break-all; }

	button {
		width: 100%; max-width: 360px;
		background: #5c6bc0; color: #fff; border: none; border-radius: 8px;
		padding: 15px; font-family: inherit; font-size: 14px; font-weight: 700;
		letter-spacing: 1px; cursor: pointer;
	}
	button:hover { background: #6979d0; }
	button.outline { background: transparent; border: 1px solid #2a2a50; color: #8888aa; }
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
</style>
