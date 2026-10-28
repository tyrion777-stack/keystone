import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { signMessage } from './crypto';
import { verifyApproval, verifyRequest, KeystoneCoreError } from '../../../wasm/js/keystone-core';
import {
	contentToSign,
	parseLink,
	parseQr,
	pinAfterApproval,
	prepare,
	Refused,
	type Pins,
	type Scan
} from './requests';

const ORIGIN = 'https://desk.example.com';
const NOW = 1_800_000_000;
const RELAY = 'wss://relay.example.com';
const CHANNEL = 'c0ffee00c0ffee00';
const service = new Uint8Array(32).fill(0x31);
const otherService = new Uint8Array(32).fill(0x32);
const person = new Uint8Array(32).fill(0x33);
const keyOf = (seed: Uint8Array) => bytesToHex(ed25519.getPublicKey(seed));

function request(over: Record<string, unknown> = {}, seed = service) {
	return signMessage(seed, JSON.stringify({
		kind: 'keystone.request', v: 1, service: 'Front desk', origin: ORIGIN, purpose: 'link',
		nonce: 'b2'.repeat(16), issued_at: NOW - 10, expires_at: NOW + 110, ...over
	}));
}

const scan = (req = request()): Scan => ({ type: 'ks_request', request: req, relay: RELAY, channel: CHANNEL });
const qr = (v: unknown) => JSON.stringify(v);
const b64u = (s: string) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

describe('the WebAssembly build of keystone-core, in the app', () => {
	it('agrees with core on every service request vector', async () => {
		const path = fileURLToPath(new URL('../../../test-vectors/service_request.json', import.meta.url));
		const { cases } = JSON.parse(readFileSync(path, 'utf8'));
		for (const c of cases.filter((c: { kind: string }) => c.kind === 'request')) {
			const valid = await verifyRequest(c.signed, c.now).then(() => true, e => {
				if (!(e instanceof KeystoneCoreError)) throw e;
				return false;
			});
			expect(valid, c.name).toBe(c.valid);
		}
	});
});

describe('parseQr', () => {
	it('reads a signed service request', () => {
		const req = request();
		expect(parseQr(qr({ type: 'ks_request', request: req, relay: RELAY, channel: CHANNEL }))).toEqual(scan(req));
	});

	it('takes old codes only with a sign-in challenge, so they can never sign a structured message', () => {
		const ok = { type: 'ks_sign', challenge: 'ab'.repeat(32), origin: ORIGIN, relay: RELAY, requestId: '3f2a9c1e-0b7d-4e55-9a7c-2d1f0e8b6a44' };
		expect(parseQr(qr(ok))).toMatchObject({ type: 'ks_sign', challenge: 'ab'.repeat(32) });
		expect(parseQr(qr({ type: 'ks_sign', challenge: 'ab'.repeat(32), origin: ORIGIN }))).toMatchObject({ relay: null, requestId: null });
		for (const c of ['{"kind":"keystone.approval"}', 'I agree to pay', 'AB'.repeat(32), '', 42]) {
			expect(() => parseQr(qr({ ...ok, challenge: c })), String(c)).toThrow(Refused);
		}
		const device = { type: 'ks_add_device', challenge: 'cd'.repeat(32), origin: ORIGIN, relay: RELAY, pairingId: '3f2a9c1e-0b7d-4e55' };
		expect(parseQr(qr(device)).type).toBe('ks_add_device');
		expect(() => parseQr(qr({ ...device, challenge: '{"kind":"keystone.approval"}' }))).toThrow(Refused);
	});

	it('refuses unencrypted relays, odd channels and anything else', () => {
		const base = { type: 'ks_request', request: request(), relay: RELAY, channel: CHANNEL };
		for (const bad of [
			{ ...base, relay: 'ws://relay.example.com' },
			{ ...base, relay: 'https://relay.example.com' },
			{ ...base, channel: '../../admin' },
			{ ...base, channel: 'short' },
			{ ...base, request: 'x' },
			{ ...base, request: { ...request(), signature: 1 } },
			{ type: 'ks_unknown' },
			null
		]) {
			expect(() => parseQr(qr(bad)), JSON.stringify(bad)?.slice(0, 60)).toThrow(Refused);
		}
		for (const text of ['not json', '42', 'x'.repeat(20000)]) {
			expect(() => parseQr(text)).toThrow(Refused);
		}
	});
});

describe('parseLink', () => {
	it('reads a request link, and old challenge links', () => {
		const req = request();
		const link = new URLSearchParams({ request: b64u(JSON.stringify(req)), relay: RELAY, channel: CHANNEL });
		expect(parseLink(link)).toEqual(scan(req));
		const old = new URLSearchParams({ challenge: 'ab'.repeat(32), origin: ORIGIN, relay: RELAY, requestId: 'c0ffee00c0ffee00' });
		expect(parseLink(old)).toMatchObject({ type: 'ks_sign' });
		expect(parseLink(new URLSearchParams())).toBeNull();
	});

	it('refuses a link that asks to sign anything but a challenge', () => {
		const evil = new URLSearchParams({ challenge: '{"kind":"keystone.approval","request":"x"}', origin: 'https://bank.example.com' });
		expect(() => parseLink(evil)).toThrow(Refused);
		expect(() => parseLink(new URLSearchParams({ request: '!!!', relay: RELAY, channel: CHANNEL }))).toThrow(Refused);
	});
});

describe('prepare', () => {
	it('shows a verified request, unpinned the first time', async () => {
		expect(await prepare(scan(), {}, NOW)).toMatchObject({
			kind: 'approve', origin: ORIGIN, service: 'Front desk', purpose: 'link', serviceKey: keyOf(service), pinnedSince: null
		});
	});

	it('refuses invalid, expired and tampered requests', async () => {
		await expect(prepare(scan(), {}, NOW + 1000)).rejects.toBeInstanceOf(Refused);
		const tampered = { ...request(), content: request({ purpose: 'check-in' }).content };
		await expect(prepare(scan(tampered), {}, NOW)).rejects.toBeInstanceOf(Refused);
		await expect(prepare(scan(signMessage(service, '{"kind":"keystone.approval"}')), {}, NOW)).rejects.toBeInstanceOf(Refused);
	});

	it('blocks an origin whose key changed', async () => {
		const pins: Pins = { [ORIGIN]: { serviceKey: keyOf(service), service: 'Front desk', since: NOW - 86400 } };
		expect(await prepare(scan(request({ purpose: 'check-in' })), pins, NOW)).toMatchObject({ kind: 'approve', pinnedSince: NOW - 86400 });
		expect(await prepare(scan(request({}, otherService)), pins, NOW)).toMatchObject({ kind: 'blocked', pinned: pins[ORIGIN] });
	});

	it('labels old codes by the origin they claim', async () => {
		const s = parseQr(qr({ type: 'ks_sign', challenge: 'ab'.repeat(32), origin: ORIGIN }));
		expect(await prepare(s, {}, NOW)).toMatchObject({ kind: 'legacy-sign', claimedOrigin: ORIGIN });
	});
});

describe('contentToSign and pinning', () => {
	it('signs an approval the service accepts, and pins on the first approval only', async () => {
		const issued = request();
		const p = await prepare(scan(issued), {}, NOW);
		const approval = signMessage(person, await contentToSign(p, {}, NOW));
		expect(await verifyApproval(approval, issued, NOW)).toMatchObject({ person: keyOf(person), purpose: 'link' });
		const pins = pinAfterApproval(p, {}, NOW);
		expect(pins).toEqual({ [ORIGIN]: { serviceKey: keyOf(service), service: 'Front desk', since: NOW } });
		expect(pinAfterApproval(p, pins!, NOW)).toBeNull();
	});

	it('checks again when signing: expired, or pinned to another key meanwhile, signs nothing', async () => {
		const p = await prepare(scan(), {}, NOW);
		await expect(contentToSign(p, {}, NOW + 1000)).rejects.toBeInstanceOf(Refused);
		const meanwhile: Pins = { [ORIGIN]: { serviceKey: keyOf(otherService), service: 'x', since: NOW } };
		await expect(contentToSign(p, meanwhile, NOW)).rejects.toBeInstanceOf(Refused);
	});

	it('signs only the challenge for old codes', async () => {
		const p = await prepare(parseQr(qr({ type: 'ks_sign', challenge: 'ab'.repeat(32), origin: ORIGIN })), {}, NOW);
		expect(await contentToSign(p, {}, NOW)).toBe('ab'.repeat(32));
	});
});
