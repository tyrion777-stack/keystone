// What a scanned QR code or a keystone:// link may ask the app to sign, checked before anything
// is shown. Service requests are checked by keystone-core itself, compiled to WebAssembly.
//
// A phone cannot see which site made a QR code, so trust comes from two things:
//   - the request is signed by the service (core/src/request.rs), and
//   - the key that signs for an origin is the one pinned the first time the person approved a
//     request from it. A different key later is blocked, with nothing to approve.
//
// Older codes (ks_sign, ks_add_device) carry a bare challenge and an origin nobody signed. They
// still work, but only for a sign-in challenge (lowercase hex), so they can never get an
// approval or any other structured message signed, and the screen says the origin is unproven.

import {
	KeystoneCoreError,
	verifyRequest,
	type Purpose,
	type SignedMessage
} from '../../../wasm/js/keystone-core';

export type { SignedMessage };

/** The service key remembered for an origin, from the first request approved from it. */
export interface Pin {
	serviceKey: string;
	service: string;
	since: number;
}

export type Pins = Record<string, Pin>;

export type Scan =
	| { type: 'ks_request'; request: SignedMessage; relay: string; channel: string }
	| { type: 'ks_sign'; challenge: string; origin: string; relay: string | null; requestId: string | null }
	| { type: 'ks_add_device'; challenge: string; origin: string; relay: string; pairingId: string };

export type Pending =
	| {
			kind: 'approve';
			origin: string;
			service: string;
			purpose: Purpose;
			payload: string | null;
			serviceKey: string;
			/** When this origin's key was first remembered; null the first time. */
			pinnedSince: number | null;
			signed: SignedMessage;
			relay: string;
			channel: string;
	  }
	| { kind: 'blocked'; origin: string; service: string; serviceKey: string; pinned: Pin }
	| { kind: 'legacy-sign'; claimedOrigin: string; challenge: string; relay: string | null; requestId: string | null }
	| { kind: 'add-device'; claimedOrigin: string; challenge: string; relay: string; pairingId: string };

export class Refused extends Error {}

const MAX_FIELD = 8192;
const SIGN_IN_CHALLENGE = /^(?:[0-9a-f]{2}){16,64}$/;
const CHANNEL = /^[A-Za-z0-9_-]{8,128}$/;
const MAX_CLAIMED_ORIGIN = 256;

export function isSignInChallenge(c: unknown): c is string {
	return typeof c === 'string' && SIGN_IN_CHALLENGE.test(c);
}

/** wss://, or ws:// to localhost for development. */
export function isRelayUrl(relay: unknown): relay is string {
	if (typeof relay !== 'string' || relay.length > 512) return false;
	try {
		const u = new URL(relay);
		return u.protocol === 'wss:' || (u.protocol === 'ws:' && u.hostname === 'localhost');
	} catch {
		return false;
	}
}

function signedMessage(value: unknown): SignedMessage {
	if (typeof value !== 'object' || value === null) throw new Refused('Not a signed request');
	const v = value as Record<string, unknown>;
	for (const f of ['author', 'content', 'content_hash', 'signature']) {
		if (typeof v[f] !== 'string' || (v[f] as string).length > MAX_FIELD) {
			throw new Refused('Not a signed request');
		}
	}
	return {
		author: v.author as string,
		content: v.content as string,
		content_hash: v.content_hash as string,
		signature: v.signature as string
	};
}

function channel(value: unknown, what: string): string {
	if (typeof value !== 'string' || !CHANNEL.test(value)) throw new Refused(`Bad ${what}`);
	return value;
}

function claimedOrigin(value: unknown): string {
	if (typeof value !== 'string' || value.length === 0 || value.length > MAX_CLAIMED_ORIGIN) {
		throw new Refused('Not a Keystone request');
	}
	return value;
}

function challenge(value: unknown): string {
	if (!isSignInChallenge(value)) throw new Refused('Keystone signs sign-in challenges only');
	return value;
}

function relayOrRefuse(value: unknown): string {
	if (!isRelayUrl(value)) throw new Refused('Bad relay address');
	return value;
}

/** What a QR code says, checked for shape. Throws Refused. */
export function parseQr(text: string): Scan {
	if (text.length > 16384) throw new Refused('Not a Keystone request');
	let v: Record<string, unknown>;
	try {
		v = JSON.parse(text);
	} catch {
		throw new Refused('Not a Keystone request');
	}
	if (typeof v !== 'object' || v === null) throw new Refused('Not a Keystone request');
	return parseFields(v);
}

/**
 * What a keystone://sign link says. A service request travels as `request`, base64url of the
 * signed request's JSON. Returns null when the link carries no request at all.
 */
export function parseLink(params: URLSearchParams): Scan | null {
	const request = params.get('request');
	if (request !== null) {
		let decoded: unknown;
		try {
			const b64 = request.replace(/-/g, '+').replace(/_/g, '/');
			decoded = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), c => c.charCodeAt(0))));
		} catch {
			throw new Refused('Not a Keystone request');
		}
		return parseFields({ type: 'ks_request', request: decoded, relay: params.get('relay'), channel: params.get('channel') });
	}
	if (params.get('challenge') === null) return null;
	return parseFields({
		type: 'ks_sign',
		challenge: params.get('challenge'),
		origin: params.get('origin'),
		relay: params.get('relay'),
		requestId: params.get('requestId')
	});
}

function parseFields(v: Record<string, unknown>): Scan {
	switch (v.type) {
		case 'ks_request':
			return {
				type: 'ks_request',
				request: signedMessage(v.request),
				relay: relayOrRefuse(v.relay),
				channel: channel(v.channel, 'channel')
			};
		case 'ks_sign': {
			const hasRelay = v.relay !== undefined && v.relay !== null;
			return {
				type: 'ks_sign',
				challenge: challenge(v.challenge),
				origin: claimedOrigin(v.origin),
				relay: hasRelay ? relayOrRefuse(v.relay) : null,
				requestId: hasRelay ? channel(v.requestId, 'request id') : null
			};
		}
		case 'ks_add_device':
			return {
				type: 'ks_add_device',
				challenge: challenge(v.challenge),
				origin: claimedOrigin(v.origin),
				relay: relayOrRefuse(v.relay),
				pairingId: channel(v.pairingId, 'pairing id')
			};
		default:
			throw new Refused('Not a Keystone request');
	}
}

/** Check a scan and decide what to show. Service requests go through keystone-core. */
export async function prepare(scan: Scan, pins: Pins, now?: number): Promise<Pending> {
	if (scan.type === 'ks_sign') {
		return { kind: 'legacy-sign', claimedOrigin: scan.origin, challenge: scan.challenge, relay: scan.relay, requestId: scan.requestId };
	}
	if (scan.type === 'ks_add_device') {
		return { kind: 'add-device', claimedOrigin: scan.origin, challenge: scan.challenge, relay: scan.relay, pairingId: scan.pairingId };
	}

	let verified;
	try {
		verified = await verifyRequest(scan.request, now);
	} catch (e) {
		if (e instanceof KeystoneCoreError) throw new Refused(`Request not valid: ${e.message}`);
		throw e;
	}
	const r = verified.request;
	const pinned = pins[r.origin];
	if (pinned && pinned.serviceKey !== verified.serviceKey) {
		return { kind: 'blocked', origin: r.origin, service: r.service, serviceKey: verified.serviceKey, pinned };
	}
	return {
		kind: 'approve',
		origin: r.origin,
		service: r.service,
		purpose: r.purpose,
		payload: r.payload ?? null,
		serviceKey: verified.serviceKey,
		pinnedSince: pinned ? pinned.since : null,
		signed: scan.request,
		relay: scan.relay,
		channel: scan.channel
	};
}

/**
 * The text to sign once the person approves. An approval is checked again here: the request
 * may have expired, or its origin been pinned to another key, while the screen was open.
 */
export async function contentToSign(p: Pending, pins: Pins, now?: number): Promise<string> {
	if (p.kind === 'legacy-sign' || p.kind === 'add-device') return p.challenge;
	if (p.kind === 'blocked') throw new Refused('This service’s key changed; nothing was signed');
	const again = await prepare({ type: 'ks_request', request: p.signed, relay: p.relay, channel: p.channel }, pins, now);
	if (again.kind !== 'approve' || again.origin !== p.origin) {
		throw new Refused('This service’s key changed; nothing was signed');
	}
	return (await verifyRequest(p.signed, now)).approvalContent;
}

/** Remember an origin's key the first time the person approves one of its requests. */
export function pinAfterApproval(p: Pending, pins: Pins, now: number): Pins | null {
	if (p.kind !== 'approve' || pins[p.origin]) return null;
	return { ...pins, [p.origin]: { serviceKey: p.serviceKey, service: p.service, since: now } };
}
