// What a web page may ask the extension to sign, checked by keystone-core itself (compiled to
// WebAssembly), before any window opens.
//
// A page gets exactly two things signed, both built here and never taken from the page:
//   - sign-in: {kind:'keystone.signin', origin, challenge}, with the origin Chrome reports for
//     the page, so the signature is no good on any other site (core/src/sign_in.rs).
//   - approval: the answer to a service's signed request (core/src/request.rs), only when the
//     request is valid, is for this page's own origin, and is signed by the key this site used
//     before (pinned on first use).

import {
  KeystoneCoreError,
  signInContent,
  verifyRequest,
  type Purpose,
  type SignedMessage,
} from '../../wasm/js/keystone-core';
import { isSignInChallenge } from './signing-policy';

/** The service key remembered for a site, from the first request the person approved there. */
export interface Pin {
  serviceKey: string;
  service: string;
  since: number;
}

export type Pins = Record<string, Pin>;

export type Pending =
  | { kind: 'sign-in'; origin: string; challenge: string; content: string }
  | {
      kind: 'approve';
      origin: string;
      service: string;
      purpose: Purpose;
      payload: string | null;
      serviceKey: string;
      /** When this site's key was first remembered; null the first time. */
      pinnedSince: number | null;
      signed: SignedMessage;
    }
  | { kind: 'blocked'; origin: string; service: string; serviceKey: string; pinned: Pin };

export class Refused extends Error {}

const MAX_FIELD = 8192;

/** A SignedMessage from a page: four strings, none huge. Anything else is refused. */
export function pageSignedMessage(value: unknown): SignedMessage {
  if (typeof value !== 'object' || value === null) throw new Refused('Not a signed request');
  const v = value as Record<string, unknown>;
  const fields = ['author', 'content', 'content_hash', 'signature'] as const;
  for (const f of fields) {
    if (typeof v[f] !== 'string' || (v[f] as string).length > MAX_FIELD) {
      throw new Refused('Not a signed request');
    }
  }
  return { author: v.author as string, content: v.content as string, content_hash: v.content_hash as string, signature: v.signature as string };
}

export async function prepareSignIn(challenge: unknown, origin: string): Promise<Pending> {
  if (!isSignInChallenge(challenge)) throw new Refused('Keystone signs sign-in challenges only');
  let content: string;
  try {
    content = await signInContent(origin, challenge);
  } catch (e) {
    if (e instanceof KeystoneCoreError) throw new Refused('Keystone signs in on https sites only');
    throw e;
  }
  return { kind: 'sign-in', origin, challenge, content };
}

export async function prepareApproval(
  request: unknown,
  origin: string,
  pins: Pins,
  now?: number,
): Promise<Pending> {
  const signed = pageSignedMessage(request);
  let verified;
  try {
    verified = await verifyRequest(signed, now);
  } catch (e) {
    if (e instanceof KeystoneCoreError) throw new Refused(`Request not valid: ${e.message}`);
    throw e;
  }
  const r = verified.request;
  // The check a phone cannot make: the request names the site the page is really on.
  if (r.origin !== origin) throw new Refused(`This request is for ${r.origin}, not this site`);

  const pinned = pins[origin];
  if (pinned && pinned.serviceKey !== verified.serviceKey) {
    return { kind: 'blocked', origin, service: r.service, serviceKey: verified.serviceKey, pinned };
  }
  return {
    kind: 'approve',
    origin,
    service: r.service,
    purpose: r.purpose,
    payload: r.payload ?? null,
    serviceKey: verified.serviceKey,
    pinnedSince: pinned ? pinned.since : null,
    signed,
  };
}

/**
 * The text to sign once the person approves. An approval is checked again here, at the moment
 * of signing: the request may have expired, or this site's key been pinned, since the window
 * opened.
 */
export async function contentToSign(p: Pending, pins: Pins, now?: number): Promise<string> {
  if (p.kind === 'sign-in') return p.content;
  if (p.kind === 'blocked') throw new Refused('This site’s key changed; nothing was signed');
  const again = await prepareApproval(p.signed, p.origin, pins, now);
  if (again.kind !== 'approve') throw new Refused('This site’s key changed; nothing was signed');
  return (await verifyRequest(p.signed, now)).approvalContent;
}

/** Remember this site's key the first time the person approves one of its requests. */
export function pinAfterApproval(p: Pending, pins: Pins, now: number): Pins | null {
  if (p.kind !== 'approve' || pins[p.origin]) return null;
  return { ...pins, [p.origin]: { serviceKey: p.serviceKey, service: p.service, since: now } };
}
