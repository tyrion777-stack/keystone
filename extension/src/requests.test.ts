import { describe, expect, it } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex } from '@noble/hashes/utils';
import { signMessage } from './crypto';
import { verifyApproval, verifySignIn } from '../../wasm/js/keystone-core';
import {
  contentToSign,
  pageSignedMessage,
  pinAfterApproval,
  prepareApproval,
  prepareSignIn,
  Refused,
  type Pins,
} from './requests';

const ORIGIN = 'https://desk.example.com';
const NOW = 1_800_000_000;
const service = new Uint8Array(32).fill(0x21);
const otherService = new Uint8Array(32).fill(0x22);
const person = new Uint8Array(32).fill(0x23);
const keyOf = (seed: Uint8Array) => bytesToHex(ed25519.getPublicKey(seed));

function request(over: Record<string, unknown> = {}, seed = service) {
  const r = {
    kind: 'keystone.request', v: 1, service: 'Front desk', origin: ORIGIN, purpose: 'link',
    nonce: 'a1'.repeat(16), issued_at: NOW - 10, expires_at: NOW + 110, ...over,
  };
  return signMessage(seed, JSON.stringify(r));
}

describe('prepareSignIn', () => {
  it('builds the content from the real origin and the challenge, and core accepts it', async () => {
    const challenge = 'ab'.repeat(32);
    const p = await prepareSignIn(challenge, ORIGIN);
    expect(p.kind).toBe('sign-in');
    const signed = signMessage(person, await contentToSign(p, {}));
    expect(await verifySignIn(signed, ORIGIN, challenge)).toBe(keyOf(person));
    await expect(verifySignIn(signed, 'https://other.example.com', challenge)).rejects.toThrow();
  });

  it('refuses anything but a hex challenge, and sites that are not https', async () => {
    for (const bad of ['', 'AB'.repeat(32), '{"kind":"keystone.approval"}', 42, null]) {
      await expect(prepareSignIn(bad, ORIGIN)).rejects.toBeInstanceOf(Refused);
    }
    await expect(prepareSignIn('ab'.repeat(32), 'http://desk.example.com')).rejects.toBeInstanceOf(Refused);
    expect((await prepareSignIn('ab'.repeat(32), 'http://localhost:5173')).kind).toBe('sign-in');
  });
});

describe('prepareApproval', () => {
  it('shows a valid request for this site, first time unpinned', async () => {
    const p = await prepareApproval(request(), ORIGIN, {}, NOW);
    expect(p).toMatchObject({ kind: 'approve', service: 'Front desk', purpose: 'link', serviceKey: keyOf(service), pinnedSince: null });
  });

  it('refuses a request made for another site, before any window', async () => {
    await expect(prepareApproval(request({ origin: 'https://bank.example.com' }), ORIGIN, {}, NOW))
      .rejects.toThrow('This request is for https://bank.example.com, not this site');
  });

  it('refuses invalid, expired, tampered and malformed requests', async () => {
    await expect(prepareApproval(request(), ORIGIN, {}, NOW + 1000)).rejects.toBeInstanceOf(Refused);
    const tampered = { ...request(), content: request({ purpose: 'check-in' }).content };
    await expect(prepareApproval(tampered, ORIGIN, {}, NOW)).rejects.toBeInstanceOf(Refused);
    const notRequest = signMessage(service, JSON.stringify({ kind: 'keystone.approval' }));
    await expect(prepareApproval(notRequest, ORIGIN, {}, NOW)).rejects.toBeInstanceOf(Refused);
    for (const bad of [null, 'x', {}, { author: 1 }, { ...request(), signature: 'x'.repeat(9000) }]) {
      await expect(prepareApproval(bad, ORIGIN, {}, NOW)).rejects.toBeInstanceOf(Refused);
    }
  });

  it('blocks a site whose key changed, and says what it pinned', async () => {
    const pins: Pins = { [ORIGIN]: { serviceKey: keyOf(service), service: 'Front desk', since: NOW - 86400 } };
    const same = await prepareApproval(request({ purpose: 'check-in' }), ORIGIN, pins, NOW);
    expect(same).toMatchObject({ kind: 'approve', pinnedSince: NOW - 86400 });
    const changed = await prepareApproval(request({ purpose: 'check-in' }, otherService), ORIGIN, pins, NOW);
    expect(changed).toMatchObject({ kind: 'blocked', serviceKey: keyOf(otherService), pinned: pins[ORIGIN] });
  });
});

describe('contentToSign and pinning', () => {
  it('signs an approval the service accepts, and pins on first approval only', async () => {
    const issued = request();
    const p = await prepareApproval(issued, ORIGIN, {}, NOW);
    const approval = signMessage(person, await contentToSign(p, {}, NOW));
    expect(await verifyApproval(approval, issued, NOW)).toMatchObject({ person: keyOf(person), purpose: 'link' });

    const pins = pinAfterApproval(p, {}, NOW);
    expect(pins).toEqual({ [ORIGIN]: { serviceKey: keyOf(service), service: 'Front desk', since: NOW } });
    expect(pinAfterApproval(p, pins!, NOW + 5)).toBeNull();
  });

  it('checks again at signing time: expired, or a key pinned meanwhile, signs nothing', async () => {
    const p = await prepareApproval(request(), ORIGIN, {}, NOW);
    await expect(contentToSign(p, {}, NOW + 1000)).rejects.toBeInstanceOf(Refused);
    const pinnedMeanwhile: Pins = { [ORIGIN]: { serviceKey: keyOf(otherService), service: 'x', since: NOW } };
    await expect(contentToSign(p, pinnedMeanwhile, NOW)).rejects.toBeInstanceOf(Refused);
    const blocked = await prepareApproval(request({}, otherService), ORIGIN, { [ORIGIN]: { serviceKey: keyOf(service), service: 'x', since: NOW } }, NOW);
    await expect(contentToSign(blocked, {}, NOW)).rejects.toBeInstanceOf(Refused);
  });
});

describe('pageSignedMessage', () => {
  it('keeps only the four fields', () => {
    const m = request();
    expect(pageSignedMessage({ ...m, extra: 'x' })).toEqual(m);
  });
});
