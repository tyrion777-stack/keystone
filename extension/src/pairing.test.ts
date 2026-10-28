import { describe, expect, it } from 'vitest';
import { isPairingOrigin, isRelayUrl, parsePhoneReply } from './pairing';

const ED = 'ab'.repeat(32);
const P256 = 'p256:02' + 'cd'.repeat(32);
const SIG = 'ef'.repeat(64);

describe('isPairingOrigin', () => {
  it('accepts an https origin and a local dev server', () => {
    expect(isPairingOrigin('https://desk.example.com')).toBe(true);
    expect(isPairingOrigin('https://desk.example.com:8443')).toBe(true);
    expect(isPairingOrigin('http://localhost:5173')).toBe(true);
  });

  it('refuses plain http, other schemes, and anything that is not a bare origin', () => {
    for (const bad of [
      'http://desk.example.com',
      'file:///etc',
      'chrome://settings',
      'https://desk.example.com/',
      'https://desk.example.com/path',
      'https://user@desk.example.com',
      'null',
      '',
    ]) {
      expect(isPairingOrigin(bad), bad).toBe(false);
    }
  });
});

describe('isRelayUrl', () => {
  it('accepts wss, and ws to localhost', () => {
    expect(isRelayUrl('wss://relay.example.com/pair')).toBe(true);
    expect(isRelayUrl('ws://localhost:9000')).toBe(true);
  });

  it('refuses unencrypted relays elsewhere, other schemes and non-strings', () => {
    for (const bad of ['ws://relay.example.com', 'https://relay.example.com', 'javascript:alert(1)', '', 42, null]) {
      expect(isRelayUrl(bad), String(bad)).toBe(false);
    }
  });
});

describe('parsePhoneReply', () => {
  it('reads an Ed25519 or P-256 key with a signature', () => {
    expect(parsePhoneReply(JSON.stringify({ pubkey: ED, signature: SIG }))).toEqual({ pubkey: ED, signature: SIG });
    expect(parsePhoneReply(JSON.stringify({ pubkey: P256, signature: SIG }))).toEqual({ pubkey: P256, signature: SIG });
  });

  it('drops extra fields', () => {
    expect(parsePhoneReply(JSON.stringify({ pubkey: ED, signature: SIG, origin: 'x' }))).toEqual({ pubkey: ED, signature: SIG });
  });

  it('returns null for anything malformed, never throws', () => {
    for (const bad of [
      'not json',
      'null',
      '42',
      '"text"',
      '[]',
      JSON.stringify({ pubkey: ED }),
      JSON.stringify({ signature: SIG }),
      JSON.stringify({ pubkey: ED.toUpperCase(), signature: SIG }),
      JSON.stringify({ pubkey: 'ed25519:' + ED, signature: SIG }),
      JSON.stringify({ pubkey: 'p256:04' + 'cd'.repeat(32), signature: SIG }),
      JSON.stringify({ pubkey: ED, signature: SIG.slice(2) }),
      JSON.stringify({ pubkey: ED, signature: SIG, pad: 'x'.repeat(5000) }),
      undefined,
      42,
    ]) {
      expect(parsePhoneReply(bad), String(bad).slice(0, 40)).toBeNull();
    }
  });
});
