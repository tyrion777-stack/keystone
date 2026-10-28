import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBytes } from '@noble/hashes/utils';
import { isSignInChallenge } from './signing-policy';
import { signChallenge } from './crypto';

function vectors(name: string) {
  const path = fileURLToPath(new URL(`../../test-vectors/${name}`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8'));
}

const signedMessages = vectors('signed_message.json');
const serviceRequests = vectors('service_request.json');

describe('isSignInChallenge', () => {
  it('accepts a challenge as the sign-in service issues it (32 random bytes, hex)', () => {
    expect(isSignInChallenge('a1'.repeat(32))).toBe(true);
    expect(isSignInChallenge('0123456789abcdef'.repeat(4))).toBe(true);
  });

  it('accepts 16 to 64 bytes, the same bounds core puts on a nonce', () => {
    expect(isSignInChallenge('ab'.repeat(16))).toBe(true);
    expect(isSignInChallenge('ab'.repeat(64))).toBe(true);
    expect(isSignInChallenge('ab'.repeat(15))).toBe(false);
    expect(isSignInChallenge('ab'.repeat(65))).toBe(false);
  });

  it('refuses every signed request and approval in the shared vectors', () => {
    let checked = 0;
    for (const c of serviceRequests.cases) {
      for (const m of [c.signed, c.issued, c.approval]) {
        if (!m) continue;
        expect(isSignInChallenge(m.content), c.name).toBe(false);
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(serviceRequests.cases.length);
  });

  it('refuses every content in the signed message vectors', () => {
    for (const c of signedMessages.cases) {
      expect(isSignInChallenge(c.message.content), c.name).toBe(false);
    }
  });

  it('refuses anything that is not plain lowercase hex', () => {
    for (const bad of [
      '',
      'A1'.repeat(32),
      'a1'.repeat(32) + '\n',
      ' ' + 'a1'.repeat(32),
      'a'.repeat(63),
      'g1'.repeat(32),
      '{"kind":"keystone.follow"}',
      'Sign in to your bank',
    ]) {
      expect(isSignInChallenge(bad), JSON.stringify(bad)).toBe(false);
    }
  });

  it('refuses values that are not strings', () => {
    for (const bad of [undefined, null, 42, ['a1'.repeat(32)], { challenge: 'a1'.repeat(32) }]) {
      expect(isSignInChallenge(bad)).toBe(false);
    }
  });
});

describe('signChallenge', () => {
  it('signs exactly as core does', () => {
    const seed = hexToBytes(signedMessages.keys.ed25519_private_hex);
    const legacy = signedMessages.cases.find((c: { name: string }) => c.name === 'ed25519_legacy');
    expect(signChallenge(seed, legacy.message.content)).toBe(legacy.message.signature);
  });
});
