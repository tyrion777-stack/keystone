// The WebAssembly build of keystone-core, through its JavaScript wrapper, against the shared
// vectors: the extension must agree with core on every case.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  KeystoneCoreError,
  signInContent,
  verifyApproval,
  verifyRequest,
  verifySignIn,
} from '../../wasm/js/keystone-core';

function vectors(name: string) {
  const path = fileURLToPath(new URL(`../../test-vectors/${name}`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8'));
}

const ok = (p: Promise<unknown>) => p.then(() => true, e => {
  if (!(e instanceof KeystoneCoreError)) throw e;
  return false;
});

describe('keystone-core (WebAssembly)', () => {
  it('agrees with core on every service request and approval vector', async () => {
    const { cases } = vectors('service_request.json');
    expect(cases.length).toBeGreaterThanOrEqual(39);
    for (const c of cases) {
      const valid = c.kind === 'request'
        ? await ok(verifyRequest(c.signed, c.now))
        : await ok(verifyApproval(c.approval, c.issued, c.now));
      expect(valid, c.name).toBe(c.valid);
    }
  });

  it('agrees with core on every sign-in vector', async () => {
    const { cases } = vectors('sign_in.json');
    expect(cases.length).toBeGreaterThanOrEqual(18);
    for (const c of cases) {
      expect(await ok(verifySignIn(c.signed, c.expected_origin, c.expected_challenge)), c.name).toBe(c.valid);
    }
  });

  it('builds sign-in content byte for byte as core does', async () => {
    const [valid] = vectors('sign_in.json').cases;
    expect(await signInContent(valid.expected_origin, valid.expected_challenge)).toBe(valid.signed.content);
  });

  it('returns what a screen and an approval need', async () => {
    const [c] = vectors('service_request.json').cases;
    const v = await verifyRequest(c.signed, c.now);
    expect(v.serviceKey).toBe(c.signed.author);
    expect(v.request.service).toBe('Front desk');
    expect(v.request.origin).toBe('https://desk.example.com');
    expect(JSON.parse(v.approvalContent)).toMatchObject({ kind: 'keystone.approval', request: c.signed.content_hash });
  });

  it('answers bad input with an error, many times over, without leaking or breaking', async () => {
    for (let i = 0; i < 2000; i++) {
      await expect(verifyRequest({ author: 'x', content: 'y'.repeat(i), content_hash: '', signature: '' }, 1))
        .rejects.toBeInstanceOf(KeystoneCoreError);
    }
    const [c] = vectors('service_request.json').cases;
    expect((await verifyRequest(c.signed, c.now)).serviceKey).toBe(c.signed.author);
  });
});
