// keystone-passkey.js — passkeys for a service's own page, verified by keystone-core.
//
// No dependencies. Drop it into your page as an ES module:
//
//   import { linkPasskey, signInWithPasskey } from './keystone-passkey.js';
//
// Link, once:
//   const { credentialId, registration } = await linkPasskey({
//     challenge, rpId: 'example.com', rpName: 'Front desk', userName: 'visitor-0001' });
//   // POST registration to your server -> WebAuthnRegistration::verify()
//   // store the returned "p256:…" key and credentialId against your record
//
// Check in:
//   const { credentialId, assertion } = await signInWithPasskey({ challenge, rpId: 'example.com' });
//   // POST to your server; add `author` (the stored "p256:…" key for credentialId)
//   // -> WebAuthnAssertion::verify()
//
// `challenge` is base64url from your server: 16+ random bytes, single use.
// Byte fields come back base64url without padding, the form keystone-core expects.

const ES256 = -7;

export class PasskeyError extends Error {
  /** @param {'unsupported' | 'cancelled' | 'failed'} code */
  constructor(code, message, cause) {
    super(message, { cause });
    this.name = 'PasskeyError';
    this.code = code;
  }
}

/** True when this browser can make and use passkeys with this helper. */
export function passkeysSupported() {
  return typeof window !== 'undefined'
    && window.isSecureContext
    && typeof window.PublicKeyCredential === 'function'
    && typeof window.AuthenticatorAttestationResponse === 'function'
    && typeof window.AuthenticatorAttestationResponse.prototype.getPublicKey === 'function'
    && typeof window.AuthenticatorAttestationResponse.prototype.getAuthenticatorData === 'function';
}

/**
 * Make a passkey for this person and return what the server needs to link it.
 *
 * @param {object} o
 * @param {string} o.challenge        base64url, from your server
 * @param {string} o.rpId             your domain, e.g. "example.com"
 * @param {string} o.rpName           shown to the person, e.g. "Front desk"
 * @param {string} o.userName         shown in the person's passkey list; not a secret, avoid personal data
 * @param {string} [o.userDisplayName]
 * @param {string} [o.userId]         base64url, your opaque record id (no personal data); random if omitted
 * @param {boolean} [o.requireUserVerification=true]  fingerprint, face or PIN
 */
export async function linkPasskey(o) {
  requireSupport();
  const userId = o.userId ? fromB64u(o.userId) : crypto.getRandomValues(new Uint8Array(16));
  const credential = await call(() => navigator.credentials.create({
    publicKey: {
      challenge: fromB64u(o.challenge),
      rp: { id: o.rpId, name: o.rpName },
      user: { id: userId, name: o.userName, displayName: o.userDisplayName ?? o.userName },
      pubKeyCredParams: [{ type: 'public-key', alg: ES256 }],
      authenticatorSelection: {
        residentKey: 'preferred', // lets check-in work without typing a name
        userVerification: uv(o.requireUserVerification),
      },
      attestation: 'none',
      timeout: 60_000,
    },
  }));
  const r = credential.response;
  const publicKey = r.getPublicKey();
  if (r.getPublicKeyAlgorithm() !== ES256 || !publicKey) {
    throw new PasskeyError('unsupported', 'this authenticator did not make a P-256 key');
  }
  return {
    credentialId: toB64u(credential.rawId),
    userId: toB64u(userId),
    registration: {
      public_key: toB64u(publicKey),
      public_key_algorithm: ES256,
      authenticator_data: toB64u(r.getAuthenticatorData()),
      client_data_json: toB64u(r.clientDataJSON),
    },
  };
}

/**
 * Sign the server's challenge with a linked passkey.
 *
 * @param {object} o
 * @param {string} o.challenge          base64url, from your server
 * @param {string} o.rpId
 * @param {string[]} [o.credentialIds]  base64url; omit to let the person pick any passkey for rpId
 * @param {boolean} [o.requireUserVerification=true]
 */
export async function signInWithPasskey(o) {
  requireSupport();
  const credential = await call(() => navigator.credentials.get({
    publicKey: {
      challenge: fromB64u(o.challenge),
      rpId: o.rpId,
      allowCredentials: (o.credentialIds ?? []).map(id => ({ type: 'public-key', id: fromB64u(id) })),
      userVerification: uv(o.requireUserVerification),
      timeout: 60_000,
    },
  }));
  const r = credential.response;
  return {
    credentialId: toB64u(credential.rawId),
    userId: r.userHandle ? toB64u(r.userHandle) : null,
    assertion: {
      authenticator_data: toB64u(r.authenticatorData),
      client_data_json: toB64u(r.clientDataJSON),
      signature: toB64u(r.signature),
    },
  };
}

function requireSupport() {
  if (!passkeysSupported()) {
    throw new PasskeyError('unsupported', 'this browser cannot use passkeys here (needs HTTPS and a current browser)');
  }
}

function uv(required) {
  return required === false ? 'preferred' : 'required';
}

async function call(fn) {
  let credential;
  try {
    credential = await fn();
  } catch (e) {
    // NotAllowedError covers both "cancelled" and "timed out"; browsers do not tell them apart.
    if (e && e.name === 'NotAllowedError') throw new PasskeyError('cancelled', 'the person cancelled or the request timed out', e);
    throw new PasskeyError('failed', String(e && e.message || e), e);
  }
  if (!credential) throw new PasskeyError('cancelled', 'no passkey was returned');
  return credential;
}

function toB64u(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64u(s) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new PasskeyError('failed', 'expected base64url without padding');
  }
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4));
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}
