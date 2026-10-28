// What the extension is willing to sign for a web page.
//
// The extension signs with the person's key and the same rule (Blake3 hex, then Ed25519) as every
// other Keystone message: approvals, follows and service requests are all signed this way, and all
// of them are JSON. A page that could get any text signed could get one of those signed in the
// person's name. So a page gets one shape signed and nothing else: a sign-in challenge, which is
// lowercase hex of 16 to 64 bytes (the bounds core puts on a nonce) and can never parse as JSON.

const SIGN_IN_CHALLENGE = /^(?:[0-9a-f]{2}){16,64}$/;

export function isSignInChallenge(challenge: unknown): challenge is string {
  return typeof challenge === 'string' && SIGN_IN_CHALLENGE.test(challenge);
}
