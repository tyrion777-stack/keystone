// The challenge a page may ask the extension to sign in with.
//
// The extension never signs text a page chose. For a sign-in it builds the signed text itself
// (requests.ts): the page's real origin and this challenge. The challenge must be lowercase hex
// of 16 to 64 bytes, the bounds core puts on a nonce, so it is refused before any window opens
// if it is anything else.

const SIGN_IN_CHALLENGE = /^(?:[0-9a-f]{2}){16,64}$/;

export function isSignInChallenge(challenge: unknown): challenge is string {
  return typeof challenge === 'string' && SIGN_IN_CHALLENGE.test(challenge);
}
