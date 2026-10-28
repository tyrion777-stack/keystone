# Changelog

## Unreleased

- **Sign-in bound to a site** (`sign_in`): `sign_in_content(origin, challenge)` is what a
  browser signs; `verify_sign_in(signed, origin, challenge)` is what the service checks. A
  signature made on one site fails on every other. Vectors: `test-vectors/sign_in.json`.
- `VerifiedRequest::approval_content`: the text to sign to approve a request, for a key held
  outside an `Identity` (a browser extension, a phone app).

## 0.2.0

Everything here is new since 0.1.2. Signatures made by 0.1.x keep verifying: the bare-hex
Ed25519 form is unchanged.

### Sign-in without the app
- **P-256 keys** (`key::PublicKey`, `key::Algorithm`): a key in a phone's secure chip or a
  security key. Wire form `p256:<33-byte compressed point, hex>`; bare hex stays Ed25519.
  `SignedMessage::verify` accepts both. Low-S signatures only.
- **Passkeys (WebAuthn)** (`webauthn`): `WebAuthnRegistration::verify` and
  `WebAuthnAssertion::verify` check a browser passkey against challenge, origin and RP id,
  with no CBOR and no attestation. Pair with `js/keystone-passkey.js` on the page.
- **Signed service requests and bound approvals** (`request`): a service signs what it is
  asking for (`ServiceRequest`); the person's approval is bound to that exact request, service
  key and purpose (`VerifiedRequest::approve`, `verify_approval`).

### Network and content
- Content-addressed file transfer with chunking and resume (`content`); remote chunk
  parameters are bounded and content hashes validated before any filesystem use.
- X25519 envelope encryption for private files (`encryption`).
- DHT revocation records (`follow::create_revocation`, `RevocationRecord`).
- QUIC alongside TCP; circuit relay and DCUtR through the bootstrap node.
- DHT identity lookup by Keystone public key.
- The `node` binary takes its bootstrap node from `--bootstrap` or `KEYSTONE_BOOTSTRAP`;
  none is compiled in.

### Features
- `network` (default): the P2P stack (libp2p, tokio) and the command-line programs. With
  `default-features = false` you get keys, signing, passkeys, signed requests, content and
  encryption with no networking in the build.

### Breaking
- `KeystoneError` has new variants: `UnsupportedAlgorithm`, `WebAuthn`, `Request`. An
  exhaustive `match` on it needs new arms.
- Minimum Rust 1.87 (`rust-version`). With `network` on, current libp2p dependencies need 1.88.

All signing paths are pinned by the shared vectors in `test-vectors/` in the repository.
