# Hardware Keys and In-Person Sign-In — Plan

A person should be able to prove who they are at a counter in five seconds, with a key that
never leaves the chip in their phone or card, and with no app to install on day one.

This plan is Keystone's half of that. It is written for any service where people show up in
person: a front desk, a counter, a gate. What a service knows about a person (their records,
their account, their family) stays in that service's own code. Keystone proves the key and
carries the messages; it never learns what the key is for.

---

## The loop this plan serves

1. **Link, once.** The service's screen shows a QR. The person approves on their phone with a
   fingerprint. The service stores the public key against its own record of them.
2. **Check in.** The screen shows a fresh QR. The person approves. The service recognises the
   key. About five seconds; nothing to copy, because every challenge is new.
3. **Tap.** A person without a smartphone taps a FIDO card on the desk's reader. The card signs
   on the spot. No relay, no network.
4. **Send something later.** The person sends a signed, encrypted message to the service (a
   correction, a request). The relay holds it until the service collects it. The service replies
   the same way.
5. **Lose a device.** The person's other device, or the service in person, revokes the old key.
   Verifiers everywhere stop accepting it.

---

## What belongs where

| Keystone (this repo, open source) | The service (its own code) |
|---|---|
| Key types, signing, verification | What a key is linked to |
| Passkey (WebAuthn) bridge | Its own screens and its own records |
| Signed requests from a service, shown verified | Which requests it makes and why |
| Relay: rooms, mailboxes, encryption, limits | What its messages mean |
| Device lists and revocation | Whether to accept a re-link in person |
| The app, the extension, hardware key storage | Nothing about how Keystone stores keys |

Rule for this repo: no example, test fixture or doc names a real service, person or field of
work. Examples use a generic "front desk".

---

## Stage 1 — Two key types

Phones keep keys in hardware, and the hardware decides the curve:

| Where | Ed25519 | P-256 |
|---|---|---|
| Android Keystore / StrongBox | Android 13+ (to confirm) | all supported versions |
| iPhone Secure Enclave | no | yes |
| Browser passkeys (WebAuthn) | some authenticators | all |
| FIDO security keys and cards | many | all |

So Keystone signs and verifies both.

- [x] The algorithm travels inside the key, not beside it: `author` is bare hex for Ed25519
      (so every existing message still verifies) and `p256:<hex>` for P-256
- [x] `SignedMessage::verify()` dispatches on the author's key type (`src/key.rs`)
- [ ] `Identity` can hold a P-256 key, with a versioned encrypted key file (1b)
- [x] Public keys printed with their algorithm (`ed25519:…`, `p256:…`) so a key is never read as the wrong kind
- [x] Test vectors for both in Rust (`test-vectors/signed_message.json`), including the Blake3-hex
      signing rule, cross-checked against OpenSSL
- [ ] The same vectors run in JavaScript (1c)
- [ ] Verifiers (the extension, the sidecar pattern in the README) accept both

## Stage 2 — Passkeys without the app

Every phone browser can already make a key in its own chip and unlock it with a fingerprint.
Keystone should accept that key as an identity, so a service can start before the app ships.

- [ ] A `webauthn` message type. A passkey signs `authenticatorData || sha256(clientDataJSON)`,
      not Keystone's Blake3 hex, so it is its own type with its own verifier
- [ ] Verification checks the challenge, the origin, the relying-party id and the user-presence flag
- [ ] COSE public keys converted to Keystone's printed form (`p256:…`)
- [ ] A small JS helper a service drops into its page: register, then sign a challenge
- [ ] Note in the docs: synced passkeys (Google, Apple) are hardware-made but copied, encrypted,
      to the person's other devices; a FIDO card is the strictly device-bound option

When the app arrives it offers the same flow with a key it holds itself, and the service's code
does not change.

## Stage 3 — Signed requests from a service

Today a QR says `origin: "…"` and the phone believes it. A fake screen could ask for anything.

- [ ] A service has its own Keystone identity and signs every request: origin, purpose
      (`link`, `check-in`, `sign`), nonce, expiry
- [ ] The app and extension verify it and show the service's name as verified, or refuse
- [ ] Pin on first link: after the first approval the phone remembers that service's key, and a
      later request from a different key for the same name is a warning
- [ ] The approval signs the whole request, so it cannot be replayed for another purpose

## Stage 4 — Relay

Today the relay is a one-shot rendezvous: the desk opens a room, the phone sends one message,
the room closes. In memory, no checks, five minutes. Enough for stages 2 and 3; not for step 4
of the loop.

| # | Needed | Why |
|---|---|---|
| 1 | Connections signed by a Keystone key | A public relay with no checks gets abused |
| 2 | Rate, count, size and age limits per key and per IP | Same |
| 3 | Rooms carry messages both ways, more than one | "Approved, please wait" back to the phone |
| 4 | Mailboxes addressed to a public key, held until collected, then deleted; an expiry | The recipient may be offline |
| 5 | End-to-end encryption (X25519 envelopes, see `RELAY_AND_ENCRYPTION_PLAN.md`) | The relay only ever holds ciphertext |
| 6 | A long-lived outbound subscriber: a service connects out and collects its mail | A service can stay private, with nothing open to the internet |
| 7 | Storage on disk, so more than one relay can run and a restart loses nothing | Mail must survive restarts |
| 8 | Waking a phone without a vendor push service (for example a self-hosted UnifiedPush or ntfy), or the app checks when opened | No dependence on Google or Apple to deliver |

Order: 1, 2, 3 first (safe in public), then 4, 5, 6, then 7, 8.

## Stage 5 — Devices and revocation

- [ ] An identity lists its devices: a signed record of the keys allowed to act for it
- [ ] Adding a device stays the existing `ks_add_device` flow
- [ ] Revoking reuses the DHT revocation records (Phase 3); the relay and verifiers check them
- [ ] A person with no other device is re-linked by the service in person; that is the service's
      decision, recorded as a revocation like any other

## Stage 6 — The app holds keys in hardware

- [ ] Android: keys made in Keystore (StrongBox where present), unlocked by fingerprint; P-256
      everywhere, Ed25519 where the device supports it
- [ ] iPhone: Secure Enclave, P-256. Until an App Store release, the web app (the same SvelteKit
      build) on the home screen, using passkeys from stage 2
- [ ] QR scanning on iPhone: Safari has no `BarcodeDetector`, so a JS decoder as fallback
- [ ] Play Store release (after the DUNS number), with a public page that links the app and the extension

---

## Open questions

- Ed25519 in Android Keystore: which versions, and is StrongBox included? Confirm before stage 6.
- Does the relay become one service or several (rendezvous, mailbox)? Decide before stage 4.
- Passkey relying-party id: the service's own domain. Does Keystone want a shared domain for
  services that have none?
- Who runs the public relay, and what are its limits for free use?
