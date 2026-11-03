# Keystone

**Sign in with a key that lives in your phone's chip. No password, no account, no company in
the middle.**

[![crates.io](https://img.shields.io/crates/v/keystone-core.svg)](https://crates.io/crates/keystone-core)
[![docs.rs](https://docs.rs/keystone-core/badge.svg)](https://docs.rs/keystone-core)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

<!-- Demo gif goes here: docs/demo.gif, 10 to 20 seconds, showing a sign-in end to end. -->

A person should be able to prove who they are at a front desk in five seconds, with a key
that never leaves their phone or security key, and with nothing to install on day one.

Keystone is that key and the protocol around it:

- **Your key is your identity.** It is made on your device. No company issued it, so no
  company can take it away.
- **Sign-in that cannot be replayed elsewhere.** A signature made for one site fails on every
  other site.
- **Services sign what they ask for.** Your phone checks who is really asking, and your
  approval is bound to that one request, that service and that purpose.
- **Passkeys work on day one.** Any phone browser can sign in with a passkey. The app is
  optional.
- **Verify anywhere.** A service checks a signature with the public key alone. It never calls
  us, and there is no "us" to call.

## Quickstart

```sh
cargo add keystone-core
```

```rust
use keystone_core::{Identity, SignedMessage, sign_in_content, verify_sign_in};

fn main() -> Result<(), keystone_core::KeystoneError> {
    // A person's key. No account, no password.
    let alice = Identity::generate();

    // Sign anything; anyone can verify with only the public key.
    let signed = alice.sign("hello keystone");
    let json = signed.to_json()?;
    SignedMessage::from_json(&json)?.verify()?;

    // Sign-in bound to one site: a signature made for one origin fails on every other.
    let challenge = "9f86d081884c7d659a2feaa0c55ad015";
    let sig = alice.sign(&sign_in_content("https://example.com", challenge)?);
    let who = verify_sign_in(&sig, "https://example.com", challenge)?;
    assert!(verify_sign_in(&sig, "https://evil.example", challenge).is_err());

    println!("signed in as {}", who.to_wire());
    Ok(())
}
```

A service that only verifies (no P2P networking in the build):

```toml
keystone-core = { version = "0.2", default-features = false }
```

Passkeys, signed service requests, the browser extension API and running a node are covered
in [`core/README.md`](core/README.md).

## How it compares

| | Passwords | Social login | Passkeys alone | Keystone |
|---|---|---|---|---|
| Who issues your identity | The site | The login provider | The site (one key per site) | You, on your device |
| A secret the server can leak | Yes | At the provider | No | No |
| One identity across services | No | Yes, through the provider | No | Yes |
| Someone else can lock you out | The site | The provider and the site | The site | No one can revoke the key |
| You see who is really asking | No | Partly | The site's domain | A signed request, checked against the service's pinned key |
| Install something first | No | No | No | No (passkeys); the app is optional |

Keystone does not replace passkeys. It accepts them: a passkey is a P-256 key in your phone's
chip, and Keystone verifies it like any other key.

## What is here

| Folder | What |
|---|---|
| [`core/`](core/) | The Rust library (`keystone-core` on crates.io): keys, signing and verification, passkeys (WebAuthn), signed service requests, P2P transport |
| [`core/js/`](core/js/) | `keystone-passkey.js`, a dependency-free helper a service drops into its page |
| [`wasm/`](wasm/) | core's checks compiled to WebAssembly, so the app and the extension verify with the same Rust that services run |
| [`relay/`](relay/) | The relay server that carries messages between a service's screen and a phone |
| [`extension/`](extension/) | The browser extension: a Keystone identity on every page |
| [`app/`](app/) | The phone app (SvelteKit + Capacitor, Android) |
| [`test-vectors/`](test-vectors/) | Shared test vectors every implementation must agree on, and the tools that make them |
| [`docs/`](docs/) | Plans and design notes; start with [`HARDWARE_KEYS_PLAN.md`](docs/HARDWARE_KEYS_PLAN.md) and [`PHILOSOPHY.md`](docs/PHILOSOPHY.md) |

## Status

- **`keystone-core` 0.2.0 is on crates.io.** Signatures made by 0.1.x still verify.
- **Every signing path is pinned by shared test vectors** in [`test-vectors/`](test-vectors/),
  so the Rust, WebAssembly and JavaScript verifiers agree case by case.
- **Security review:** the findings are fixed in 0.2.0. Content hashes from remote peers are
  validated before any filesystem use, and chunk sizes and counts from remote peers are
  bounded.
- **The extension and the Android app build from source.** They are not in the stores yet.

Not done yet: key recovery and rotation, cross-device key sync, and more than one bootstrap
node. See [`docs/TASKS.md`](docs/TASKS.md).

## Build and test

```sh
# Rust: core and relay
cargo test --workspace --all-features

# Extension
cd extension && npm ci && npm run build      # load extension/dist unpacked in Chrome

# App
cd app && npm ci && npm run build
```

## Contributing

Read [`AGENTS.md`](AGENTS.md) first. It holds the rules for this repository, for people and
tools alike: one ticket per branch, a failing test before a fix, test vectors for every
signing path, and extra care (a written plan, agreed first) for anything that touches keys,
signing or verification.

## Licence

[MIT](LICENSE)
