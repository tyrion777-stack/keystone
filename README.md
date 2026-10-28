# Keystone

A person should be able to prove who they are with a key that never leaves the chip in their
phone or card, at a counter in five seconds, with nothing to install on day one.

Keystone is that key and the protocol around it: portable identity, signed requests and
approvals, passkeys, and a relay to carry messages. It never learns what a key is used for.
What a service knows about a person stays in that service's own code.

Everything is open source under the MIT licence.

## What is here

| Folder | What |
|---|---|
| [`core/`](core/) | The Rust library (`keystone-core` on crates.io): keys, signing and verification, passkeys (WebAuthn), signed service requests, P2P transport |
| [`core/js/`](core/js/) | `keystone-passkey.js`, a dependency-free helper a service drops into its page |
| [`relay/`](relay/) | The relay server that carries messages between a service's screen and a phone |
| [`extension/`](extension/) | The browser extension: a Keystone identity on every page |
| [`app/`](app/) | The phone app (SvelteKit + Capacitor, Android) |
| [`test-vectors/`](test-vectors/) | Shared test vectors every implementation must agree on, and the tools that make them |
| [`docs/`](docs/) | Plans and design notes; start with [`HARDWARE_KEYS_PLAN.md`](docs/HARDWARE_KEYS_PLAN.md) and [`PHILOSOPHY.md`](docs/PHILOSOPHY.md) |

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
