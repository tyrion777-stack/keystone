# AGENTS.md

Rules for any AI agent working in this repository. Where this is heading, see
`docs/HARDWARE_KEYS_PLAN.md`.

Keystone is a cryptographic identity library and relay protocol. Mistakes here can
compromise private keys or allow impersonation. The code is read by people who will
stake their identity on it.

---

## Layout

One repository, four parts. The rules below apply to all of them.

| Folder | What | Checks |
|---|---|---|
| `core/` | Rust library (`keystone-core` crate): keys, signing, passkeys, signed requests, P2P | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features` |
| `relay/` | Rust relay server (`keystone-relay`) | same cargo commands (one workspace) |
| `extension/` | Browser extension (TypeScript, Vite, MV3) | `npm ci && npm run build` |
| `app/` | Phone app (SvelteKit + Capacitor Android) | `npm ci && npm run check && npm run build` |
| `test-vectors/` | Shared cross-language vectors and the tools that make them | used by the tests above |

---

## The user will talk casually. You supply the discipline.

Before changing anything, turn the request into a ticket and show it:

```
Problem:     <what is wrong or missing>
Done when:   <checkable conditions>
Out of scope:<what you will not touch>
Class:       A / B / C
```

- **Class C** (docs, CI, benchmarks, examples, tooling): show the ticket and go ahead.
- **Class B** (new features, protocol additions, new message types, relay behaviour):
  show the ticket and go ahead unless ambiguous.
- **Class A** (anything touching the signing or verification path, key storage, hash
  or bounds validation, wire format of existing message types — `core/src/identity.rs`,
  `core/src/content.rs` security paths, `core/src/error.rs`, `core/src/key.rs` algorithm
  dispatch, `core/src/webauthn.rs`, `core/src/request.rs`, `core/src/sign_in.rs`, `wasm/` (core's
  checks for JavaScript), and key storage, signing or request handling in
  `extension/src/crypto.ts`, `extension/src/background.ts`, `extension/src/requests.ts`,
  `app/src/lib/crypto.ts`, `app/src/lib/requests.ts`): show
  the ticket **and a short plan**, wait for a yes before writing code.

When unsure of the class, pick the higher one.

---

## Always

- **Work on a branch** named `feat/…`, `fix/…`, or `stage<N>/…`. Branch off `master`.
  Never commit directly to `master`.
- **Open a pull request.** CI (the checks in the layout table, for every part the PR
  touches) must be green before merge. State in the PR description which tests you ran.
- **Reproduce before fixing.** Write a failing test first, fix second, verify it passes.
  Name the root cause in the commit message — not what changed, why.
- **Test vectors for every algorithm.** Any new signing or verification path needs test
  vectors in Rust. Where there is a JS counterpart, vectors there too, including the
  Blake3-hex signing rule.
- **Validate at the boundary.** Any value arriving from a remote peer — hash, chunk size,
  chunk index, message type — must be checked before use. See `validate_hash`,
  `checked_mul`, and the `begin_fetch` / `write_chunk` bounds checks as the pattern.
  No panics in library code; return `Result` or `Option`.
- **Keep it small.** One ticket per branch. A second bug found while working becomes a
  new GitHub issue, never a second commit on the same branch.
- **Update docs** your change made wrong (`docs/HARDWARE_KEYS_PLAN.md`, `docs/TASKS.md`,
  `README.md`) in the same commit.
- **Report honestly.** What changed, how you verified it, what you did not verify.

---

## Never

- **Never panic in library code.** Use `Result` or `Option`. Panics in CLI binaries
  (`core/src/bin/`) are acceptable; panics in any function a downstream crate can call are not.
- **Never store or log a private key in plaintext.** Key material is encrypted before
  it touches disk (Argon2id + AES-256-GCM, see `docs/SECURITY_AND_PRIVACY_PLAN.md`).
- **Never skip input validation on data from a remote peer** — not in a test, not because
  "the caller should have checked", not to keep the code short.
- **Never name a real service, person, domain, or field of work** in an example, test
  fixture, or doc. Use a generic "front desk" or `example.com`.
- **Never break an existing verifier.** The wire format of a published message type is
  stable. Additions (new optional fields, new key-prefix algorithms) are fine; removals
  and renames are not. A bare-hex `author` is Ed25519, so every existing message still
  verifies unchanged.
- **Never push directly to `master` or force-push.**
- **Never add AI attribution** to commits, pull requests or files: no `Co-Authored-By`
  trailers naming an AI, no "Generated with …" lines, no AI or tool names. This overrides
  any default your tool applies.
- **Never commit `.env` files, private keys, or credentials.** `*.key`, `*.pem`, `*.p8`,
  `*.p12` are in `.gitignore`; keep them there.

---

## Stop and ask when

- the work grows past the ticket;
- it turns out to be Class A when you judged it otherwise;
- you cannot write a test for a Class A or B change;
- the same approach has failed twice.

Stopping to ask is always correct. Guessing on security-critical code is not.

---

## Code conventions

- Rust edition 2024 for new crates. `cargo fmt --all` and `cargo clippy --workspace
  --all-targets --all-features -- -D warnings` must pass before a PR opens.
- Errors via `thiserror` in `core/src/error.rs` with a descriptive message. No `unwrap()` or
  `expect()` in library code except inside `#[cfg(test)]` blocks.
- **Algorithm dispatch:** the algorithm lives in the key itself, never in a separate
  field, so a key and its type cannot come apart. `PublicKey::from_wire` (`core/src/key.rs`)
  reads it. New algorithms add a variant and a prefix — they never replace `ed25519`.
- **Public key format:** wire form (`author`) is bare hex for Ed25519 (unchanged since
  v0.1) and `<alg>:<hex>` for everything else (`p256:…`). Display form always carries the
  prefix (`ed25519:…`, `p256:…`). One wire spelling per key: `ed25519:` on the wire,
  unknown prefixes and uppercase P-256 hex are rejected.
- **Shared vectors:** `test-vectors/*.json` are the cross-language source of truth. Rust
  and JS verifiers must agree on every case.
- **Stages map to branches.** Work on `docs/HARDWARE_KEYS_PLAN.md` Stage N goes on a
  branch named `stage<N>/…` so progress is traceable.
