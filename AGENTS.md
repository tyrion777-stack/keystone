# AGENTS.md

Rules for any AI agent working in this repository. Where this is heading, see
`docs/HARDWARE_KEYS_PLAN.md`.

Keystone is a cryptographic identity library and relay protocol. Mistakes here can
compromise private keys or allow impersonation. The code is read by people who will
stake their identity on it.

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
  or bounds validation, wire format of existing message types — `src/identity.rs`,
  `src/content.rs` security paths, `src/error.rs`, the `alg` dispatch): show the
  ticket **and a short plan**, wait for a yes before writing code.

When unsure of the class, pick the higher one.

---

## Always

- **Work on a branch** named `feat/…`, `fix/…`, or `stage<N>/…`. Branch off `master`.
  Never commit directly to `master`.
- **Open a pull request.** CI (`cargo build`, `cargo test`, `cargo clippy`, `cargo fmt
  --check`) must be green before merge. State in the PR description which tests you ran.
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
  (`src/bin/`) are acceptable; panics in any function a downstream crate can call are not.
- **Never store or log a private key in plaintext.** Key material is encrypted before
  it touches disk (Argon2id + AES-256-GCM, see `docs/SECURITY_AND_PRIVACY_PLAN.md`).
- **Never skip input validation on data from a remote peer** — not in a test, not because
  "the caller should have checked", not to keep the code short.
- **Never name a real service, person, domain, or field of work** in an example, test
  fixture, or doc. Use a generic "front desk" or `example.com`.
- **Never break an existing verifier.** The wire format of a published message type is
  stable. Additions (new optional fields, new `alg` variants) are fine; removals and
  renames are not. `alg` defaults to `ed25519` so every existing message still verifies
  without the field.
- **Never push directly to `master` or force-push.**
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

- Rust edition 2024. `cargo fmt` and `cargo clippy --all-features -- -D warnings` must
  pass before a PR opens.
- Errors via `thiserror` in `src/error.rs` with a descriptive message. No `unwrap()` or
  `expect()` in library code except inside `#[cfg(test)]` blocks.
- **Algorithm dispatch:** `alg` field on messages. Default `ed25519` so old messages
  verify without it. New algorithms add a variant — they never replace `ed25519`.
- **Public key format:** `<alg>:<hex>` (e.g. `ed25519:abc123…`, `p256:def456…`) so a
  key is never silently read as the wrong type.
- **Stages map to branches.** Work on `docs/HARDWARE_KEYS_PLAN.md` Stage N goes on a
  branch named `stage<N>/…` so progress is traceable.
