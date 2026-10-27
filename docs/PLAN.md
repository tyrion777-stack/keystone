# Keystone — The Full Plan

This document captures where Keystone is going, why, and how to get there.
It covers everything from immediate DeltaType hardening through the long-term
vision of a universal internet identity layer. Read PHILOSOPHY.md first for
the foundational thinking behind these decisions.

---

## What Keystone Is

A universal identity layer for the internet.

One key per person. Permanent. Owned by nobody but you. Devices are portals
to your identity — not the identity itself. Your data is yours by default,
encrypted, selectively opened on your terms. Real communities form through
trust, not through platforms that own the relationship.

The goal is not a better login system. It is a structural fix to who owns
your digital existence.

---

## Where We Are

### Done

```
Cryptographic core:
  Ed25519 signing and verification
  X25519 ECDH encryption
  AES-256-GCM symmetric encryption
  Argon2id key derivation
  Blake3 content addressing

P2P layer:
  TCP transport with Noise encryption and Yamux multiplexing
  mDNS — zero-config LAN discovery
  Kademlia DHT — distributed WAN peer routing
  Request-response data transfer between peers

DeltaType integration (live in production):
  Challenge-response auth via keystone-sidecar
  Browser-side key generation (Argon2id + AES-256-GCM encrypted localStorage)
  Enrollment token flow — add new devices
  Device management — list, revoke
  Admin keygen page
  Keystone login tab alongside password login
```

### Current gaps

```
Sessions die on container restart (in-memory Map, no persistence)
No rate limiting on Keystone auth endpoints
Password login still exists — attack surface, should be removed
Key rotation not implemented — compromise currently unrecoverable
No key transfer between devices — new device requires re-enrollment
No SUPERADMIN_PUBKEY pattern — operator must enroll per client site
```

---

## Design Constraints

These are not aspirations. They are hard limits that govern every
architectural decision. Full reasoning in PHILOSOPHY.md.

1. **One person, one identity, permanent.** The citizen proof is generated
   once in a lifetime. New device means nothing — devices are portals.

2. **Never charge users to exist.** Identity creation is always free.
   The moment it costs money, equal opportunity is gone.

3. **Never aggregate trust into global scores.** Vouches are local and
   contextual. No leaderboard. No reputation number. No tier system.

4. **Never gate access to necessities.** Communities can exclude.
   The protocol has no connection to real-world enforcement.

5. **Always allow exit.** New keypair, different relay, different community.
   No single entity can remove you from the protocol.

6. **Nothing revealed that doesn't have to be.** Privacy is the default.
   Disclosure is a choice made by the key owner.

---

## Phase 1 — Lock Down the Testing Ground

**Outcome:** Keystone is the only way into DeltaType. Reliable under real
conditions. One key signs you into every client site with no per-site setup.

**Timeline: one week.**

### Sessions → DB table

Replace the in-memory `Map` in `session.ts` with a `sessions` table in
Postgres. Sessions survive container restarts. Sessions can be listed
and revoked per user. Rolling expiry — 7 days, extended on each use.

```sql
CREATE TABLE sessions (
  token      TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role       TEXT NOT NULL,
  email      TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX sessions_expires_at ON sessions(expires_at);
```

`session.ts` becomes DB reads/writes. Clean up expired rows on each auth
check — no cron job needed, just prune on read.

### Rate limit the Keystone auth endpoint

The existing `ratelimit.ts` is in-memory and that is fine — rate limit
state resetting on restart is acceptable. Just wire it to
`/api/auth/keystone`.

10 attempts per 15 minutes per IP. After that, 429 with `Retry-After`.
Apply to both the GET (challenge request) and POST (verification).

### SUPERADMIN_PUBKEY via settings table

The `settings` table already exists. Use it.

On `new-client.sh` setup, seed a `superadmin_pubkey` entry into the
settings table. The Keystone auth handler reads it on each request.
No container restart needed to update it.

```typescript
// In /api/auth/keystone/+server.ts — after signature verification:
const [setting] = await db.select().from(settings)
  .where(eq(settings.key, 'superadmin_pubkey'));
const superadminPubkey = setting?.value?.pubkey ?? '';

if (superadminPubkey && pubkey_hex === superadminPubkey) {
  const [superadmin] = await db.select().from(users)
    .where(eq(users.role, 'superadmin')).limit(1);
  if (!superadmin) throw error(500, 'No superadmin configured');
  user = superadmin;
} else {
  // existing device table lookup
}
```

### Operator key on the server — one-time setup

Store your pubkey once on the server. Every new client gets it automatically.

```bash
# Run once on the server:
echo 'your_64_char_pubkey_hex' > ~/.deltatype_operator

# new-client.sh reads it:
OPERATOR_PUBKEY=$(cat ~/.deltatype_operator 2>/dev/null)
if [ -z "$OPERATOR_PUBKEY" ]; then
  echo "Error: ~/.deltatype_operator not found."
  echo "Create it: echo 'your_pubkey' > ~/.deltatype_operator"
  exit 1
fi
# Seeds settings table with OPERATOR_PUBKEY during setup
```

### Remove password login

Delete the password tab from `+page.svelte` admin login.
Remove the `default` action from `/admin/login/+page.server.ts`.
The `changePassword` action in `/admin/account` can stay temporarily —
it becomes dead UI once the tab is gone.

`create-admin.js` stays as a CLI-only bootstrap tool. That is correct.
Passwords exist only for initial setup via command line. Never via the web.

### Verify with the full test checklist

Run every test from the test plan before declaring Phase 1 done:
keygen, sign in with saved key, wrong password, raw key fallback,
second device enrollment, enrollment token single-use, device revocation,
container restart resilience, Fred on his own device.

---

## Phase 2 — Key Management Becomes Solid

**Outcome:** Devices are truly portals. Losing a device means nothing.
Key compromise is recoverable. New device = thirty seconds, not re-enrollment.

**Timeline: four to six weeks.**

### Key rotation

The most critical missing piece. Without it, a compromised key is permanently
lost — the attacker owns your identity forever.

Old key signs a rotation record:

```json
{
  "type":        "key_rotation",
  "previous_key": "old_pubkey_hex",
  "new_key":      "new_pubkey_hex",
  "timestamp":    "2026-06-18T...",
  "signature":    "... signed by old key ..."
}
```

Published to the DHT. Sites check for rotation records before accepting
auth from any key. If your old key has a rotation record pointing to a
new key, only the new key is accepted.

This is a signed append-only log entry. No blockchain. No consensus.
The old key's signature is the authority.

### Encrypted key transfer between devices

New device, same identity. Thirty seconds. No server involved.

Option A — QR code (ship this first):
Old device displays the encrypted key blob as a QR code.
New device scans it. Prompts for password. Decrypts locally.
Done. No network. No server. No exposure.

Option B — P2P transfer over mDNS (add later):
Two devices on the same network find each other via mDNS.
Old device encrypts key blob to new device's ephemeral X25519 key.
Transfers over encrypted channel. New device decrypts.
Requires the P2P layer — already built.

### Per-app subkeys

One master key. A unique derived subkey per deployment domain.

```
Master keypair   (never transmitted, lives on device)
    ↓  BLAKE3(master_private + domain)
App subkey for deltatype.com
App subkey for clientsite.com
App subkey for anothersite.com
```

Each site sees a different pubkey. No site can correlate you with
another site without your consent. Compromise on one site exposes
nothing about your identity elsewhere.

You can prove all subkeys belong to the same master — selectively,
when you choose to link accounts across sites.

### Encrypted key backup

Standardize the backup format. Already designed in SECURITY_AND_PRIVACY_PLAN.md.
Ship it as a CLI command and as a downloadable file from the admin.

```
salt(16) + nonce(12) + AES-256-GCM(Argon2id(password, salt), key_bytes)
```

Store it anywhere — USB, cloud, email. Useless without the password.

---

## Phase 3 — Browser Extension

**Outcome:** Your identity follows you everywhere. Any Keystone-enabled
site works without setup. You are one person on the entire internet.

**Timeline: six to eight weeks.**

The identity wallet. This is the leap from "auth plugin per site" to
"universal identity in the browser."

- Key stored in `chrome.storage.local` — outside clearable browser storage
- OS keychain backing — survives browser reinstalls
- Injects two functions into every page:
  - `window.keystone.sign(challenge)` — signs any challenge, returns signature
  - `window.keystone.getPublicKey()` — returns your pubkey
- Any site that calls those functions gets Keystone auth working
- You set your password once at install. Done forever.
- Works across all tabs, all sites, all sessions

After this phase you never visit `/admin/keygen` on a new site.
You just sign in. Your identity is in your browser.

---

## Phase 4 — Protocol Becomes Standalone

**Outcome:** Any developer integrates Keystone auth in an afternoon.
Keystone can spread beyond your own sites.

**Timeline: four weeks.**

Extract the auth logic from DeltaType into standalone packages:

**`keystone-client`** — npm package for frontends.
`generateKey()`, `saveKey(password)`, `loadKey(password)`,
`sign(challenge)`, `getPublicKey()`.

**`keystone-verify`** — npm package for backends.
`verifySignature(pubkey, challenge, signature)` — five lines,
any Node.js server accepts Keystone auth.

**`keystone-core`** — publish to crates.io.
The Rust library already exists. Package it properly.

**Protocol spec** — a plain document.
Exact JSON format. Challenge-response flow. Verification rules.
Language-agnostic. Anyone implements it in any language.

---

## Phase 5 — Identity Document

**Outcome:** You arrive at a new Keystone site and it already knows
your name and avatar. You filled it in once. It follows you everywhere.

**Timeline: two weeks.**

A self-signed JSON document. Generated on your device. Published to relays.

```json
{
  "pubkey":    "your_pubkey_hex",
  "name":      "Your Name",
  "avatar":    "https://...",
  "website":   "https://...",
  "bio":       "...",
  "signed_at": "2026-06-18T...",
  "signature": "..."
}
```

Sites fetch it when they first see your pubkey. No profile form ever again.
This is also the foundation the citizen proof attaches to in Phase 7.

---

## Phase 6 — Proof of Work on Registration

**Outcome:** Creating fake identities costs real time. Mass Sybil attacks
become economically painful without creating any financial barrier.

**Timeline: one week.**

When you create a Keystone identity for the first time, your device solves
a Blake3 puzzle. Two to three seconds on a normal phone. One time ever.

```
Find N such that:
  Blake3(pubkey_hex + N)[0..difficulty] == "0000..."
```

The solution is embedded in your identity document. Any node verifies it
in one Blake3 call — instant. Generating one identity: invisible friction.
Generating a million fake identities: weeks of compute.

Difficulty is tunable. Set it so a phone solves it in under five seconds.
A bot farm solving it a million times still pays a real electricity bill.

This is not uniqueness. It is cost. The floor rises without a gate.

---

## Phase 7 — ZK Citizen Proof

**Outcome:** Cryptographic proof you are a real unique human. Generated
once in your life. Attached to your key forever. Reveals nothing about you.

**Timeline: three to six months.**

The hardest phase. The most important for the long-term vision.

### What it proves

"A real person generated this key at a specific moment in time."

Nothing else. Not where you were. Not what device you used. Not who you are.

### What goes in — person-bound, not device-bound

```
PRIVATE — stays on your device, never transmitted:
  Rough location        proves you exist on Earth, not a data center
  Behavioral fingerprint  how you move and type — yours, follows you
  Biometric hash        Face ID or fingerprint if device supports it
  Timestamp             when you became a citizen

PUBLIC — known to everyone:
  Your Keystone public key
  PoW solution
  Timestamp
```

Device hardware is deliberately excluded. The proof is about the person.
New device, same key, same proof. The proof does not know or care what
phone you are using today.

### How the compute works

Proof generation: runs on your device. Private inputs never leave.
Roughly three to eight seconds on current mobile hardware. Once. Ever.

Proof verification: runs on Keystone nodes. Milliseconds. Trivial.
Fully distributed — any node can verify any proof.

Proof storage: relays hold it permanently attached to your public key.
Anyone can check it anytime without involving you.

### Technology

plonky2 or arkworks in Rust. Circuit design in noir.
All three are mature libraries. The cryptography is solved.
The work is designing the circuit — what inputs, what the proof asserts,
how to tune it so real humans in edge cases still pass.

### What this makes possible

A verifiably real human identity that reveals nothing about the human.
No government ID. No biometric database. No company holding your data.
Just math that says: a real person was here.

---

## Phase 8 — Web of Trust

**Outcome:** Communities form. People vouch for each other. Trust has
real meaning without becoming a score.

**Timeline: two to three months.**

### Attestations

A vouch is a signed message. Already supported by SignedMessage format.

```json
{
  "type":      "vouch",
  "from":      "pubkey_A",
  "for":       "pubkey_B",
  "claims":    ["known-irl", "real-person"],
  "expires":   "2027-06-18",
  "signature": "..."
}
```

Revocable. Expirable. Readable by anyone. Verifiable by anyone.
Issued by the voucher. Means whatever the reader decides it means
given how much they trust the voucher. No global aggregation. Ever.

### Communities

A shared community keypair. A signed membership list. New members
added when existing members vouch for them. The community key signs
the list. Anyone can verify membership without asking the community.

### Graph analysis — Sybil detection

Organic human social graphs have specific structural properties.
Sybil farms do not.

Rules:
- Connections forming too fast get reduced trust weight, not blocked
- Connections to long-established identities validate fast-forming ones
- Dense clusters of new identities with no external links: high suspicion
- The algorithm flags. It never hard-blocks. Humans correct machines.

The vouching system is the appeal mechanism. Ten established trusted
connections saying "this person is real" overrides any algorithmic flag.

---

## Phase 9 — Relay Network

**Outcome:** The network runs itself. No single point of control.
Communities own their infrastructure.

**Timeline: two to three months.**

Simple relay servers. Accept, store, forward signed messages.
Anyone runs one. Communities run their own.

Identity documents, citizen proofs, attestations, community lists —
all stored on relays. Content-addressed via Blake3 so any mirror
is verifiable as authentic regardless of who serves it.

Relays cannot forge messages — everything is signed. They can censor —
which is why you use multiple relays in multiple jurisdictions.
Censorship resistance through redundancy, not through consensus.

Economic model: communities pay subscription for reliable hosted relays.
Anyone self-hosts for free. The protocol has no opinion on this.

---

## Phase 10 — Data Consent Marketplace

**Outcome:** Your data makes you money. Ad companies pay you directly.
You capture the value that currently flows to platforms.

**Timeline: this is a business problem as much as a technical one.
Build after Phase 7 and 8 have established a real user base.**

Your attributes — interests, broad location, purchase patterns — are
encrypted blobs attached to your public key. Nobody reads them.
Closed by default.

You choose to open a hole:

```json
{
  "type":       "consent",
  "from":       "your_pubkey",
  "to":         "advertiser_pubkey",
  "attributes": ["interests", "broad_location"],
  "expires":    "2026-12-31",
  "price":      "agreed_out_of_band",
  "signature":  "..."
}
```

They pay you directly. They read your attribute until expiry.
Expiry passes, access ends cryptographically. No renewal, no access.

Keystone takes a cut of the marketplace transaction.
Not of the data. Of the connection between willing seller and buyer.

This is the business model:
```
Never charge users to exist.
Charge everyone else to reach them.
```

---

## The Timeline

```
Now          Phase 1   DeltaType locked. One key, all sites. No passwords.
Week 4       Phase 2   Key rotation. Device transfer. Devices are portals.
Month 2      Phase 3   Browser extension. Universal identity in the browser.
Month 3      Phase 4   Protocol standalone. Any developer integrates.
Month 4      Phase 5   Identity document. Name follows the key.
Month 4      Phase 6   PoW on registration. Sybil cost established.
Month 6-9    Phase 7   ZK citizen proof. Cryptographic proof of personhood.
Month 9-12   Phase 8   Web of trust. Communities. Graph analysis.
Month 12     Phase 9   Relay network. Self-sustaining infrastructure.
Month 18+    Phase 10  Data consent marketplace. The business model.
```

---

## The Test for Every Decision

From VISION.md:
> Which person does this help, and how does their day get better?

From PHILOSOPHY.md:
> Does this give any single entity — including us — the ability to remove
> someone's identity, aggregate their trust into a score, or gate their
> access to the protocol?

If the answer to the second question is yes: don't build it.
