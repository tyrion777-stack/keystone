# Keystone — Philosophy and Design Constraints

This document captures the foundational thinking behind Keystone that doesn't
belong in the technical roadmap or the user persona stories. It answers the
question: what is this really for, and what will it never become?

Read this before making architectural decisions. If a decision conflicts with
something in here, the decision needs to be justified or the philosophy needs
to be updated. Either is valid. Neither should happen silently.

---

## The Problem Is Structural, Not Technical

Every platform you use — every social network, every SaaS tool, every ad
network — was built on the same structural assumption: **your identity and
your data live on their servers.** Not because that's the only way to build
software, but because it's the most profitable way for them.

The consequences flow directly from that assumption:

- You don't own your audience. They do.
- You don't own your data. They do.
- You don't choose who sees it. They do.
- You don't get paid when it's sold. They do.
- You can be removed from the internet with no appeal.

None of this is accidental. It's the business model.

Keystone is a structural fix, not a feature. The goal is to invert the
assumption: **your identity and your data belong to your keypair, not to
any server.**

---

## What "Citizen of the Internet" Means

A citizen has rights that no single entity can revoke. A user has
permissions that can be withdrawn at any time.

Right now everyone on the internet is a user. You exist at the pleasure
of the platforms. Gmail can delete your account. Twitter can ban you.
Facebook can shadow-ban you. Apple can remove your app. Google can
deindex your site. None of these require your consent. None have
meaningful appeal.

A Keystone identity is different in one fundamental way: **no company
issued it, so no company can revoke it.** Your Ed25519 keypair was
generated on your device. It lives there. The math that proves it's yours
doesn't ask anyone's permission.

This is not a legal argument. It's a cryptographic one. The key is yours
because you have it, not because someone granted it to you.

That's what citizenship on the internet means in practice: an identity
that exists independent of any platform's continued goodwill.

---

## Data Sovereignty and the Advertising Inversion

The current advertising model operates on taken data:

```
You visit a site
→ They track you (cookies, fingerprinting, pixels, session recording)
→ They sell that profile to brokers
→ Brokers aggregate it across thousands of sources
→ Ad companies buy the merged profile
→ You never consented, you can't see it, you can't stop it
→ The value flows to the platforms, not to you
```

This works because you have no wall. The data is just taken.

Keystone builds the wall first. Your attributes — interests, purchase
history, location, behaviour — are encrypted blobs that hang off your
public key. Nobody can read them. They are yours.

Selling access becomes a choice, not a default:

```
You hold your data, encrypted to your key
→ You choose to open a "hole" — a signed consent message
→ Ad company X can read attribute Y until date Z
→ You get paid directly for that access
→ The consent has a cryptographic expiry — no renewal = no access
→ You have a receipt proving what you consented to
```

The difference is the direction of consent. Today consent is a fiction —
a legal checkbox on a dark-pattern popup that you click to make it stop.
In this model consent is a cryptographic signature with an expiry date
that you control with your private key.

When the expiry passes, access ends. Not because a company deleted
your data from their servers. Because they can't re-derive the decryption
key you didn't renew.

This is real capitalism applied to personal data. You have an asset.
You negotiate its use. You capture the value. Right now you have none
of those three things.

---

## True Capitalism, Not the Rigged Version

This needs to be said plainly: the current internet economy is not
capitalism in the sense of equal participants in a market. It's
monopoly capture masquerading as a market.

Google doesn't compete for your search attention. They own it.
Meta doesn't compete for your social graph. They captured it.
Amazon doesn't compete for your purchase history. They built a moat
around it with AWS, Prime, and FBA.

These are not the outcomes of a free market. They are the outcomes
of a structural advantage: they got there first, captured the network
effects, and built walls around them. Now every small business, every
creator, every developer operates inside their rules, paying their
tolls, at their mercy.

Keystone's purpose is not to build a better Google. It's to make
the structural advantage impossible to recreate. If your identity,
your social graph, your data, and your content addresses are
cryptographically yours — not stored on any single company's servers
— then the moat cannot be built. The next Google cannot lock you in
because there is no lock.

This is the actual precondition for equal opportunity online:
**a layer of the internet that no one company can own.**

---

## Web of Trust Without Social Credit

Communities will form on top of Keystone. People will vouch for each
other. Trust will be a meaningful concept between participants.

This is good and necessary. The concern is what it must never become.

China's social credit system is the clearest example of a trust
system going wrong. The technical failure mode is not that it uses
cryptography or scoring — it's a specific set of design choices:

- **One global score** — behaviour across all domains of life
  aggregated into a single number
- **No exit** — you live there, you're in the system
- **Opaque rules** — unclear what affects your score
- **Gatekeeping** — score gates access to things you need to live
- **Enforcement** — a single authority connects score to consequences

Every one of these failure modes is a design choice. Not an
inevitability of trust systems. And every one can be deliberately
avoided.

**Trust in Keystone must stay local and contextual, never global.**

When Alice vouches for Bob, that is a statement Alice made, verifiable
by anyone who cares about Alice's opinion. It does not increment Bob's
global score. It does not affect Bob's standing in communities where
Alice is unknown. Different communities have different trust graphs.
There is no aggregation layer.

A vouch is just a signed message:

```json
{
  "type": "vouch",
  "from": "alice_pubkey",
  "for": "bob_pubkey",
  "claims": ["known-irl", "pays-debts"],
  "expires": "2027-01-01",
  "signature": "..."
}
```

It is readable by anyone. It is verifiable by anyone. It means
whatever the reader decides it means given how much they trust Alice.
It contributes to no central score. It is issued by Alice and she
can revoke it.

**The line that must never be crossed:** vouches becoming a gating
mechanism for access to resources people depend on to participate
in society.

Keystone communities can exclude you. They cannot cancel your
train ticket. The protocol has no connection to real-world
enforcement mechanisms by design. The moment Keystone trust scores
start gating access to anything people need to survive, a weapon
has been created. Don't build the connection.

---

## Why Not Blockchain

This question comes up every time decentralisation and identity
are discussed in the same sentence. The answer is no, and here is
the precise reason.

Blockchain exists to solve one specific problem: **trustless
consensus among parties who don't trust each other about the state
of a shared ledger.** Bitcoin needs it. There's no central bank
and every participant needs to agree on who owns what without
trusting any single authority to tell them.

Keystone's problems are different:

**Auth:** does this message come from this keypair? That's
Ed25519. One line of crypto. No consensus needed. The math
is the authority.

**Data ownership:** is this data mine to grant access to?
Yes if you can sign the consent with the key that owns it.
No consensus needed.

**Vouching:** did Alice vouch for Bob? Yes if Alice's key
signed the vouch message. Verifiable by anyone. No consensus
needed.

**Communities:** who are the members of this group? The
members whose keys signed the membership list. No consensus
needed.

The only thing blockchain adds to any of these is latency,
gas fees, dependence on a network that can fork or die,
and complexity. In exchange for: nothing you don't already
have with signatures.

The Sybil problem (fake identities vouching for each other
to inflate trust) is real and blockchain's proof-of-work
does solve it — but at the cost of making identity creation
a financial barrier, which excludes people who can't afford
it. The better solution for human communities is social
verification: you can only get vouched by someone who
knows you in the real world. The chain of vouches is only
as strong as its weakest real-world link. No blockchain
needed. This is how PGP key signing worked. The failure
of PGP was UX, not cryptography.

**Relays, not consensus.** Communities need somewhere to
store and discover signed messages. Relays solve this:
simple servers that accept, store, and forward signed
messages. Nobody trusts the relay — every message is
signed, so the relay can't forge anything. It can censor
(stop relaying your messages) but not forge (put words in
your mouth). Run your relays on multiple servers, in
multiple jurisdictions. Censorship resistance through
redundancy, not through consensus.

This is the model Nostr uses. Millions of users. No
blockchain. It works.

---

## Device Permanence

The natural evolution of Keystone on the device level is a
**browser extension** — an identity wallet analogous to what
MetaMask is for Ethereum, but for identity instead of money.

The extension:
- Stores your private key outside the browser's clearable
  storage (in `chrome.storage.local`, optionally backed by
  the OS keychain)
- Injects a `window.keystone` API into every page
- Any site that wants Keystone auth calls
  `window.keystone.sign(challenge)` — the extension handles it
- You set your password once at install
- Your identity follows you to every site without re-setup

This is the missing piece for universal identity. Without it,
Keystone is a per-site plugin. With it, your keypair is
genuinely universal — one signature API, every site that
speaks the protocol.

Above the extension on the permanence hierarchy:
- **OS keychain backing** — survives browser reinstalls
- **Hardware key (YubiKey with Ed25519)** — the key never
  leaves the chip. Physical possession is the proof.
  The most permanent thing that can exist.

---

## The Operator Key Model

For a developer or agency running multiple sites on Keystone:
one keypair, recognized everywhere, with no per-site enrollment.

Each deployment has `SUPERADMIN_PUBKEY` in its environment.
The auth handler checks the incoming pubkey against this value
before hitting the device table. Match = operator access.
No registration. No enrollment token. Just the key you carry.

This scales to any number of deployments. New client spun up —
your pubkey goes into their env from day one. You sign in the
same way you sign in everywhere.

Per-site users (editors, clients) still enroll per-site.
That's correct — a client editor only needs access to their
one deployment.

---

## What Keystone Will Never Do

These are design constraints, not aspirations. They exist to
prevent the failure modes documented above.

1. **Aggregate trust into global scores.** Trust is always
   local to the community and relationship it was issued in.
   No leaderboard. No reputation number. No tier system.

2. **Gate access to necessities.** Keystone communities can
   exclude. The protocol has no mechanism to enforce that
   exclusion in the physical world or to block access to
   anything outside the protocol itself.

3. **Remove the exit.** You can always generate a new keypair.
   You can always find a different relay, a different community.
   No single entity can remove you from the protocol.

4. **Require financial participation.** Identity creation is
   free. Always. The moment generating a Keystone identity
   requires owning a token, paying a fee, or staking value,
   equal opportunity is gone.

5. **Obscure the rules.** Every vouch, every credential, every
   consent message is a signed document anyone can inspect.
   There are no hidden scoring algorithms.

---

## The Test (amended from VISION.md)

Before shipping any feature:

> Which person does this help, and how does their day get better?

And now also:

> Does this feature give any single entity — including us —
> the ability to remove someone's identity, aggregate their
> trust into a score, or gate their access to the protocol?

If yes to the second question: don't ship it.
