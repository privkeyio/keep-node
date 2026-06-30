# Security

This chapter sets out what Keep Node protects, what it does not, and the assumptions those
guarantees rest on. It is deliberately conservative: a security appliance is only as honest
as its threat model.

## Cryptography

| Component | Implementation |
|-----------|----------------|
| Volume encryption | LUKS2 (`cryptsetup`), 32-byte key on a keyslot |
| Threshold unlock | 2-of-3 Oblivious PRF over secp256k1 (RFC 9497 construction) |
| Hash-to-curve | RFC 9380 `secp256k1_XMD:SHA-256_SSWU_RO_` (via `k256`) |
| Threshold layer | Shamir split + in-exponent Lagrange combination (`vsss-rs`) |
| Key derivation | HKDF (RFC 5869) with injective domain separation |
| Threshold signing | FROST (BIP-340 Schnorr), from `keep-core` |
| Transport | Nostr, authenticated and encrypted, via `keep-frost-net` |
| Memory hygiene | `zeroize` on key material and intermediates |

The threshold unlock primitive is covered in detail in the
[Threshold Unlock](./threshold-unlock.md) chapter.

## Threat model

### What each holder holds

The unlock secret is split into a 2-of-3 quorum across three heterogeneous holders. No
holder ever sees the volume key; each holds one share and contributes only a blinded partial
evaluation. Any two of the three reconstruct the key in the exponent; any one cannot.

| Holder | What it holds | What protects it | What compromising it alone yields |
|--------|---------------|------------------|-----------------------------------|
| Box (this node) | One OPRF share, TPM-sealed under a measured-boot policy; never on disk in the clear | The TPM seal + measured boot | One share, below threshold: no key, and the box cannot self-unlock |
| Phone | One OPRF share in the phone's hardware-backed keystore; also gates approval | Mobile hardware keystore + user-present approval | One share, below threshold: no key; a wrong partial only fails the unlock |
| Replica | One OPRF share on a second node or a managed ciphertext-only replica; provides availability and recovery | The replica's own boot/attestation posture | One share, below threshold: no key |

A wrong or malicious partial from any single holder causes a failed unlock, never a key
leak: the combination is in the exponent, so an incorrect share simply does not reconstruct.

### A stolen, powered-off box

An attacker who walks off with a powered-off node gets ciphertext. The vault volume is
LUKS-encrypted; its key is not stored on the disk. The box holds at most one share of the
unlock secret, which is below the quorum threshold and is sealed to the box's TPM, bound to
a measured boot state. One share is cryptographically insufficient to derive the key, and
the box keeps no local recovery keyslot to fall back on. Stealing the box, on its own,
yields nothing usable.

### A powered-on box

A running box still cannot unlock the vault by itself. Deriving the volume key requires a
quorum, which means a second holder (the phone) has to evaluate the blinded element and a
holder has to approve. The approval is not a policy toggle that the box can flip; it is a
necessary step in the cryptography, because the box's single share is below threshold.

The honest boundary: a box that is actively compromised at the moment it unlocks
necessarily learns that volume's key, because it must, in order to mount the disk. This is
true of all full-disk encryption. The quorum protects the key at rest and gates every
unlock on a second holder; it does not protect a live, compromised, running system. Keep
Node does not claim to.

### Duress and coercion

The quorum protects against theft and remote compromise, not against an attacker who coerces
a present, cooperating user: a user forced to unlock can be forced to do so with the real
quorum. For that threat the underlying `keep-core` carries a hidden-volume primitive
(`keep_core::hidden`): a vault can hold a second storage area that is cryptographically
indistinguishable from random padding, so unlocking with a decoy credential reveals only the
decoy contents and the existence of the hidden area cannot be proven. Keep Node does not yet
expose a decoy-credential flow on top of this primitive; wiring a duress/decoy unlock into
the appliance is future work, and until it ships Keep Node makes no duress claim.

### The evaluation oracle

Because the unlock input is a fixed, low-entropy label, the holder's evaluation oracle is
the part of the system that most needs protecting. An unbounded or unauthenticated oracle
would reduce the unlock to an offline brute force of a known input. The oracle is therefore
gated on every request: group and participant membership, a replay window, a receive
policy, a binding between the requester's identity and its share index, verified
attestation, a per-requester rate limit, and a default-deny operator approval hook. The
oracle answers only when all of these pass. It fails closed.

### The relay and the network

The Nostr relay (and any networking between nodes) is untrusted. It stores and forwards
ciphertext only, never plaintext, and it holds at most one share, below the quorum
threshold. A compromised relay can drop or delay traffic, which degrades availability, but
it cannot decrypt the vault, derive the volume key, or sign. Vaultwarden is bound to
localhost and never serves plaintext HTTP on the LAN; remote access is over the encrypted
transport, which terminates to loopback.

Inter-node replication (the planned multi-node HA) is held to the same rule: nodes replicate
each other's encrypted state only, never plaintext and never an at-or-above-threshold set of
shares, so a node or its sync path can degrade availability but cannot decrypt another node's
vault. That replication is not yet implemented.

## Trust assumptions

- **Measured boot and attestation.** The box's share is released only after a measured boot
  state, and a holder only evaluates for a requester whose attestation is verified. These
  guarantees are only as strong as the underlying measured-boot and attestation
  configuration; a node guarding a real vault must configure its expected boot measurements,
  because an unconfigured peer would be treated fail-open and is therefore refused.
- **Holder devices.** The phone and replica are trusted to hold their shares and to gate
  approval. Compromise of a single holder is survivable: one share is below threshold, and a
  wrong partial only causes a failed unlock, never a key leak.
- **The libraries.** The dangerous cryptography is delegated to vetted crates (`voprf`,
  `vsss-rs`, `k256`, `hkdf`, `zeroize`). The bespoke surface is small and is reviewed
  independently.

## Fail-closed defaults

The system is built to fail toward refusing service rather than toward exposing data:

- The volume gate refuses to reformat a device that already holds data it did not create.
- It keeps no local recovery keyslot; recovery is from a replica or the quorum, never a
  secret at rest. A change in the box's boot measurements makes its own copy of the volume
  unreadable until re-provisioned from a replica, by design.
- If the volume cannot be unlocked, Vaultwarden does not start. The password manager
  hard-requires the mount.
- The operator approval hook on the evaluation oracle is default-deny.
- The rate-limiter's tracking table is hard-capped and refuses new identities rather than
  growing without bound.

## Reporting vulnerabilities

If you discover a security vulnerability, please report it privately rather than opening a
public issue. Use [GitHub Security
Advisories](https://github.com/privkeyio/keep-node/security/advisories/new), or email
security@privkey.io. Please include enough detail to reproduce the issue, and allow time
for a fix before any public disclosure.
