# Security

This chapter sets out what Keep Node protects, what it does not, and the assumptions those
guarantees rest on. It is deliberately conservative: a security appliance is only as honest
as its threat model.

## Current status

Keep Node is an early scaffold, so this chapter describes the **target** design alongside
what ships **today**. Read every guarantee below in that light:

- **Today (default):** the vault is a TPM-sealed LUKS volume that **auto-unlocks at boot**,
  with the key sealed to **PCR 7 only** (Secure Boot policy, not a real measured-boot
  policy). This is full-disk encryption at rest: a powered-on box can unlock itself, there is
  **no second holder**, and there is **no phone**. An opt-in `oprf` gate mode wires the
  threshold-OPRF quorum unlock; the crates and the unlock path exist and are tested, but
  it is not the default, and it is only a fully verified gate once measured boot is enabled
  (available as the opt-in `keepNode.measuredBoot` module, off by default).
- **Target (in progress):** the 2-of-3 OPRF quorum described below, with a **phone holder
  that does not exist yet** and the box's share sealed under a **real measured-boot PCR
  policy** (the Lanzaboote work, shipped as the opt-in `keepNode.measuredBoot` module but not
  the default appliance). The "no single box can decrypt" property
  holds only once those are in place.

Sections below describe the target unless a "today" note says otherwise.

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

**Today:** none of this quorum is active by default. The box holds a TPM-sealed LUKS key
directly (PCR 7), there is no phone holder, and the replica quorum is not yet wired. The
table describes the target that the `oprf` gate mode and the holder devices are being built toward.

### A stolen, powered-off box

An attacker who walks off with a powered-off node gets ciphertext. The vault volume is
LUKS-encrypted and its key is not stored on the disk: today the key is sealed to the box's
TPM (PCR 7), which will not release it on a different machine or a changed boot state, and in
the target the box holds only one share of the unlock secret, below the quorum threshold and
cryptographically insufficient to derive the key. Either way the box keeps no local recovery
keyslot to fall back on (unless the opt-in recovery keyslot is enabled). Stealing the box,
powered off, yields nothing usable.

### A powered-on box

This is where today and the target differ most. **Today, with the default TPM-only seal, a
powered-on box does unlock its own vault**: the TPM releases the PCR-7-bound key at boot
with no second party. That is exactly the limitation the quorum exists to remove. In the
**target**, a running box still cannot unlock by itself: deriving the volume key requires a
quorum, so a second holder (the phone) has to evaluate the blinded element and approve. That
approval is not a policy toggle the box can flip; it is a necessary step in the cryptography,
because the box's single share is below threshold. The opt-in `oprf` gate mode is the first
step toward this, but the "a powered-on box cannot self-decrypt" property holds only once the
phone holder and a real measured-boot policy are both in place.

The honest boundary: a box that is actively compromised at the moment it unlocks
necessarily learns that volume's key, because it must, in order to mount the disk. This is
true of all full-disk encryption. The quorum protects the key at rest and gates every
unlock on a second holder; it does not protect a live, compromised, running system. Keep
Node does not claim to.

### A stolen operator laptop

Admin access is key-only SSH as `keepadmin`, reachable only over the mesh. With a software key, that
key is a **file**: an attacker who takes the laptop, or lands malware on it, inherits full node admin
(including passwordless sudo), silently and replayably, for as long as the key exists.

`keepNode.security.yubikey` narrows that. With a FIDO2 credential (`ed25519-sk` / `ecdsa-sk`) the
private key lives in the token's secure element and cannot be extracted or copied, and
`verify-required` makes every single authentication need a PIN *and* a physical touch. Possession of
the laptop stops being sufficient; remote malware cannot authenticate without the operator physically
present at the token. `requireHardwareKey = true` enforces this at sshd (`PubkeyAcceptedAlgorithms`
restricted to `sk-` algorithms), so a software key is refused by the daemon rather than merely absent
from a file.

The boundary: this protects the *authentication*, not a session already established. An attacker who
compromises the laptop while the operator is logged in can act inside that live session; the touch
requirement bounds the damage to the moments the operator is present, and the credential cannot be
stolen for later use. It is also strictly node access , it does not gate the vault, whose protection is
the FROST quorum above. Losing every token costs SSH (physical console is the break-glass), never the
vault.

### Duress and coercion

The quorum protects against theft and remote compromise. It does not, on its own, protect
against an attacker who coerces a present, cooperating user into unlocking with the *real*
credential: that user can be forced to drive the real quorum, and Keep Node does not claim to
stop it.

For that threat Keep Node ships an opt-in **coercion response**. A holder provisions a duress
credential, chosen distinct from the real vault password. Entering the duress credential at
`serve` fails closed: the vault is never unlocked and the holder's OPRF share is never loaded,
so the box drops below the quorum threshold and no key is reconstructed, and the holder emits a
signed **duress beacon** to the rest of the group. Holders that have pinned that beacon key
verify it and **freeze**: they refuse co-signing and OPRF evaluations, so the whole group fails
closed rather than only the coerced node. The freeze is sticky across reboot, so a coerced
holder cannot be quietly restarted back into service. The in-band way to lift it is a **delayed,
cancelable operator clear**, so an attacker who compels a "clear" still faces a waiting period in
which a legitimate operator can abort it. The persisted freeze marker itself rests on filesystem
permissions: it lives in a root-owned, non-writable directory, and that permission boundary, not
the delay, is what stops an attacker from simply deleting the marker to resume service. This is a
non-destructive alert-and-freeze: it wipes nothing and it is not a decoy.

The beacon's *contents* are metadata-private on the wire. It is a NIP-59 gift wrap, an ordinary
`kind:1059` event authored by an ephemeral key, so an untrusted relay cannot read its payload and
cannot recover the beacon key, the group, or a duress label from it. What the encryption does not
hide is the *shape* of the traffic, and the honest limits are stated plainly below because this is
security-first and not a marketing claim:

- **Traffic shape, not content, still leaks.** A relay that sees Nostr metadata can observe
  that `kind:1059` traffic is happening, its size, and its re-broadcast cadence, even though the
  content stays encrypted. Shaping that traffic to be indistinguishable from cover traffic is
  tracked future work. Carrying the OPRF and duress coordination over the on-box `nvpn` mesh
  (WireGuard) already hides it from any *network* observer, leaving only the relay host.
- **Availability is not guaranteed; failing closed is.** An *active* relay that drops or delays
  the beacon can keep other holders from freezing. This is the same "a compromised relay
  degrades availability" caveat that applies to all relay traffic here. The beacon re-broadcasts,
  and a frozen quorum is the safe state, but delivery against a censoring relay is not promised.
- **The beacon pin is a shared secret of modest strength.** Every holder must hold the pin to
  act on it, and the beacon key derives from a possibly low-entropy duress credential, hardened
  with Argon2id but not unbreakable. A leaked pin lets an attacker grind the credential offline
  and forge a freeze: a denial of service on availability, never a path to the key. Hardening
  this beyond a grindable key is tracked work.
- **It does not defend a user coerced into the real unlock.** Duress is something the user opts
  into by entering the duress credential; it does nothing against a coercer who already knows the
  real credential and watches the user use it.

Separately, for concealing *that a second vault exists at all*, the underlying `keep-core`
carries a hidden-volume primitive (`keep_core::hidden`): a vault can hold a second storage area
cryptographically indistinguishable from random padding, so unlocking with a decoy credential
reveals only the decoy contents and the hidden area's existence cannot be proven. Keep Node does
not yet expose a decoy-credential *unlock* flow on top of this primitive; that remains future
work and is distinct from the duress-beacon response above.

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

Because the box reconstructs its volume key by parsing responses from that untrusted relay,
that parser is a semi-trusted-input attack surface. The gate does not run it inline in the
privileged unit that drives cryptsetup and the mount: the every-boot `keep oprf-unlock` runs
in a tightly-confined transient scope, as a dedicated unprivileged user with an empty
capability set, no-new-privileges, a `@system-service` syscall filter, `MemoryDenyWriteExecute`,
and no access to the PID1/D-Bus control sockets. A memory-safety or logic bug handling a
malicious relay response therefore cannot escalate to root or read the box's other secrets
(it reaches only its own FROST-share database, the TPM device, and the relay socket); the
reconstructed 32-byte key returns over a pipe to the privileged unit that opens the volume.

Inter-node replication (the multi-node HA) is held to the same rule: nodes replicate each other's
encrypted application state only, never plaintext and never an at-or-above-threshold set of shares,
so a node or its sync path can degrade availability but cannot decrypt another node's vault. It is
implemented and runs over the `nvpn` encrypted mesh, which authenticates peers by their Nostr
identity (npub roster) and encrypts every hop (WireGuard); the standby's replica receiver is exposed
only on the mesh interface, so nothing on the LAN or the WireGuard underlay can reach it. A promoted
standby that *serves* the vault necessarily decrypts it and is therefore a fully trusted holder (a
warm standby), exactly as the cold-vs-warm discussion in [Multi-node sync](./multi-node-sync.md)
sets out; replication itself moves only ciphertext.

## Trust assumptions

- **Measured boot and attestation.** In the target, the box's key material is released only
  in the expected boot state, and a holder only evaluates for a requester whose attestation
  is verified. Today the seal binds **PCR 7 only** (Secure Boot policy), which is weak: a real
  measured-boot policy that also covers the kernel/initrd/UKI (PCR 11, the Lanzaboote work)
  is not the default; enable it with the opt-in `keepNode.measuredBoot` module. The attestation verifier itself does enforce a full PCR set, a fresh
  nonce, and a pinned key; but these guarantees are only as strong as the boot stack that
  populates those PCRs, and a node guarding a real vault must configure its expected
  measurements, since an unconfigured peer is treated fail-open and is therefore refused.
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
