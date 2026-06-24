# Threshold Unlock

This is the heart of Keep Node: how the encrypted vault's volume key is derived from a
quorum of devices using a threshold Oblivious PRF, without any single party ever
reconstructing the key. The construction and its protocol are implemented in the Keep
crates (`keep-core`'s `oprf` module and `keep-frost-net`'s OPRF session); this chapter
describes what that code does and is careful to mirror its own hedged language about what
it protects. Wiring this quorum unlock into the appliance boot gate, in place of the
current TPM-sealed volume key, is in progress; this chapter describes the design those
crates implement.

## The problem

Full-disk encryption protects data at rest, but the volume key has to come from somewhere.
A key sealed only to the box's TPM is local protection: it binds the key to a measured
boot state on that one machine. It does not make the key a quorum. A powered-on box that
holds its own TPM-sealed key can unlock its disk by itself, so a TPM-only seal does not, on
its own, satisfy the property that no single device can decrypt the vault.

The goal of the threshold unlock is to make the volume key depend on a quorum of separate
holders, so that:

- A stolen, powered-off box holds only one share of the secret, below threshold, and is
  cryptographically unable to derive the key.
- Every unlock requires another holder (the phone) to take part, which makes the phone's
  approval a property of the cryptography rather than a policy that could be flipped.

## The construction

The primitive is a 2-of-3 (configurable t-of-n) threshold Oblivious PRF over secp256k1.

An Oblivious PRF lets a client compute a pseudorandom function of an input under a server's
key, where the server learns neither the input nor the output, and the client learns
nothing about the key. The base construction is the 2HashDH OPRF standardized in
[RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html): the client blinds its input to a
group element, the server applies its key to that element, and the client unblinds and
finalizes to a uniform output.

RFC 9497 defines no secp256k1 ciphersuite, so Keep binds the generic prime-order-group
construction to secp256k1 by implementing the `voprf` crate's `CipherSuite` trait over
`k256::Secp256k1`. Hash-to-curve is the RFC 9380 suite
`secp256k1_XMD:SHA-256_SSWU_RO_`, provided by `k256`'s `hash2curve` feature. The suite ID
is non-standard and is pinned in the code; it feeds the RFC 9497 context string, so it can
never change once it has derived keys that protect data, because changing it changes every
derived key.

The threshold layer makes this t-of-n. The OPRF key `s` is Shamir-split across the holders
(box, phone, replica). For a client's blinded element `B`, each holder `i` returns a
**partial evaluation** `s_i * B` using only its share `s_i`. A quorum of these partials is
combined in the exponent by Lagrange interpolation (using `vsss-rs`'s in-group share
combination) into `B^s`, **without any party ever reconstructing `s`**. The combined
element is fed back into the unchanged OPRF finalize step. The only bespoke arithmetic in
the whole path is the single multiplication `s_i * B`; the Shamir split, the in-exponent
Lagrange combination, the group operations, and the blind and finalize are all done by
vetted libraries.

The correctness of this is checked directly in the code: for any 2-of-3 quorum, the
threshold combination produces exactly the same OPRF output as a single server holding the
un-split key, and the key is never reconstructed.

### Deriving the volume key

The OPRF output is already a uniform SHA-256 PRF value. It is run through HKDF (RFC 5869)
to produce the 32-byte LUKS key:

```
K_luks = HKDF(oprf_output, info = "keep-node/luks/v1" || len(volume_id) || volume_id || epoch)
```

The `info` is built injectively, length-prefixed, so two distinct `(volume_id, epoch)`
pairs can never collide into the same key. The volume id separates multiple volumes and the
epoch allows the derivation to be rotated without changing the OPRF key. The result is fed
to a LUKS2 keyslot via `cryptsetup ... --key-file - --keyfile-size 32`.

## Enrollment (provisioning)

Provisioning is the one moment the box holds the OPRF secret, and it is brief.

1. The box generates a random OPRF key `s` and uses the fixed unlock input
   `keep-node-vault-v1`.
2. The box derives `K_luks` once from `s` and that input, and uses it to LUKS-format the
   data volume.
3. The box Shamir-splits `s` into a 2-of-3 set of shares and distributes one share to each
   holder (box, phone, replica) over an authenticated, encrypted pairing channel.
4. The box zeroizes `s` and every transient copy of a share it handled. From this point no
   party holds `s`, and no party holds two or more shares.

Each holder's OPRF key share is dedicated to the unlock and is separate from any FROST
signing share, so the same secret is never reused across both Schnorr signing and OPRF
evaluation. The box's own share is sealed to its TPM, bound to a measured boot state, so
that an attacker cannot read it off a stolen disk.

The split itself is handled carefully: the returned shares are live key material, and the
caller is responsible for zeroizing each one once it is distributed. The split rejects
invalid parameters (a threshold above the share count, or a threshold below two).

## Unlock (per boot)

On each boot the box drives one unlock attempt. The box is both the OPRF client and one of
the three holders.

1. The box blinds the fixed input, producing the blinding state (kept locally until
   finalize) and a 33-byte blinded element to send to the holders.
2. The box computes its own partial evaluation locally from its TPM-sealed share.
3. The box sends an OPRF-eval request, carrying the blinded element, to the eligible
   holders over `keep-frost-net`. A session id is derived from the blinded element and the
   participant set.
4. A holder that passes every gate (below) evaluates the blinded element with its share and
   returns a 65-byte partial evaluation (a 32-byte Shamir identifier plus the 33-byte
   compressed point). The holder never sees the input or the output, only the blinded
   element.
5. Once the box has a quorum of partials (its own plus one holder's), it combines them,
   finalizes the OPRF output, and derives `K_luks`. The derived key never crosses the wire.
6. The box opens the LUKS volume with the derived key and mounts it. Intermediates are
   zeroized.

The box collects partials keyed by share index, rejecting a non-participant, a duplicate
index, or a wrong-length partial, and finalizes only when the quorum threshold is reached.
The session times out (30 seconds) if a quorum never arrives. A replayed partial (a
duplicate Shamir identifier) is rejected by the combination, so a single holder cannot
forge a quorum by answering twice.

## The eval oracle and why it defaults closed

The unlock input is a single fixed, low-entropy label. That is a deliberate design choice,
and it is also the reason the holder's evaluation oracle is the security spine of the whole
scheme. If a holder would auto-answer evaluation requests, an attacker who can reach the
oracle could obtain the partial it needs and derive the key, because there is no secret
input to guess. So a single unguarded, auto-answered evaluation can be enough to reveal the
key. The protection is to bound and gate who may obtain an evaluation.

The holder's eval handler in `keep-frost-net` applies a sequence of gates before it will
evaluate anything, and only invokes the oracle if all of them pass:

- **Group and participant checks.** The request must be for this node's group and name this
  node as a participant; a node with no OPRF share silently ignores the request.
- **Replay window.** Requests outside the configured replay window are rejected.
- **Receive policy.** The sender must be allowed to send eval requests.
- **Identity binding.** The sender's public key must match the share index it claims.
- **Attestation.** The requester's attestation must be `Verified`, not merely "attested".
  A node guarding a real vault must configure expected boot measurements (PCRs) and will
  only answer a requester whose measured boot verified. Accepting an unconfigured peer would
  be fail-open, so it is refused.
- **Rate limit.** Each requester is capped with a sliding window (the implemented default is
  eight evaluations per sixty seconds), and the tracking table is itself hard-capped and
  fails closed if it ever fills. Bounding the number of evaluations is precisely what keeps
  the fixed, low-entropy input from being brute-forced.
- **Operator approval.** Finally an approval hook is consulted. It is **default-deny**: a
  holder answers only if it has opted in with an explicit policy. The phone implements this
  as the user-facing "tap to approve" prompt. A node emits an event when an eval is
  requested so that prompt can be raised.

The oracle defaults closed at the last step on purpose. The honest reading is that the
quorum's resistance to guessing depends on this oracle being authenticated and bounded; an
unbounded or unauthenticated oracle would reduce the unlock to an offline brute force of a
known input.

## Fail-closed and recovery

The scheme is designed so that the failure mode is a failed unlock, never a key leak.

A wrong partial, whether from a misbehaving holder or a forged or corrupted message,
interpolates a different key. That yields a different OPRF output, hence a different derived
key, which LUKS rejects at the keyslot digest. The box surfaces the failure and tears the
session down rather than waiting out its timeout. It does not, and cannot, learn anything
about the real key from a wrong partial. This property is checked directly in the code: a
quorum that mixes in a share from a different key derives a different LUKS key.

Malformed inputs are rejected rather than trusted: off-curve points, identity elements,
non-canonical or zero Shamir identifiers, and wrong-length partials all return errors at
the trust boundary.

Per-partial DLEQ verifiability (a zero-knowledge proof that a holder used its committed
share) is a planned follow-on, not a security gate for the core guarantee. Because a wrong
partial already yields a wrong key that LUKS rejects, a misbehaving holder causes a failed
unlock, never a silent corruption or a leak. DLEQ would upgrade that fail-safe into a
diagnosable, denial-of-service-resistant one; it would not change what an attacker can
learn.

Recovery follows from the same 2-of-3 structure and needs no local recovery secret. A blank
replacement box is just an OPRF client with no share of its own; it blinds the input,
requests partials from any two surviving holders (for example phone plus replica),
combines, derives `K_luks`, and opens a replicated copy of the volume. There is no seed
phrase, and no share ever leaves a holder during recovery.

## The boundary, stated plainly

Threshold unlock protects the volume key **at rest** and **gates every unlock on a second
holder**. It does not protect a live, actively compromised running box. A box that is
compromised at unlock time necessarily learns that volume's key, because it has to, in
order to mount the disk. That is true of all full-disk encryption, and Keep Node does not
claim otherwise. What the quorum adds is that an offline box, a powered-on box without its
quorum, and a stolen disk all come up empty.
