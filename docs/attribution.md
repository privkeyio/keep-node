# Attribution

Keep Node is assembled from existing open-source work as much as possible, adding only the
glue that is genuinely new. This chapter credits the projects it builds on. Licenses are
noted where they bear on how a component is used; copyleft services are run as separate
processes rather than linked into the MIT codebase.

## Services

- **[Vaultwarden](https://github.com/dani-garcia/vaultwarden)** (AGPL-3.0): a lightweight
  server that speaks the Bitwarden protocol, used as the password manager. It is run
  unmodified as a separate service, not linked into Keep Node, so its copyleft license is
  respected.

## The Keep ecosystem

- **[Keep](https://github.com/privkeyio/keep)** (MIT): the project Keep Node is part of.
  `keep-web` (the headless daemon, FROST co-signer, and NIP-46 bunker), `keep-core` (the
  encrypted vault, FROST signing, and the threshold-OPRF unlock primitive), and
  `keep-frost-net` (the Nostr-transported FROST and OPRF networking) are reused directly.
- **FROST and the FROSTR/Bifrost lineage**: Keep's threshold signing is
  [FROST](https://eprint.iacr.org/2020/852) (Flexible Round-Optimized Schnorr Threshold
  signatures) with BIP-340 Schnorr, and its Nostr-transported threshold protocol follows the
  FROSTR/Bifrost lineage of FROST key management for Nostr.

## Platform

- **[NixOS and nixpkgs](https://nixos.org)** (MIT): the appliance OS base, giving
  reproducible builds, atomic updates, and rollback.
- **[systemd](https://systemd.io)** (LGPL-2.1+): used as a service, providing `cryptsetup`
  and `cryptenroll` for the LUKS volume and TPM enrollment, and credential sealing for the
  box's key share.

## Rust cryptography crates

The dangerous parts of the cryptography are delegated to vetted libraries; the bespoke
surface is intentionally small.

- **[voprf](https://github.com/facebook/voprf)** (MIT): the RFC 9497 OPRF/VOPRF reference
  implementation. Keep binds a secp256k1 ciphersuite to it without an upstream patch.
- **[vsss-rs](https://github.com/mikelodder7/vsss-rs)** (Apache-2.0 / MIT): Verifiable
  Secret Sharing Schemes, used for the Shamir key split and the in-exponent Lagrange
  combination of partial evaluations.
- **[k256 / RustCrypto](https://github.com/RustCrypto/elliptic-curves)** (Apache-2.0 / MIT):
  secp256k1 group arithmetic and the RFC 9380 `secp256k1_XMD:SHA-256_SSWU_RO_`
  hash-to-curve (the `hash2curve` feature).
- **[hkdf](https://github.com/RustCrypto/KDFs)** (Apache-2.0 / MIT): the RFC 5869 HKDF used
  to derive the 32-byte LUKS key from the OPRF output.
- **[zeroize](https://github.com/RustCrypto/utils)** (Apache-2.0 / MIT): clearing key
  material and intermediates from memory.

## Standards

- **RFC 9497**: Oblivious Pseudorandom Functions (OPRFs) using prime-order groups.
- **RFC 9380**: Hashing to elliptic curves.
- **RFC 5869**: HMAC-based key derivation (HKDF).
- **BIP-340**: Schnorr signatures for secp256k1.

The threshold OPRF construction draws on the published research on threshold and oblivious
PRFs (notably TOPPSS, IACR ePrint 2017/363) for making the OPRF key t-of-n without any party
reconstructing it.
