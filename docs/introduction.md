# Keep Node

*A self-sovereign security appliance for your passwords and secrets.*

Keep Node turns a small Linux box into a private security appliance. Each node runs
your core security services on an encrypted vault, and the key that decrypts that vault
is never held by any single device. To unlock, a quorum of devices has to cooperate.
The plain consequence: stealing the box gets nothing, and a powered-on box on its own
still cannot decrypt the vault.

A node bundles two services on top of that encrypted volume:

- **keep-web**, the Keep headless daemon: an encrypted key vault, a FROST threshold
  co-signer, and a NIP-46 remote-signing bunker for Nostr.
- **Vaultwarden**, a password-manager server that speaks the Bitwarden protocol, so you
  keep using stock Bitwarden clients and your normal master password.

Both run on a NixOS appliance image with reproducible builds and atomic updates. The
data they hold lives on a LUKS-encrypted volume that is unsealed at boot, before
Vaultwarden is allowed to start. If the volume cannot be unlocked, the password manager
does not run.

## The core property

The vault key is derived from a threshold quorum rather than from a single secret on the
box. The Keep ecosystem splits the most sensitive material across the box, your phone,
and an optional replica, so that no one device, including the box itself, ever holds
enough to decrypt or to sign. Recovery is a quorum of devices, not a seed phrase you can
lose.

## How this relates to Keep

Keep Node is part of the broader [Keep](https://github.com/privkeyio/keep) project. The
node daemon, the encrypted vault, the FROST threshold signing, and the Nostr transport
are reused from Keep's `keep-web` and `keep-core` crates rather than rebuilt. Keep Node
adds the appliance: the NixOS image, the threshold-gated volume, the multi-node story,
and the seedless onboarding around it.

## Where to start

- **[Architecture](./architecture.md)** explains the components and how they compose, and
  the boot flow that unseals the vault.
- **[Threshold Unlock](./threshold-unlock.md)** is the centerpiece: how a quorum derives
  the volume key with a threshold Oblivious PRF, without any party reconstructing the key.
- **[Security](./SECURITY.md)** covers the threat model, the trust assumptions, and how to
  report a vulnerability.
- **[Attribution](./attribution.md)** credits the open-source work Keep Node builds on.

The software is MIT licensed. Accuracy and restraint matter here more than marketing, so
the chapters that follow describe what the system actually does and are careful to name
the boundaries of what it protects.
