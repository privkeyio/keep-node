# Architecture

Keep Node is a NixOS appliance that composes a small set of services on top of a
threshold-gated encrypted volume. This chapter describes those components, the roles the
devices play, and the boot flow that brings everything up in the right order.

## The appliance

The OS base is NixOS, with reproducible builds, atomic updates, and rollback. The
appliance is assembled from a few NixOS modules under `nixos/`, wired together by
`keep-node.nix`:

- `vaultwarden.nix`, the password-manager service.
- `keep-web.nix`, the Keep headless daemon.
- `frost-gate.nix`, the encrypted-volume gate that unseals the vault.

The whole image boots and is verified in a NixOS VM test with no hardware required, which
is also the canonical way to try it (`nix flake check`).

## Components

```
                          Keep Node (NixOS appliance)
  +-------------------------------------------------------------------+
  |                                                                   |
  |   keep-web daemon            Vaultwarden                          |
  |   (127.0.0.1:8080)           (127.0.0.1:8222)                     |
  |   - encrypted vault          - Bitwarden-protocol server          |
  |   - FROST co-signer          - signups disabled                   |
  |   - NIP-46 bunker            - data dir on the gated volume        |
  |        |                            |                             |
  |        |                            | (starts only once unsealed) |
  |        v                            v                             |
  |   +----------------------------------------------------------+    |
  |   |  frost-gate: LUKS-encrypted vault volume                 |    |
  |   |  unsealed at boot, mounted at the Vaultwarden data dir   |    |
  |   +----------------------------------------------------------+    |
  |        ^                                                          |
  |        | volume key derived from a quorum                        |
  |   +----------------------------------------------------------+    |
  |   |  keep-frost-net: FROST / OPRF networking over Nostr      |    |
  |   +----------------------------------------------------------+    |
  +--------|----------------------------------------------------------+
           |  encrypted, authenticated Nostr messages
           v
     bundled relay (wisp)  <----->   phone holder        replica holder
     (untrusted; sees only          (key share)          (key share)
      ciphertext)
```

### keep-web

`keep-web` is the Keep headless daemon, built from the `keep-web` crate in
[privkeyio/keep](https://github.com/privkeyio/keep). It provides the encrypted key vault,
a FROST threshold co-signer, a NIP-46 remote-signing bunker for Nostr, and an
authenticated admin API. It listens on loopback by default (`127.0.0.1:8080`); the admin
API and the bunker are not exposed off-box. Reach them over the encrypted transport.

### Vaultwarden

Vaultwarden is run unmodified as a service. It is bound to localhost only
(`ROCKET_ADDRESS = 127.0.0.1`) and self-registration is disabled by default
(`SIGNUPS_ALLOWED = false`), so the node is not an open signup endpoint and never serves
plaintext HTTP on the LAN. No firewall port is opened for it; access is over the encrypted
transport, which terminates to localhost.

Vaultwarden is zero-knowledge end to end: the server only ever holds the encrypted user
key plus an auth hash, so it cannot decrypt a user's vault. Keep Node therefore does not
modify Vaultwarden or its clients. The threshold guarantee is delivered one layer down, at
the data-at-rest and service-availability layer, by putting Vaultwarden's entire state
directory on the gated volume.

### frost-gate

The frost-gate is the encrypted LUKS volume that holds Vaultwarden's data directory (and
Keep state). It is a `oneshot` systemd service, `keep-node-frost-gate`, that runs before
the volume is mounted. On first boot it provisions the volume (LUKS format, key enrollment,
and `mkfs`); on every later boot it unlocks the volume and mounts it at the data directory.

The gate is deliberately fail-closed. It refuses to reformat a device that already holds
data it did not create, it keeps no local recovery keyslot, and if the volume cannot be
unlocked it stays down rather than serving without the data. The current appliance image
seals the volume key to the box's TPM, released by measured boot. Deriving that key from a
device quorum instead, so that a powered-on box alone cannot release it, is the subject of
the [Threshold Unlock](./threshold-unlock.md) chapter; the unlock primitive and its
networking session are implemented in the Keep crates, and wiring the quorum into the
appliance gate is in progress.

### keep-frost-net

`keep-frost-net` is the networking layer that carries FROST signing and the threshold-OPRF
unlock between devices. It transports messages over Nostr, with per-peer authentication,
attestation, and replay protection. The unlock uses a dedicated OPRF-evaluation session,
distinct from the signing sessions, described in the next chapter.

### The relay (wisp)

Nostr coordination (FROST, the bunker, the unlock session, peer discovery) needs a relay.
The design bundles `wisp`, a lightweight Nostr relay, so a deployment does not depend on
third-party public relays. The relay is untrusted infrastructure: it stores and forwards
ciphertext only, never plaintext, and holds at most one key share, below the quorum
threshold, so a compromised relay still cannot decrypt or sign.

## Roles: box, phone, replica

Key custody is split across three roles in a 2-of-3 quorum:

- **Box**: the appliance itself. It holds one key share and is also the initiator of an
  unlock.
- **Phone**: a second holder. Because the box's share alone is below threshold, the phone
  has to take part in every unlock; the approval prompt on the phone is a cryptographic
  necessity, not just a policy check.
- **Replica**: an optional third holder (another node, an air-gapped signer, or a managed
  ciphertext-only replica). It provides availability and recovery without ever holding a
  full key.

No single device, including the box, ever holds enough to decrypt the vault or to sign.
Running two or more nodes that replicate each other's encrypted state is planned, so that a
single node failing does not take the vault down; replicas only ever exchange ciphertext.

## Boot flow

The ordering is what makes the guarantee hold: nothing that needs the vault starts before
the vault is unsealed.

1. The appliance boots into NixOS.
2. `keep-node-frost-gate.service` runs. On first boot it provisions the LUKS volume; on
   later boots it unlocks it.
3. The gate mounts the decrypted volume at Vaultwarden's data directory.
4. `vaultwarden.service` is ordered `After=` and `requires=` the gate, so it starts only
   once the volume is unsealed and mounted. If the gate fails, Vaultwarden does not start.

Because Vaultwarden hard-requires the mount, a node that cannot reach its quorum (or, in
the current image, whose TPM refuses to release the key) simply does not bring the password
manager up. That is the intended behavior.
