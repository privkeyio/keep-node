<div align="center">

# keep-node

*Self-sovereign security appliance for your passwords and secrets.*

</div>

## About

keep-node turns a small Linux box into a private security appliance. Each node runs your core security services (a [Vaultwarden](https://github.com/dani-garcia/vaultwarden) password manager, secrets, identity) and holds only a [FROST](https://eprint.iacr.org/2020/852) threshold key share, so no single device can decrypt your vault. Run two or more and they sync to each other, so if one goes down the others keep serving. Built for non-technical users: no seed phrases.

Part of the [Keep](https://github.com/privkeyio/keep) ecosystem; the node daemon, vault, and threshold signing are reused from [`keep`](https://github.com/privkeyio/keep) (`keep-web`, `keep-core`).

> **Status: MVP in progress, developed and CI-tested entirely in NixOS VMs (no hardware).** Built and validated so far: Vaultwarden + keep-web on a LUKS volume gated at boot, either by a TPM seal (default) or, opt-in, by a **threshold-OPRF quorum** reconstructed from a live keep relay + a second holder (tested end to end with the real `keep` binary); **opt-in measured boot** (Lanzaboote UKI, so the seal binds a real PCR 11); and **multi-node active/standby HA for the vault** , a shared JWT signing key, Litestream WAL streaming of the SQLite DB, attachment/Send file replication, and crash-then-promote failover, all covered by a two-node nixosTest. Still ahead: the production **mesh transport** between nodes (the HA tests ship the replica with a stand-in copy today), the **phone holder** and QR onboarding (the `keep-android` app; tests use a keep holder as its stand-in), moving the quorum to **2-of-3**, and running on **real hardware** (TPM 2.0 + secure element on an SBC).

## Features

- **Threshold custody**: the box holds one FROST share; steal it and get nothing.
- **Multi-node HA**: nodes sync, so a single failure doesn't take your vault down.
- **Seedless**: recovery via a device quorum, no 24 words to lose.
- **Open**: MIT software on commodity hardware.

## Quick Start

Requires [Nix](https://nixos.org/download) with flakes enabled.

```bash
# Run the test suite (boots a VM, no hardware needed: Vaultwarden + keep-web)
nix flake check

# Boot the VM interactively to poke at it
nix build .#checks.x86_64-linux.single-node.driverInteractive
./result/bin/nixos-test-driver --interactive
```

## Install on hardware

Build a bootable USB installer and install keep-node on a real UEFI machine.

1. Build the installer ISO (requires Nix with flakes; produces a ~1.4 GB UEFI hybrid ISO):

   ```bash
   nix build .#installer-iso
   # ISO at: result/iso/*.iso
   ```

   No Nix? Build it in an isolated container instead:

   ```bash
   docker run --rm --privileged -v "$PWD":/work -w /work nixos/nix \
     nix --extra-experimental-features 'nix-command flakes' build .#installer-iso
   ```

2. Flash it to a USB stick. This erases the stick: replace `/dev/sdX` with the real device (verify with `lsblk`).

   ```bash
   sudo dd if=result/iso/*.iso of=/dev/sdX bs=4M oflag=sync status=progress
   sync
   ```

3. Boot the target machine from the USB (UEFI; disable Secure Boot if it won't boot, the image isn't Secure-Boot-signed), then install to the internal disk:

   ```bash
   install-keepnode /dev/sda      # the target's internal disk, NOT the USB
   ```

   It auto-elevates, wipes the disk, partitions UEFI, and installs offline. Type `YES` to confirm. When it finishes, remove the USB and reboot.

4. After first boot, console autologin and SSH are available; default login is `root` / `keepnode`, change it immediately (`passwd`). Find the node's IP with `ip a`, then open the Vaultwarden web vault from the LAN at `https://<node-ip>` (self-signed cert, accept the browser warning; plain HTTP won't work because the web vault needs a secure context).

> **Insecure by design (bring-up only).** The installer image is the `keepnode-debug` profile: it enables an opt-in, test-grade `debugAccess` config (known root password, password SSH, open signups, self-signed TLS) so a fresh box is reachable over the LAN before the encrypted transport lands. For any real deployment, deploy the hardened `nixosConfigurations.keepnode` profile instead (debugAccess off, SSH off, signups default-deny), not `keepnode-debug`. `frost-gate` is off in both, so Vaultwarden data sits on the plain disk with no TPM unlock yet.

## License

[MIT](LICENSE)
