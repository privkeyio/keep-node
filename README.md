<div align="center">

# keep-node

*Self-sovereign security appliance for your passwords and secrets.*

</div>

## About

keep-node turns a small Linux box into a private security appliance. Each node runs your core security services (a [Vaultwarden](https://github.com/dani-garcia/vaultwarden) password manager, secrets, identity) and holds only a [FROST](https://eprint.iacr.org/2020/852) threshold key share, so no single device can decrypt your vault. Run two or more and they sync to each other, so if one goes down the others keep serving. Built for non-technical users: no seed phrases.

Part of the [Keep](https://github.com/privkeyio/keep) ecosystem; the node daemon, vault, and threshold signing are reused from [`keep`](https://github.com/privkeyio/keep) (`keep-web`, `keep-core`).

> **Status: early scaffold.** Today it boots Vaultwarden and the keep-web daemon in a NixOS VM, with Vaultwarden's data on a TPM-sealed LUKS volume that auto-unlocks at boot. Making that unlock a FROST quorum (instead of TPM-only), multi-node sync, and hardware support are in progress.

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
