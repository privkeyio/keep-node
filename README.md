<div align="center">

# keep-node

*Self-sovereign security appliance for your passwords and secrets.*

</div>

## About

keep-node turns a small Linux box into a private security appliance. Each node runs your core security services (a [Vaultwarden](https://github.com/dani-garcia/vaultwarden) password manager, secrets, identity) and holds only a [FROST](https://eprint.iacr.org/2020/852) threshold key share, so no single device can decrypt your vault. Run two or more and they sync to each other, so if one goes down the others keep serving. Built for non-technical users: no seed phrases.

Part of the [Keep](https://github.com/privkeyio/keep) ecosystem; the node daemon, vault, and threshold signing are reused from [`keep`](https://github.com/privkeyio/keep) (`keep-web`, `keep-core`).

> **Status: MVP in progress, developed and CI-tested entirely in NixOS VMs (no hardware).** Built and validated so far: Vaultwarden + keep-web on a LUKS volume gated at boot, either by a TPM seal (default) or, opt-in, by a **threshold-OPRF quorum** reconstructed over privkey's own **`wisp`** relay + a second holder (tested end to end with the real `keep` binary, including with NIP-42 relay auth required); **opt-in measured boot** (Lanzaboote UKI, so the seal binds a real PCR 11); and **multi-node active/standby HA for the vault**, running over a real **`nvpn` encrypted mesh** between nodes (nostr-vpn, boringtun userspace WireGuard, peer-authenticated) , a shared JWT signing key, Litestream WAL streaming of the SQLite DB, attachment/Send file replication, a replication-lag health signal, and crash-then-promote failover, all covered by two-node nixosTests with no relay. Still ahead: the **phone holder** and QR onboarding (the `keep-android` app; tests use a keep holder as its stand-in), moving the quorum to **2-of-3**, internet **NAT traversal** for the mesh (nvpn's Nostr discovery + the bundled `wisp` relay), and running on **real hardware** (TPM 2.0 + secure element on an SBC).

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

Build a bootable USB installer and install keep-node on a real UEFI machine. For a full tier-by-tier
runbook (BIOS/TPM/Secure-Boot settings, the encrypted-volume and measured-boot setup, and multi-node
HA), see [Hardware bring-up](docs/hardware.md).

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
   install-keepnode /dev/sda --ssh-key "ssh-ed25519 AAAA... you@host"   # /dev/sda is the target's internal disk, NOT the USB
   ```

   It auto-elevates, wipes the disk, partitions UEFI, installs offline, and enrolls your SSH public key. Type `YES` to confirm. When it finishes, remove the USB and reboot. `--ssh-key` is required (the image has no password, so your key is how you reach the node) and accepts the public key inline as shown, or a file path. The installer's live session is not your laptop, so `~/.ssh/id_ed25519.pub` won't exist there unless you put it there first (paste the key inline, `scp` your `.pub` in, or bring it on a second USB).

4. After first boot, reach the node over **key-only SSH** from a machine on the same LAN (there is no password login):

   ```bash
   ssh keepadmin@<node-ip>      # find <node-ip> from your DHCP leases or the node's console
   ```

   To open the Vaultwarden web vault before the mesh is set up, tunnel it over that SSH session (it binds localhost only): `ssh -L 8222:localhost:8222 keepadmin@<node-ip>`, then browse `http://localhost:8222` (localhost is a secure context, so the web vault loads). Then onboard the node onto the encrypted mesh and redeploy with `keepNode.adminAccess.lanBringup = false` for the mesh-only posture.

> **Hardened by default, reachable by your key.** The installer image is the hardened profile: no known password, key-only SSH (the `keepadmin` account, your enrolled key), `debugAccess` off, Vaultwarden bound to localhost, signups default-deny. During bring-up SSH is reachable on the LAN (`keepNode.adminAccess.lanBringup`) because a fresh node has no mesh yet; once it joins the mesh you redeploy mesh-only. See [Deployment](docs/deployment.md) for the declarative multi-node + admin-access how-to. The legacy `keepnode-debug` profile (known root password, password SSH, open signups) still exists as an explicit opt-in for keyless evaluation, but is never the installed default. `frost-gate` is off, so Vaultwarden data sits on the plain disk with no TPM unlock yet.

### Console status display (optional)

A hardened node boots to a login prompt where every account is password-locked, so an operator standing
in front of the box learns nothing about why the vault didn't unlock or why the mesh didn't form. The
status display paints a read-only screen on a virtual terminal instead: node label, vault and gate
state, service health, anti-lockout, and (opt-in) mesh facts. It is **off by default**; enable it with:

```nix
keepNode.statusDisplay.enable = true;   # optional: tty = 2, nodeLabel = "vault-rack-3"
```

It is a pane of glass, not a console. It accepts **no input** (the renderer runs unprivileged with
`StandardInput=null`, so it holds no descriptor on the keyboard), reaches no shell, and grants nothing
that physical presence didn't already grant. The mesh address is a separate opt-in
(`showMeshAddress`) because it is network topology shown to whoever is standing
there. Operator detail in [Hardware bring-up](docs/hardware.md#console-status-display-optional);
threat model in [Security](docs/SECURITY.md).

## License

[MIT](LICENSE)
