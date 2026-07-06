# Hardware bring-up

A practical runbook for standing keep-node up on a real machine, tier by tier. Written against an
**HP EliteDesk 800 G3 DM** (Intel i5-7500, TPM 2.0, HP business UEFI), but the steps generalize to any
x86_64 UEFI mini-PC with a TPM 2.0. The build is **x86_64 only** , an ARM SBC will not work.

Each tier is independent and additive; you can stop at any of them. Do them in order , later tiers
assume the earlier ones work.

| Tier | Proves | Needs |
|------|--------|-------|
| 0. Appliance + mesh + SSH | Boots, installs, reachable over key-only SSH; mesh forms | The box (no TPM needed) |
| 1. TPM seal (`frostGate` tpm) | Vault volume auto-unlocks from this box's TPM | TPM 2.0 on; a vault volume device |
| 2. Measured boot | Seal binds real kernel/initrd (PCR 11), not just Secure Boot policy | Secure Boot custom keys (`sbctl`) |
| 3. OPRF quorum | 2-of-3 threshold unlock (box + holders) | A second holder + relay |
| 4. Multi-node HA | Active/standby replication + failover | A second box |

## Phase 0 , BIOS / firmware (per box)

Enter setup (**F10** on the EliteDesk at power-on) and set:

- **TPM**: Security → TPM Device = **Available**, TPM State = **Enabled**. (Tier 1+.)
- **Boot mode**: **UEFI** (not Legacy/CSM). Required.
- **Boot order**: put USB ahead of the internal disk for the install, or use the one-time boot menu
  (**F9**).
- **Secure Boot**: leave **off for now**. You enable it in Tier 2 after enrolling your own keys ,
  turning it on first with only Microsoft's keys blocks the unsigned installer.
- Note the internal disk name later with `lsblk` , on this box it is typically `/dev/sda` (SATA SSD)
  or `/dev/nvme0n1` (M.2). For Tier 1 you want a **second** disk or partition for the vault volume; the
  EliteDesk has a free M.2 slot , a small NVMe there is the clean option.

## Phase 1 (Tier 0) , install the hardened appliance

On your workstation, build and flash the installer, then install on the box:

```bash
nix build .#installer-iso                    # ISO at result/iso/*.iso
sudo dd if=result/iso/*.iso of=/dev/sdX bs=4M oflag=sync status=progress   # your USB stick
```

Boot the box from USB, then (the image has **no password** , your key is how you get in):

```bash
install-keepnode /dev/sda --ssh-key "ssh-ed25519 AAAA... you@laptop"   # your real disk + pubkey
```

It wipes the disk, installs the hardened profile offline, and enrolls your key. Reboot, remove the USB,
and from your laptop on the same LAN:

```bash
ssh keepadmin@<node-ip>          # <node-ip> from your DHCP leases or the box's console
```

That's a hardened node on real metal: key-only SSH, no known password, signups default-deny. To reach
the Vaultwarden web vault before the mesh exists, tunnel it: `ssh -L 8222:localhost:8222
keepadmin@<node-ip>`, then open `http://localhost:8222`.

## Phase 2 , mesh onboarding (declarative)

From here you leave the stock image and deploy **your own config** (a flake that imports keep-node's
modules and sets your roster + keys). See [Deployment](./deployment.md) for the full `keepNode.mesh` +
`keepNode.adminAccess` how-to; the short version:

1. Generate an nvpn identity per participant (each box **and** your laptop) and record each npub.
2. Author each box's `keepNode.mesh` (networkId, selfEndpoint = its LAN ip:port, peers = the others'
   npub+endpoint, identityDir) and `keepNode.adminAccess.authorizedKeys`.
3. Deploy your config to each box , either `nixos-rebuild switch --flake .#<host> --target-host
   keepadmin@<node-ip> --use-remote-sudo`, or a tool like deploy-rs/colmena.

The mesh forms at boot; your laptop (a mesh peer) then reaches each node at its `10.44.x.y` mesh IP.
Once joined, set `keepNode.adminAccess.lanBringup = false` and redeploy for the mesh-only posture.

## Phase 3 (Tier 1) , TPM-sealed vault volume

Add a dedicated vault volume (the second disk/partition from Phase 0) and turn on the FROST gate in
**tpm** mode. In your config:

```nix
keepNode.frostGate = {
  enable = true;
  mode = "tpm";                                        # LUKS key sealed to this box's TPM (PCR 7)
  volumeDevice = "/dev/disk/by-id/nvme-...";           # STABLE path, never /dev/sdb (see below)
  recoveryKeyFile = "/root/keep-vault-recovery.key";   # opt-in escape hatch, see note
};
```

- **Use a stable `/dev/disk/by-id/...` path**, not `/dev/sda`/`/dev/sdb` , first-boot provisioning
  formats this device, and a kernel name can re-point at the wrong disk across reboots. Find it with
  `ls -l /dev/disk/by-id/`.
- First boot provisions + formats the volume, seals the LUKS key to the TPM, and mounts it at
  `/var/lib/vaultwarden`. Subsequent boots auto-unlock unattended.
- **`recoveryKeyFile`** enrolls an extra recovery keyslot and writes the key to that path , move it
  **offline and delete it**. It is the escape hatch if PCR 7 changes (a firmware/Secure-Boot/board
  change) before you have a replica to recover from. It deliberately weakens "steal the box, get
  nothing," so drop it once you have a second node (Tier 4).

## Phase 4 (Tier 2) , measured boot (bind the seal to the real boot image)

PCR 7 alone only covers Secure Boot *policy*. Measured boot (Lanzaboote UKI → PCR 11) binds the seal to
the actual kernel/initrd/cmdline, so a tampered boot image fails closed. This is a bigger change (it
replaces the boot stack) and needs your **own Secure Boot keys**.

1. On the box, create the Secure Boot PKI: `sbctl create-keys` (writes `/var/lib/sbctl`).
2. Enroll your keys into firmware: `sbctl enroll-keys` (with the box in Secure Boot **Setup Mode** ,
   set in BIOS: Security → Secure Boot → clear/erase keys, which drops to Setup Mode). Optionally keep
   Microsoft's keys with `sbctl enroll-keys -m` if any option ROM needs them.
3. In your config, import Lanzaboote + the measured-boot module and bind the seal to PCR 11:

   ```nix
   imports = [ inputs.lanzaboote.nixosModules.lanzaboote ./nixos/measured-boot.nix ];
   keepNode.measuredBoot.enable = true;            # pkiBundle defaults to /var/lib/sbctl
   keepNode.frostGate.sealPcrs = [ 7 11 ];         # bind the TPM seal to the measured UKI
   ```

4. Deploy, then enable **Secure Boot** in BIOS. Verify with `sbctl verify` and `bootctl status`.

Order matters: enroll keys and switch to the Lanzaboote UKI **before** adding `11` to `sealPcrs`, or the
seal binds a zero/garbage PCR 11 and the next boot fails closed. The `recoveryKeyFile` from Tier 1 is
your way back in if that happens.

## Phase 5 (Tiers 3-4) , OPRF quorum + HA

- **OPRF (`mode = "oprf"`)** reconstructs the LUKS key from a 2-of-3 threshold at boot (this box + two
  holders). It is only a meaningful *threshold* gate once measured boot (Tier 2) is on AND the holders
  authenticate + gate requests , until then it is no stronger than `tpm` (see the `mode` option's
  security note). The OPRF crypto path is proven in the `oprf-unlock` / `oprf-unlock-2of3` tests.
- **Multi-node HA** wires `keepNode.vaultReplication` (role active/standby, shared JWT key, Litestream
  WAL streaming, file replication) over the mesh between two boxes. See
  [Multi-node sync](./multi-node-sync.md).

## Gotchas

- **x86_64 only** , no ARM SBC.
- **TPM must be enabled in BIOS** before Tier 1, or provisioning fails.
- **Never point `volumeDevice` at a kernel name** (`/dev/sdb`) , use `/dev/disk/by-id/...`.
- **Enroll Secure Boot keys before Secure Boot enforcement** , enabling it with only Microsoft's keys
  blocks the unsigned installer/UKI.
- **Keep the Tier 1 recovery key** until you have a second node; a PCR change otherwise locks you out.
