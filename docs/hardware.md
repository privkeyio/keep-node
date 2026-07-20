# Hardware bring-up

A practical runbook for standing keep-node up on a real machine, tier by tier. Written against an
**HP EliteDesk 800 G3 DM** (Intel i5-7500, TPM 2.0, HP business UEFI), but the steps generalize to any
x86_64 UEFI mini-PC with a TPM 2.0. The build is **x86_64 only** , an ARM SBC will not work.

Each tier is independent and additive; you can stop at any of them. Do them in order , later tiers
assume the earlier ones work. The phases below group the work and do not map one-to-one to tiers: Phase
0 is BIOS prep (no tier), Tier 0 spans Phases 1-2, and Tiers 1-4 are Phases 3-5.

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

### Console status display (optional)

Everything above assumes you can already reach the box over SSH. When you can't, the only thing on the
monitor is a login prompt for accounts that all have locked passwords. `keepNode.statusDisplay` replaces
that with a read-only status screen, which is most useful exactly here in Tier 0 , before the mesh
exists and before SSH is proven.

```nix
keepNode.statusDisplay = {
  enable = true;          # off by default
  tty = 1;                # which VT it owns (1-12); 1 is what a plugged-in monitor shows on boot
  nodeLabel = "vault-rack-3";   # defaults to config.networking.hostName
  # showMeshAddress = true;     # both default false, see below
  # showMeshPeers = true;
};
```

It is two units: `keep-node-status-collect` (root, on a timer, writes one JSON snapshot to
`/run/keep-node-status/status.json`) and `keep-node-status-render` (unprivileged, reads that file and
paints the VT). Neither binary is on your `$PATH`; to debug the screen from an SSH session use
`systemctl status keep-node-status-render`, `journalctl -u keep-node-status-collect`, and
`cat /run/keep-node-status/status.json`.

**The rows.** `VAULT` is the vault volume (`unlocked` / `locked` / `wrong-device`, the last meaning the
data dir is mounted from something that is not the gate's mapper). `GATE`, `VAULTWARDEN`, `MESH`,
`WISP` and `ANTI-LOCKOUT` are the systemd states of the corresponding units. `MESH LINK` appears only
when `keepNode.mesh.enable` is on, and reads the interface's `UP` flag (not its `state` word, which
sits at `UNKNOWN` on a healthy tun device). `MESH ADDR` and `MESH PEERS` appear only when you opt in.
`REPLICATION` appears only when `keepNode.vaultReplication.role` is set, and shows the role plus lag in
seconds when a lag number is available.

**`n/a` vs `unknown` vs `failed`** are three different facts and the screen never conflates them:

- `n/a` (`·`, or `[ -- ]` in ASCII) , the owning module is not enabled on this node. Normal. A node
  without `frostGate` shows `VAULT n/a`, not `locked`; that is a node that was never gated, not a node
  whose vault failed to open.
- `unknown` (`○`, `[ ?? ]`) , the probe did not return, or the value could not be determined. `MESH
  PEERS unknown` means the mesh daemon could not be asked, which is not the same claim as zero peers.
- `failed` (`×`, `[FAIL]`) , the unit actually failed. An absent unit is never reported this way.

Every state is triple-coded (glyph + word + colour), so the reading survives a monochrome panel, a
colourblind reader, a serial capture and a photograph.

**STALE.** If the newest snapshot is older than `staleSeconds` (default 20, against a `refreshSeconds`
collection cadence of 5), a red full-width banner appears and **every collected value on the screen is
replaced by `??`** , not dimmed, not greyed, not left showing its last reading. A greyed-out `UNLOCKED`
is still read as "unlocked" by someone glancing across the room, and if the collector has stopped, the
screen no longer knows whether that is true. Only the last-known timestamp (in the footer), the
hostname and the SSH line survive, because those are static config rather than collected facts. Seeing
`??` everywhere means the collector is not producing snapshots; check
`journalctl -u keep-node-status-collect`. Note that the node label blanks with everything else, so a
stale screen does not tell you which box you are looking at , the SSH line at the foot does.

**Anti-lockout renders as a full-width alarm**, not just a row. `nixos/admin-access.nix:198` writes its
"NO authorized SSH key" warning directly to `/dev/console` , the same VT the renderer owns , so a
repaint would erase it within a second. It is re-raised here as a banner pinned above the fold, where
the row-budget fitter can never drop or scroll it. If you see it, the box has no admin key and remote
access is impossible; provision one before you walk away.

The anti-lockout row carries **the age of its own verdict** (`active (checked 3d ago)`), and you should
read that age, not just the colour. `keep-node-admin-key-check` is a `Type=oneshot` +
`RemainAfterExit=true` unit with no timer: it runs once at boot and latches its result. A key deleted
*after* boot does not re-trigger it, so a green anti-lockout row on a long-uptime node means "no lockout
as of that many days ago", not "no lockout now". To re-verify on demand:

```
systemctl restart keep-node-admin-key-check.service
```

The screen picks the new verdict, and the reset age, up within one collector cycle.

**If the status screen is blank or dead, use another VT.** Press **Alt+F2** (through Alt+F6) for a normal
login prompt; the status display only ever takes over its own VT and tty2-6 keep their gettys. This
matters because the renderer's VT has *no* getty to fall back to , `getty@` and `autovt@` for that
terminal are disabled, which NixOS implements by masking them, so `systemctl start getty@tty1` will
refuse. Alt+F2 is the recovery path at the keyboard. (Those prompts grant nothing by themselves: every
account is password-locked, so you still need a key-based SSH session, or physical media, to do
anything.) From there, `systemctl status keep-node-status-render` and
`journalctl -u keep-node-status-render` say why the screen is not painting.

**Conflict with `debugAccess`.** `keepNode.debugAccess` sets `services.getty.autologinUser = "root"`,
which claims tty1. Enabling both with `statusDisplay.tty = 1` is a build-time assertion failure, not a
runtime surprise. Remedy: either disable `keepNode.debugAccess` (the production posture), or move the
screen to a free VT with `keepNode.statusDisplay.tty = 2`. The status display takes over only its own
VT , tty2-6 keep their normal gettys, which grant nothing anyway since every account is
password-locked.

Untested on real hardware: this is CI-tested in NixOS VMs like the rest of the tree, so treat the first
boot on metal (console font, VT geometry, whether your firmware hands you a usable tty1) as something
to confirm, not assume.

## Phase 2 (Tier 0, cont.) , mesh onboarding (declarative)

From here you leave the stock image and deploy **your own config** (a flake that imports keep-node's
modules and sets your roster + keys). See [Deployment](./deployment.md) for the full `keepNode.mesh` +
`keepNode.adminAccess` how-to; the short version:

1. Generate an nvpn identity per participant (each box **and** your laptop) and record each npub.
2. Author each box's `keepNode.mesh` (networkId, selfEndpoint = its LAN ip:port, peers = the others'
   npub+endpoint, identityDir) and `keepNode.adminAccess.authorizedKeys`. `identityDir` holds that
   box's mesh secret key , deliver it out-of-band to a runtime path (e.g. `/run/secrets/...`), never a
   Nix-store path, or the key lands in the world-readable store (the module asserts against this).
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
- **`recoveryKeyFile`** enrolls an extra recovery keyslot and writes the key to that path , which sits
  on the **unencrypted root disk** (only `/var/lib/vaultwarden` is on the sealed volume), so **move it
  offline and delete the on-disk copy** as soon as first boot writes it. It is the escape hatch if PCR 7
  changes (a firmware/Secure-Boot/board change, or the Tier-2 switch to measured boot) before you have a
  replica to recover from. Left in place it defeats "steal the box, get nothing," so keep it only while
  you are single-node and drop it once you have a second node (Tier 4).

## Phase 4 (Tier 2) , measured boot (bind the seal to the real boot image)

PCR 7 alone only covers Secure Boot *policy*. Measured boot (Lanzaboote UKI → PCR 11) binds the seal to
the actual kernel/initrd/cmdline, so a tampered boot image fails closed. This is a bigger change (it
replaces the boot stack) and needs your **own Secure Boot keys**.

The seal's PCR set is enrolled **once, at first provision** (Tier 1). Changing `sealPcrs` and
redeploying does **not** re-seal an existing volume , the gate just keeps unlocking the old,
PCR-7-bound token (the only `--tpm2-pcrs` enrollment is the first-boot provision path). So plan the
order deliberately:

- **Fresh box (recommended):** do this phase *before* Tier 1 provisions the vault. Set up the Secure
  Boot keys and Lanzaboote (steps below), reboot into the UKI with Secure Boot on, and only then attach
  the vault volume with `sealPcrs = [ 7 11 ]` already set , first provision then seals to PCR 7+11 from
  the start.
- **Already-sealed box (Tier 1 done):** enrolling your Secure Boot keys and turning Secure Boot on
  change PCR 7 itself, so the current PCR-7 seal fails closed on the next boot , this is expected, not a
  fault. Boot the new stack, unlock the volume with the Tier-1 `recoveryKeyFile`, then re-seal the token
  to the new PCRs by hand (the gate will not re-enroll for you):

  ```bash
  # after unlocking with the recovery key, on the box:
  systemd-cryptenroll --wipe-slot=tpm2 --tpm2-device=auto --tpm2-pcrs=7+11 /dev/disk/by-id/nvme-...
  ```

Steps (both paths share the key setup):

1. On the box, create the Secure Boot PKI: `sbctl create-keys` (writes `/var/lib/sbctl`).
2. Enroll your keys into firmware: `sbctl enroll-keys` (with the box in Secure Boot **Setup Mode** ,
   set in BIOS: Security → Secure Boot → clear/erase keys, which drops to Setup Mode). Optionally keep
   Microsoft's keys with `sbctl enroll-keys -m` if any option ROM needs them.
3. In your config, import Lanzaboote + the measured-boot module and set the seal PCRs:

   ```nix
   imports = [ inputs.lanzaboote.nixosModules.lanzaboote ./nixos/measured-boot.nix ];
   keepNode.measuredBoot.enable = true;            # pkiBundle defaults to /var/lib/sbctl
   keepNode.frostGate.sealPcrs = [ 7 11 ];         # first provision seals here; re-enroll by hand if already sealed
   ```

4. Deploy, then enable **Secure Boot** in BIOS. Verify with `sbctl verify` and `bootctl status`.

Never add `11` to `sealPcrs` before the box actually boots the Lanzaboote UKI: until then PCR 11 is
unpopulated, so a seal would bind a zero/garbage value and the next boot fails closed. The module's own
assertion refuses a `sealPcrs` containing 11 unless `measuredBoot.enable` is set, but enabling the
module and *booting* the UKI are two different moments , the reboot in step 4 is what populates PCR 11.
On an already-sealed box the Tier-1 recovery key is your way back in, both for the expected PCR-7 lockout
above and for any misstep here.

## Phase 5 (Tiers 3-4) , OPRF quorum (incl. geo-distributed holders) + HA

**OPRF (`mode = "oprf"`)** reconstructs the LUKS key from a 2-of-3 threshold at boot (this box + two
holders). It is only a meaningful *threshold* gate once measured boot (Tier 2) is on AND the holders
authenticate + gate requests , until then it is no stronger than `tpm` (see the `mode` option's
security note). The OPRF crypto path is proven in the `oprf-unlock` / `oprf-unlock-2of3` tests; this
phase stands the same quorum up on metal, with **at least one holder in a different physical location**
(the real target: a holder that a local theft of the box cannot also seize).

Roles below: the **vault box** is this appliance (the FROST-gate dealer, runs `keepNode.frostGate` in
`oprf` mode); a **holder** is any device , your phone, a laptop, or a second box at another site , that
runs `keep frost network serve` and answers evaluations. Start with the smallest quorum that proves the
geo split (the box + one remote holder), then add the third share.

### 5a , Generate the group and hand out shares

On the vault box, generate the threshold group and export one share per holder:

```bash
keep frost generate -t 2 -s 3 --name g           # prints the group npub; generates all 3 shares
keep frost export --share 2 --group <group-npub>  # prints a kshare… bech32 for holder A (out-of-band)
keep frost export --share 3 --group <group-npub>  # prints a kshare… bech32 for holder B (the remote box)
```

Deliver each `kshare…` to its holder over a channel you trust (it is share-level secret, below
threshold on its own but still sensitive), and import it there: `keep frost import`. The remote box is
just a holder here , it does **not** need a TPM or the frost-gate; it needs `keep` and network reach to
the coordination relay (next step).

Then **delete the exported holder shares from the box** so a stolen box does not also carry them (the
OPRF threshold protects the LUKS key regardless, but this keeps the box below threshold on its own for
the FROST shares too, defense in depth):

```bash
keep frost delete-share --share 2 --group <group-npub>
keep frost delete-share --share 3 --group <group-npub>   # the box retains only its own share 1
```

### 5b , Choose the coordination relay (the one address every party must reach)

The quorum coordinates over **one** Nostr relay that the box **and every holder** can reach. Across
geos this is the crux, so choose deliberately:

- **A relay both sites can reach (works today).** Point `keepNode.frostGate.relay` (and each holder's
  `--relay`) at a `wss://` relay reachable from both locations. The on-box `keepNode.wisp` is *not* it
  out of the box , it binds plaintext `7777` scoped to the mesh interface only, so reaching it off-mesh
  means fronting it with a TLS-terminating reverse proxy at a routable `wss://` address (a real proxy +
  firewall change, not a config toggle); otherwise use another `wss://` relay you control. The relay
  only ever sees **ciphertext and traffic shape**, never plaintext or a share (it is untrusted by
  design, see [Security](./SECURITY.md)); the residual it *can* observe is timing/size/kind metadata.
  This is the recommended path for the first geo-distributed run.
- **Over the on-box mesh `wisp` (most private, pending).** Riding the coordination inside the `nvpn`
  WireGuard mesh would hide even that traffic shape from any network observer, leaving only the relay
  host. It is **not wired yet**: `keep` rejects a raw mesh-IP relay URL (its SSRF guard refuses internal
  addresses) and the mesh has no name resolver yet, so there is no address to point `--relay` at. Wiring
  this (a mesh-relay name via nvpn's `.fips` resolver, or an `allow-internal` build scoped to the mesh)
  is the open transport-hardening step , settle it during this bring-up, not by guessing. Until then,
  use the first option and accept the documented traffic-shape residual.

Whatever you choose, **use `wss://`** off the mesh: plaintext `ws://` is test-only (the
`allowInsecureWs` / `KEEP_ALLOW_WS` opt-ins) and exposes the coordination to an on-path attacker.

### 5c , Bootstrap attestation (holders pin the box's TPM quote)

Have the box announce its TPM quote and each holder TOFU-pin it, producing a `policy.toml` the holder
serves under. This is what makes the oracle refuse an unattested requester (the security property that
turns OPRF from "no stronger than tpm" into a real threshold). On each holder:

```bash
keep frost network attestation-provision --group <group-npub> --relay <relay> --out policy.toml --wait 60
```

### 5d , Provision the quorum (needs every holder online)

With both holders serving (`keep frost network serve --group <group-npub> --relay <relay>
--oprf-share-file <path> --oprf-dealer 1 --oprf-auto-approve --attestation-config policy.toml`), turn on
`keepNode.frostGate` in `oprf` mode on the box and let its provision unit seal a share to every party.
Provisioning **requires all three parties reachable at once** (it distributes a sealed share to each);
after it, each holder reloads its newly sealed OPRF share and only the box + any **one** holder are
needed to unlock.

### 5e , Validate the threshold across a reboot and across the geo split

- **Reboot with the remote holder online** , the box + the remote holder should reconstruct the key
  and mount the vault unattended. This is the headline: a holder in another location gates the unlock.
- **Reboot with every holder offline** , the gate must fail closed (no mapper, Vaultwarden down). This
  proves the box alone is below threshold, i.e. stealing the box gets nothing.

### 5f , Validate the duress path across geos (optional but recommended)

Provision a duress credential and pin the remote holder to a beacon, then rehearse the coercion
response end to end over the real network: entering the duress credential on one holder must **freeze**
the pinned remote holder (co-signing + OPRF refused), survive a restart, and lift only via the delayed,
cancelable operator clear. The mechanism and its honest ceiling are in [Security](./SECURITY.md); this
is where you confirm the beacon actually reaches a holder in another location over the live relay.

**Multi-node HA (Tier 4)** wires `keepNode.vaultReplication` (role active/standby, shared JWT key,
Litestream WAL streaming, file replication) over the mesh between two boxes. See
[Multi-node sync](./multi-node-sync.md).

## Gotchas

- **x86_64 only** , no ARM SBC.
- **TPM must be enabled in BIOS** before Tier 1, or provisioning fails.
- **Never point `volumeDevice` at a kernel name** (`/dev/sdb`) , use `/dev/disk/by-id/...`.
- **Enroll Secure Boot keys before Secure Boot enforcement** , enabling it with only Microsoft's keys
  blocks the unsigned installer/UKI.
- **Keep the Tier 1 recovery key** until you have a second node; a PCR change otherwise locks you out.

### Multi-geo specific (Phase 5 with a remote holder)

- **Sync every clock (NTP) before you coordinate.** Coordination events carry a timestamp and are
  rejected outside a **300s replay window**, and anything more than **30s in the future** is refused
  outright; the duress beacon's freshness rides the same window. Two boxes in different locations with
  drifted clocks will see each other's announces/evaluations (and a duress beacon) as stale or
  future-dated, and the quorum silently never converges. Enable NTP on every node and confirm
  `timedatectl` agrees across sites before Phase 5.
- **The mesh underlay needs a routable endpoint per node.** The `nvpn` mesh is UDP on the underlay, and
  nvpn **refuses to advertise an RFC1918 address** (STUN/hole-punching is not wired). A box behind home
  NAT (the remote holder's likely situation) must advertise a **routable** `selfEndpoint` , forward the
  mesh listen port (default 51820/udp) on that site's router to the box, and set `selfEndpoint` to the
  public `ip:port`. `discovery.enable` mode brokers *addresses* over a relay but still needs the
  underlay itself reachable. If the mesh never reaches "peers connected", this is almost always it.
- **Both sites must reach the same relay.** The quorum shares one coordination relay (Phase 5b); a
  remote holder that cannot reach it simply never answers, and the box fails closed as if the holder
  were offline. Verify reachability (`wss://` handshake) from *each* site before provisioning.
- **The remote holder is a full trust-bearing party.** It holds a share and gates an unlock, so treat
  its host with the same care as the box; a compromised holder is survivable (one share is below
  threshold) but a compromised *majority* across sites is not.
