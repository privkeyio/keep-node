# frost-gate: Vaultwarden's data dir is an encrypted LUKS volume gated at boot.
#   node  - mode = "tpm" (v1): TPM-sealed LUKS volume, auto-unlocked at boot. Grounded in nixpkgs
#           nixos/tests/systemd-cryptenroll.nix (emptyDiskImages + tpm.enable +
#           systemd-cryptenroll --tpm2-device=auto), unlocked by the keep-node-frost-gate service.
#   recovery - mode = "tpm" with the opt-in recoveryKeyFile: first boot enrolls an extra LUKS
#           recovery keyslot and writes its key (the escape hatch for a single-node PCR change).
#   oprf  - mode = "oprf" (v2): threshold-OPRF quorum unlock. The live relay + remote holders and
#           the TPM-sealed credentials are NOT reproduced in the VM (`keep` is a stub, no holders
#           online), so this leg covers config evaluation, systemd unit wiring, and the fail-closed
#           posture rather than a real end-to-end quorum unlock (which needs external infra).
# The `node` leg also covers the data-loss branches: interrupted-provision reclaim, token-gone
# fail-closed, and the oprf-volume mode-switch refusal. The dd-unreadable and wipefs-retry guards
# are defensive against transient I/O and are not simulated deterministically here.
# Run: nix build .#checks.x86_64-linux.frost-gate
{ ... }:
{
  name = "keep-node-frost-gate-test";

  nodes.node =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.frostGate = {
        enable = true;
        volumeDevice = "/dev/vdb";
      };

      # For the test-script assertions (cryptsetup isLuks / enroll listing).
      environment.systemPackages = [ pkgs.cryptsetup ];

      virtualisation = {
        emptyDiskImages = [ 512 ]; # /dev/vdb, the vault volume
        tpm.enable = true; # swtpm
      };
    };

  # mode = "oprf" wiring + fail-closed coverage. `keep` is stubbed: the fail-closed paths
  # exercised here (missing TPM-sealed creds, blank/unprovisioned device) never reach the binary,
  # so a stub is sufficient and avoids building keep-cli in the VM. A true end-to-end OPRF unlock
  # needs the external relay + holder quorum and is out of scope for this harness.
  nodes.oprf =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.frostGate = {
        enable = true;
        mode = "oprf";
        volumeDevice = "/dev/vdb";
        keepPackage = pkgs.writeShellScriptBin "keep" ''
          echo "stub keep invoked (no live OPRF quorum in the VM): $*" >&2
          exit 1
        '';
        keepDbPath = "/var/lib/keep";
        group = "npub1stubgroup";
        relay = "ws://127.0.0.1:7777";
        keepPasswordCred = "/var/lib/keep-node/keep-password.cred";
        oprfShareCred = "/var/lib/keep-node/oprf-share.cred";
      };

      environment.systemPackages = [ pkgs.cryptsetup ];

      virtualisation = {
        emptyDiskImages = [ 512 ];
        tpm.enable = true;
      };
    };

  # mode = "tpm" with the opt-in recoveryKeyFile: first-boot provisioning must enroll an extra
  # LUKS recovery keyslot and write its key, so a single-node deploy can survive a PCR change.
  nodes.recovery =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.frostGate = {
        enable = true;
        volumeDevice = "/dev/vdb";
        recoveryKeyFile = "/var/lib/keep-node/recovery.key";
      };

      environment.systemPackages = [ pkgs.cryptsetup ];

      virtualisation = {
        emptyDiskImages = [ 512 ];
        tpm.enable = true;
      };
    };

  testScript = ''
    node.start()

    # First boot: blank disk -> the gate self-provisions (LUKS format + TPM2 enroll + mkfs).
    node.wait_for_unit("keep-node-frost-gate.service")
    node.succeed("cryptsetup isLuks /dev/vdb")
    node.succeed("systemd-cryptenroll /dev/vdb | grep -q tpm2")

    # Drop a canary into the decrypted volume so the reboot can prove the SAME data came
    # back (i.e. the volume was unlocked, not silently reformatted).
    node.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
    node.succeed("echo keep-node-canary > /var/lib/vaultwarden/canary")

    # Reboot: the gate TPM2-unlocks the volume, it mounts, then Vaultwarden starts off it.
    node.shutdown()
    node.start()
    node.wait_for_unit("keep-node-frost-gate.service")
    node.succeed("test -e /dev/mapper/keep-vault")
    node.wait_for_unit("vaultwarden.service")

    # The vault data dir IS the decrypted LUKS mapper, and Vaultwarden serves off it.
    node.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")

    # The canary survived: the gate unlocked the existing volume rather than reformatting.
    node.succeed("grep -qx keep-node-canary /var/lib/vaultwarden/canary")
    node.wait_for_open_port(8222)
    node.succeed("curl -fsS http://localhost:8222/alive")

    # Reclaim branch (the headline data-loss fix): label present, completion marker ABSENT, but the
    # TPM2 token still PRESENT. The marker is the sole authority that a filesystem exists, so its
    # absence means a first provision interrupted before mkfs (no data) even with a token already
    # enrolled. The gate must RECLAIM (wipe + reprovision from blank), NOT take the token-first
    # unlock path and then fail to mount an empty volume on every boot (the pre-fix brick). Strip
    # ONLY the subsystem marker (re-set the label in the same call, as provisioning does) while
    # leaving the token, then reboot.
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-provisioned")  # marker present
    node.succeed('cryptsetup config /dev/vdb --label keep-node-frost-gate --subsystem ""')
    node.succeed("! cryptsetup luksDump /dev/vdb | grep -q keep-node-provisioned")  # marker gone
    node.succeed("systemd-cryptenroll /dev/vdb | grep -q tpm2")  # token deliberately left enrolled

    node.shutdown()
    node.start()
    # Reclaimed, not bricked: the gate comes back up, the volume is freshly provisioned (marker
    # re-set, a new TPM2 token), and the stale canary is GONE (the device was reformatted, proving
    # the reclaim path ran rather than attach-an-empty-volume-then-fail-to-mount).
    node.wait_for_unit("keep-node-frost-gate.service")
    node.succeed("test -e /dev/mapper/keep-vault")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-provisioned")
    node.succeed("systemd-cryptenroll /dev/vdb | grep -q tpm2")
    node.wait_for_unit("vaultwarden.service")
    # Assert the stale canary is gone against the MOUNTED reclaimed volume. Confirm the mapper is
    # mounted first: otherwise an unmounted dataDir would read the (empty) underlying root dir and
    # the check would pass spuriously, masking the very brick regression this test guards.
    node.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
    node.fail("test -e /var/lib/vaultwarden/canary")  # reformatted: stale data gone

    # Re-seed the canary so the fail-closed test below operates on a provisioned, data-bearing volume.
    node.succeed("echo keep-node-canary > /var/lib/vaultwarden/canary")

    # Losing the TPM2 token on a PROVISIONED volume must FAIL CLOSED, never auto-wipe. Removing
    # the systemd-tpm2 token leaves the volume with no usable keyslot, so its data (the canary
    # above) is unrecoverable on-box. Per the fail-closed design (header: recover from a replica,
    # never destroy local data) the gate must refuse to reformat and leave the node down, NOT come
    # back up on a freshly wiped empty volume. The completion marker (LUKS2 subsystem) is what lets
    # the gate tell this apart from an interrupted first provision (which has no marker and IS
    # reclaimed). Note: a real PCR change / TPM clear leaves the token present and the unseal simply
    # fails closed at attach; deleting the token here reproduces the same "no usable keyslot" end
    # state via a path the test can drive deterministically.
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-provisioned")  # marker is set
    tokid = node.succeed("cryptsetup luksDump /dev/vdb | sed -n 's/^\\s*\\([0-9]\\+\\): systemd-tpm2/\\1/p' | head -n1").strip()
    node.succeed(f"cryptsetup token remove --token-id {tokid} /dev/vdb")
    node.succeed("! systemd-cryptenroll /dev/vdb | grep -q tpm2")  # tpm2 token really gone

    node.shutdown()
    node.start()
    # The gate refuses to destroy the provisioned-but-unrecoverable volume: its unit fails closed,
    # and for THIS reason (the refuse-to-reformat path), not some unrelated abort.
    node.wait_until_succeeds("systemctl is-failed --quiet keep-node-frost-gate.service")
    node.succeed("journalctl -u keep-node-frost-gate.service | grep -q 'refusing to reformat'")
    node.fail("test -e /dev/mapper/keep-vault")  # not unlocked
    node.fail("systemctl is-active --quiet vaultwarden.service")  # vault stays down (hard dep)
    # The volume was NOT reformatted: our LUKS container, label, and completion marker all survive.
    node.succeed("cryptsetup isLuks /dev/vdb")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-frost-gate")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-provisioned")

    # Mode-switch data-loss guard: tpm and oprf modes share the LUKS label, so a tpm-mode gate must
    # NOT wipe an oprf-provisioned volume. Re-stamp the subsystem marker to keep-node-oprf (our data
    # and label intact) and reboot; the tpm gate must refuse fail-closed (its keep-node-oprf branch),
    # not fall through to the reclaim-wipe.
    node.succeed('cryptsetup config /dev/vdb --label keep-node-frost-gate --subsystem keep-node-oprf')
    node.shutdown()
    node.start()
    node.wait_until_succeeds("systemctl is-failed --quiet keep-node-frost-gate.service")
    node.succeed("journalctl -b -u keep-node-frost-gate.service | grep -q 'OPRF-provisioned'")
    node.fail("test -e /dev/mapper/keep-vault")  # not unlocked, not wiped
    # The oprf volume survived untouched: still LUKS, our label, the keep-node-oprf marker intact.
    node.succeed("cryptsetup isLuks /dev/vdb")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-frost-gate")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-oprf")

    # --- mode = "tpm" with recoveryKeyFile: opt-in recovery keyslot is enrolled on first boot. ---
    recovery.start()
    recovery.wait_for_unit("keep-node-frost-gate.service")
    recovery.succeed("cryptsetup isLuks /dev/vdb")
    # The recovery key file was written, owner-only (0600).
    recovery.succeed("test -f /var/lib/keep-node/recovery.key")
    recovery.succeed('test "$(stat -c %a /var/lib/keep-node/recovery.key)" = 600')
    # It actually unlocks the volume INDEPENDENTLY of the TPM: the enrolled recovery passphrase
    # (fed without its trailing newline) opens a keyslot. --test-passphrase checks it without
    # activating a mapper. This is the escape hatch a PCR change would otherwise leave no path to.
    recovery.succeed(
        "printf '%s' \"$(cat /var/lib/keep-node/recovery.key)\" "
        "| cryptsetup luksOpen --test-passphrase -d - /dev/vdb"
    )
    # The TPM2 token is still the primary keyslot; the recovery slot is additive, not a replacement.
    recovery.succeed("systemd-cryptenroll /dev/vdb | grep -q tpm2")

    # --- mode = "oprf": config evaluation, unit wiring, fail-closed posture. ---
    # The live threshold-OPRF quorum (relay + remote holders) and the TPM-sealed credentials are
    # NOT reproduced here, so this does NOT assert a real unlock. It asserts the oprf config
    # evaluates, the units are wired as intended, and that with no usable credentials/quorum the
    # gate stays locked and vaultwarden never starts (fail-closed). End-to-end OPRF unlock needs
    # the external relay/holder infrastructure and is out of scope for the VM harness.
    oprf.start()

    # The operator-driven provision unit exists but is NOT wired into boot (no WantedBy).
    oprf.succeed("systemctl cat keep-node-frost-provision.service")
    oprf.succeed(
        'test -z "$(systemctl show -p WantedBy --value keep-node-frost-provision.service)"'
    )

    # The gate carries the oprf wiring: both encrypted credentials are loaded. Read the rendered
    # unit file (`systemctl show -p LoadCredentialEncrypted` does not surface the credential IDs).
    oprf.succeed(
        "systemctl cat keep-node-frost-gate.service | grep -q 'LoadCredentialEncrypted=keep-password:'"
    )
    oprf.succeed(
        "systemctl cat keep-node-frost-gate.service | grep -q 'LoadCredentialEncrypted=oprf-share:'"
    )
    # ...and the boot unlock renders the hardware-attestation flag into the unlock invocation. The
    # flag lives in the ExecStart script (not the unit body), so resolve the script path and grep
    # it: a renamed option or dropped interpolation would silently strip attestation and otherwise
    # pass CI (the fail-closed paths above never reach the stubbed `keep`).
    gate_script = oprf.succeed(
        "systemctl show -p ExecStart --value keep-node-frost-gate.service "
        "| grep -oE '/nix/store/[^ ;]*unit-script-keep-node-frost-gate-start[^ ;]*' | head -n1"
    ).strip()
    oprf.succeed(f"grep -q -- '--tpm-tcti device:/dev/tpmrm0' {gate_script}")
    # ...and the boot unlock is time-bounded (a hung relay can't stall boot forever).
    oprf.succeed(
        'test "$(systemctl show -p TimeoutStartUSec --value keep-node-frost-gate.service)" != infinity'
    )

    # Fail-closed: with no quorum and no TPM-sealed creds the gate fails, the volume is never
    # unlocked, and vaultwarden (hard dep) never starts off a plaintext/wrong device.
    oprf.wait_until_succeeds("systemctl is-failed --quiet keep-node-frost-gate.service")
    oprf.fail("test -e /dev/mapper/keep-vault")
    oprf.fail("systemctl is-active --quiet vaultwarden.service")
    # The blank vault device was not touched (no LUKS signature written by the failed gate).
    oprf.fail("cryptsetup isLuks /dev/vdb")
  '';
}
