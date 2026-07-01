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

  # mode = "oprf" wiring + fail-closed + oprfGateScript coverage. `keep` is stubbed (exit 1): the
  # script reaches it -- after decrypting the TPM-sealed creds and matching the keep-node-oprf
  # marker -- and the stub's lack of a quorum is what makes it fail closed, so the gate's unlock
  # path and credential check are exercised without building keep-cli or standing up a live quorum.
  # A successful end-to-end quorum unlock (relay + holders) is covered by the oprf-unlock test.
  nodes.oprf =
    { pkgs, ... }:
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.frostGate = {
        enable = true;
        mode = "oprf";
        volumeDevice = "/dev/vdb";
        keepPackage = pkgs.writeShellScriptBin "keep" ''
          # Read our capability bounding set with shell builtins only: this stub runs inside the
          # confined transient systemd-run unit, which does NOT inherit the gate unit's PATH, so
          # external grep/awk are not resolvable here. CapBnd is the direct value of the scope's
          # CapabilityBoundingSet= (empty when confined), so the test can prove delegation from it.
          capbnd=
          while read -r field value _; do
            if [ "$field" = "CapBnd:" ]; then capbnd=$value; fi
          done < /proc/self/status
          echo "stub keep invoked (no live OPRF quorum in the VM): $* CapBnd=$capbnd" >&2
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
    # wait_until (not a bare grep): the unit can enter the failed state a moment before its final
    # log line is flushed to the journal, which occasionally raced the grep. A genuinely wrong
    # failure path still fails here (the line never appears), just after the retry window.
    node.wait_until_succeeds(
        "journalctl -u keep-node-frost-gate.service | grep -q 'refusing to reformat'"
    )
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
    node.fail("systemctl is-active --quiet vaultwarden.service")  # hard dep held: stays down
    # The oprf volume survived untouched: still LUKS, our label, the keep-node-oprf marker intact.
    node.succeed("cryptsetup isLuks /dev/vdb")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-frost-gate")
    node.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-oprf")

    # --- mode = "tpm" with recoveryKeyFile: opt-in recovery keyslot is enrolled on first boot. ---
    recovery.start()
    recovery.wait_for_unit("keep-node-frost-gate.service")
    recovery.succeed("cryptsetup isLuks /dev/vdb")
    # The recovery key file was written, root-owned and owner-only (0600).
    recovery.succeed("test -f /var/lib/keep-node/recovery.key")
    recovery.succeed('test "$(stat -c %U /var/lib/keep-node/recovery.key)" = root')
    recovery.succeed('test "$(stat -c %a /var/lib/keep-node/recovery.key)" = 600')
    # It actually unlocks the volume INDEPENDENTLY of the TPM, fed exactly as the operator would use
    # it: the file passed straight to `cryptsetup -d <file>` (cryptsetup reads the whole file as the
    # passphrase, so the stored bytes must carry NO trailing newline). --test-passphrase checks the
    # keyslot without activating a mapper. This is the escape hatch a PCR change would otherwise
    # leave no path to.
    recovery.succeed("cryptsetup luksOpen --test-passphrase -d /var/lib/keep-node/recovery.key /dev/vdb")
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

    # Now exercise oprfGateScript ITSELF with real inputs (the credential decrypt + the unlock
    # branch), so the fail-closed above isn't only passing because the creds were missing. Seal the
    # two creds to this TPM (PCR 7) -- the same key LoadCredentialEncrypted decrypts with -- and lay
    # down a volume carrying our label + the keep-node-oprf completion marker so the gate takes the
    # unlock branch. The stub keep has no quorum, so the script must fail closed AT the keep
    # invocation, not before it. (A successful quorum unlock is covered end to end at the keep-cli
    # level by the oprf-unlock test.)
    oprf.succeed("mkdir -p /var/lib/keep-node")
    oprf.succeed(
        "printf 'dev-password' | systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 "
        "--name=keep-password - /var/lib/keep-node/keep-password.cred"
    )
    oprf.succeed(
        "head -c 64 /dev/urandom | systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 "
        "--name=oprf-share - /var/lib/keep-node/oprf-share.cred"
    )
    oprf.succeed(
        "echo dummy-bootstrap | cryptsetup luksFormat -q --label keep-node-frost-gate /dev/vdb -"
    )
    oprf.succeed("cryptsetup config /dev/vdb --label keep-node-frost-gate --subsystem keep-node-oprf")

    # Re-run the gate: creds now load, the script runs, and the stub-keep unlock fails closed.
    oprf.fail("systemctl restart keep-node-frost-gate.service")
    # It REACHED `keep oprf-unlock` -- so the creds decrypted and the keep-node-oprf marker matched.
    # That is the script/quorum logic failing closed, not a missing-credential abort before ExecStart.
    # The relay-facing unlock now runs in a confined transient systemd-run scope; find its stub log
    # in the boot journal (assert on message content, since --pipe hands the scope the gate unit's
    # inherited journald stderr fd, so unit attribution alone can't prove delegation).
    oprf.wait_until_succeeds("journalctl -b | grep -qE 'stub keep invoked.*oprf-unlock'")
    # ...and confirm it was actually delegated to the sandbox, not run inline as uncapped root in the
    # privileged gate unit (the whole point of the confinement). The transient scope sets
    # CapabilityBoundingSet= (empty), so the delegated `keep` sees an all-zero CapBnd; inline in the
    # gate (no CapabilityBoundingSet=) it would show the default full set. The CapBnd token is emitted
    # on the SAME log line as the oprf-unlock args, so this proves confinement of that invocation.
    oprf.wait_until_succeeds("journalctl -b | grep -qE 'oprf-unlock.*CapBnd=0000000000000000'")
    oprf.fail("test -e /dev/mapper/keep-vault")  # not unlocked
    oprf.fail("systemctl is-active --quiet vaultwarden.service")
    # The marker'd volume was NOT wiped by the failed unlock (oprf mode never auto-formats).
    oprf.succeed("cryptsetup isLuks /dev/vdb")
    oprf.succeed("cryptsetup luksDump /dev/vdb | grep -q keep-node-oprf")
  '';
}
