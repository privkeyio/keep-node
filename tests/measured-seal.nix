# 54v increment 2: with measured boot ON (Lanzaboote UKI, so PCR 11 is a real measurement of the
# kernel+initrd+cmdline), the FROST gate can seal the vault's LUKS key to sealPcrs = [ 7 11 ] and
# it must round-trip: provision seals to PCR 7 AND 11, and an unchanged-UKI reboot re-measures the
# same PCR 11 so the TPM releases the key and the volume unlocks. This is the payoff of the
# measured-boot work: the at-rest seal is now bound to the actual boot image, not just Secure Boot
# policy (PCR 7). A DIFFERENT UKI would re-measure a different PCR 11 and the unseal would fail
# closed; that is a cryptographic property of sealing to a real PCR 11 (PCR 11 realness is proven
# by the measured-boot test, the seal's PCR-11 binding is proven here). Directly booting a tampered
# UKI to observe the failure is a larger test, tracked separately.
#
# Reuses Lanzaboote's pinned image harness (repart image + OVMF + swtpm) by reference, like the
# measured-boot test. Secure Boot key enrollment is skipped (keyFixture = false, allowUnsigned =
# true): PCR 11 is measured regardless, and mode = "tpm" seals to PCR values, not to SB signatures.
#
# Run: nix build .#checks.x86_64-linux.measured-seal
{ lanzaboote, ... }:
{
  name = "keep-node-measured-seal";

  nodes.machine =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    {
      imports = [
        lanzaboote.nixosModules.lanzaboote
        "${lanzaboote}/nix/tests/lanzaboote/common/image.nix"
        ../nixos/measured-boot.nix
        ../nixos/frost-gate.nix
      ];

      options.lanzabooteTest = {
        keyFixture = lib.mkEnableOption "pkiBundle fixture baked into the image" // {
          default = config.virtualisation.useSecureBoot;
        };
        persistentRoot = lib.mkEnableOption "a persistent root filesystem";
      };

      config = {
        keepNode.measuredBoot.enable = true;
        keepNode.frostGate = {
          enable = true;
          volumeDevice = "/dev/vdb";
          # The whole point: bind the seal to the UKI measurement (PCR 11), not only PCR 7.
          sealPcrs = [
            7
            11
          ];
        };

        lanzabooteTest.keyFixture = lib.mkForce false;
        lanzabooteTest.persistentRoot = true;
        boot.lanzaboote.allowUnsigned = true;

        virtualisation.tpm.enable = true;
        virtualisation.emptyDiskImages = [ 512 ]; # /dev/vdb, the vault volume

        environment.systemPackages = [
          pkgs.cryptsetup
          pkgs.jq
          pkgs.tpm2-tools
          # Attach /dev/vdb via its TPM2 token to a scratch mapper, exactly as the gate does at
          # boot. Exits non-zero if the TPM refuses to release the key (e.g. a PCR no longer
          # matches). Used to prove the seal fails closed when PCR 11 changes.
          (pkgs.writeShellScriptBin "tpm-unseal-attempt" ''
            exec ${pkgs.systemd}/lib/systemd/systemd-cryptsetup attach "$1" /dev/vdb - tpm2-device=auto
          '')
        ];
      };
    };

  testScript =
    { nodes, ... }:
    (import "${lanzaboote}/nix/tests/lanzaboote/common/image-helper.nix" {
      inherit (nodes) machine;
    })
    + ''
      machine.wait_for_unit("default.target")

      # First boot: the gate self-provisions the vault and TPM2-seals it.
      machine.wait_for_unit("keep-node-frost-gate.service")
      machine.succeed("cryptsetup isLuks /dev/vdb")
      machine.succeed("systemd-cryptenroll /dev/vdb | grep -q tpm2")

      # The seal is bound to the UKI measurement (PCR 11) AND Secure Boot policy (PCR 7). Without
      # PCR 11 in the token, a swapped kernel/initrd would still release the key.
      bound_pcrs = machine.succeed(
          "cryptsetup luksDump --dump-json-metadata /dev/vdb "
          "| jq -c '[.tokens[] | select(.type==\"systemd-tpm2\") | .\"tpm2-pcrs\"[]] | sort'"
      ).strip()
      assert bound_pcrs == "[7,11]", f"TPM2 seal not bound to PCRs 7 and 11, got: {bound_pcrs}"

      # Canary proves the SAME volume returns after reboot (unlocked, not reformatted).
      machine.succeed("test -e /dev/mapper/keep-vault")
      machine.succeed("echo keep-node-canary > /var/lib/vaultwarden/canary")

      # Reboot on the UNCHANGED UKI: systemd-stub re-measures the same PCR 11, so the TPM releases
      # the key and the gate unlocks the existing volume. A changed UKI would fail this closed.
      machine.reboot()
      machine.wait_for_unit("keep-node-frost-gate.service")
      machine.succeed("test -e /dev/mapper/keep-vault")
      machine.succeed("findmnt -n -o SOURCE /var/lib/vaultwarden | grep -q '/dev/mapper/keep-vault'")
      machine.succeed("grep -qx keep-node-canary /var/lib/vaultwarden/canary")

      # The tamper check below must exercise the TPM's PCR policy, which means the vault device has
      # to be FREE: while the gate keeps /dev/vdb open as keep-vault, any tpm-unseal-attempt dies at
      # systemd-cryptsetup's "device in use" guard BEFORE the TPM is consulted, so both the positive
      # control and the negative check would resolve for a device-busy reason rather than the PCR
      # policy. Tear the live vault down first (unmount the vault, close the mapper) so the attempts
      # below actually reach the TPM.
      machine.succeed("umount /var/lib/vaultwarden")
      machine.succeed("cryptsetup close keep-vault")

      # Positive control on the helper itself: with the device free and PCR 11 unchanged, the same
      # tpm-unseal-attempt helper makes the TPM release the key and unseals cleanly. This ties the
      # tamper failure below to the PCR 11 change and not to a broken helper path (bad arg, device
      # busy, missing device).
      machine.succeed("tpm-unseal-attempt precheck")
      machine.succeed("test -e /dev/mapper/precheck")
      machine.succeed("cryptsetup close precheck")

      # Fail closed on a changed boot. Extend PCR 11 to a different value, which is what a swapped
      # kernel/initrd/cmdline would measure, and confirm the TPM refuses to release the key so a fresh
      # unlock through the identical helper fails and no mapper is created. This is the tamper-detection
      # property measured boot exists to provide. A PCR extend is irreversible until reboot, so this
      # runs last. There is no passphrase keyslot to fall back on (the gate wipes it after enrolling
      # the TPM2 token), so the attempt fails rather than prompting.
      machine.succeed(
          "tpm2_pcrextend -T device:/dev/tpmrm0 "
          "11:sha256=0000000000000000000000000000000000000000000000000000000000000000"
      )
      machine.fail("timeout 60 tpm-unseal-attempt tampercheck")
      machine.succeed("test ! -e /dev/mapper/tampercheck")
    '';
}
