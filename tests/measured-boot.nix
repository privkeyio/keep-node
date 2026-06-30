# keepNode.measuredBoot: boot through a Lanzaboote UKI and prove TPM PCR 11 is a REAL measurement
# of the boot image (kernel + initrd + cmdline + os-release), which is the precondition for the
# FROST gate to seal to sealPcrs = [ 7 11 ]. Without UKI boot, PCR 11 is never populated.
#
# The VM harness (repart disk image, OVMF Secure Boot firmware, EFI-var persistence, the
# reboot-to-enroll helper) is reused from Lanzaboote's own, pinned test suite rather than
# re-derived: this test references those files from the pinned `lanzaboote` flake input. Following
# Lanzaboote's measured-boot test, Secure Boot key enrollment is skipped (keyFixture = false,
# allowUnsigned = true): systemd-stub measures the UKI into PCR 11 whether or not Secure Boot is
# enforcing, so PCR 11 is provable without the (separate, finicky) key-enrollment step.
#
# Run: nix build .#checks.x86_64-linux.measured-boot
{ lanzaboote, ... }:
{
  name = "keep-node-measured-boot";

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
        # Lanzaboote's image harness: repart ESP/nix-store/root image + OVMF + swtpm wiring.
        "${lanzaboote}/nix/tests/lanzaboote/common/image.nix"
        ../nixos/measured-boot.nix
      ];

      # `image.nix` reads these toggles (normally declared in Lanzaboote's common/lanzaboote.nix,
      # which we do not import because keepNode.measuredBoot is what drives boot.lanzaboote here).
      options.lanzabooteTest = {
        keyFixture = lib.mkEnableOption "pkiBundle fixture baked into the image" // {
          default = config.virtualisation.useSecureBoot;
        };
        persistentRoot = lib.mkEnableOption "a persistent root filesystem";
      };

      config = {
        # The appliance's opt-in measured-boot module is the thing under test: it turns on
        # boot.lanzaboote and stands systemd-boot down.
        keepNode.measuredBoot.enable = true;

        lanzabooteTest.keyFixture = lib.mkForce false;
        lanzabooteTest.persistentRoot = true;
        boot.lanzaboote.allowUnsigned = true;

        virtualisation.tpm.enable = true;

        environment.systemPackages = [
          (pkgs.writeShellScriptBin "lanzaboote-measure-uki" ''
            UKI_SECTIONS_DIR=$(mktemp -d)
            for section in .osrel .cmdline; do
              ${lib.getExe' pkgs.bintools "objcopy"} -O binary --only-section=$section /boot/EFI/Linux/nixos-generation-1-*.efi "$UKI_SECTIONS_DIR/$section"
            done
            /run/current-system/sw/lib/systemd/systemd-measure calculate \
              --linux /boot/EFI/nixos/kernel-*.efi \
              --initrd /boot/EFI/nixos/initrd-*.efi \
              --osrel "$UKI_SECTIONS_DIR/.osrel" \
              --cmdline "$UKI_SECTIONS_DIR/.cmdline" \
              --phase "" \
              --bank "sha256"
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

      # The live PCR 11 in the TPM must equal the value computed from the on-disk UKI sections.
      # Equality proves PCR 11 is a genuine measurement of THIS boot image (real measured boot),
      # not an unpopulated/zero register.
      pcr_calculated = machine.succeed("lanzaboote-measure-uki")
      pcr_current = machine.succeed("/run/current-system/sw/lib/systemd/systemd-measure status --bank sha256")
      t.assertEqual(pcr_calculated, pcr_current, "Live PCR 11 does not match the calculated UKI measurement")
    '';
}
