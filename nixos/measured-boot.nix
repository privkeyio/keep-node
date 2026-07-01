# Opt-in measured boot: boot the appliance through a Unified Kernel Image (Lanzaboote +
# systemd-stub) so the kernel + initrd + kernel command line + os-release are measured into
# TPM PCR 11. Without this the box boots via systemd-boot and PCR 11 is never populated, so
# `keepNode.frostGate.sealPcrs = [ 7 11 ]` would seal to a zero/garbage PCR 11 and fail closed
# on the next boot. Enabling this makes PCR 11 a real, deterministic measurement of the boot
# image, which is what lets the FROST gate bind its TPM seals to the actual kernel/initrd
# (not just Secure Boot policy, which is all PCR 7 covers).
#
# This is OFF by default and is NOT pulled into the default appliance composition
# (nixos/keep-node.nix), because Lanzaboote replaces the boot stack (UEFI + UKI + signing) and
# the VM test suite boots via the lightweight direct-kernel path. To use it, a deployment
# imports THIS module AND lanzaboote's NixOS module together, e.g.:
#
#   imports = [
#     inputs.lanzaboote.nixosModules.lanzaboote
#     ./nixos/measured-boot.nix
#   ];
#   keepNode.measuredBoot.enable = true;
#
# (The lanzaboote module is what defines `boot.lanzaboote.*`; this module only drives it.)
# Secure Boot key material is provisioned out of band with `sbctl` into `pkiBundle`; see the
# Lanzaboote quick start. PCR 11 is populated by systemd-stub regardless of whether Secure Boot
# is enforcing, so measured boot is meaningful even before Secure Boot enrollment is complete.
{
  config,
  lib,
  ...
}:
let
  cfg = config.keepNode.measuredBoot;
in
{
  options.keepNode.measuredBoot = {
    enable = lib.mkEnableOption "UKI/Lanzaboote measured boot (populates TPM PCR 11)";

    pkiBundle = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/sbctl";
      description = ''
        Directory holding the Secure Boot PKI (created with `sbctl create-keys`) that Lanzaboote
        uses to sign the Unified Kernel Images. Must persist across rebuilds.

        Provision it out of band BEFORE the first `nixos-rebuild switch` with this module enabled:
        Lanzaboote signs the UKI during the switch and the rebuild fails if the signing key is
        absent (this module sets neither `boot.lanzaboote.autoGenerateKeys` nor `allowUnsigned`).
        This directory holds the Secure Boot db signing private key, so it must be root-owned with
        restrictive permissions (`sbctl` creates it 0700 with 0600 keys); a leaked db.key lets an
        attacker sign a UKI the firmware will trust.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Lanzaboote owns the EFI boot entries; systemd-boot must step aside or the two fight over
    # the ESP. mkForce because the base nixpkgs profile enables systemd-boot by default.
    boot.loader.systemd-boot.enable = lib.mkForce false;
    boot.loader.efi.canTouchEfiVariables = true;

    boot.lanzaboote = {
      enable = true;
      pkiBundle = cfg.pkiBundle;
    };
  };
}
