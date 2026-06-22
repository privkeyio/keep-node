# FROST threshold volume gate (Approach B).
#
# v1 (this module): Vaultwarden's data dir lives on a LUKS volume whose key is sealed to the
# TPM (released by measured boot). A single gate service provisions the volume on first boot
# (format + TPM2 enroll + mkfs) and unlocks it on every boot via TPM2, before the volume is
# mounted and before vaultwarden.service. Grounded in nixpkgs nixos/tests/systemd-cryptenroll.nix
# (systemd-cryptenroll --tpm2-device=auto) and systemd-cryptsetup attach for the unlock.
#
# v2 (later): replace the TPM-only seal with the FROST quorum (the on-box share in the secure
# element PLUS the phone share) so the volume key is *threshold*-derived. That is what makes
# "no single box can decrypt" true; the TPM seal here is the box's local protection only.
#
# Vaultwarden hard-requires the mount, so if the volume cannot be unlocked the password
# manager does not start.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.frostGate;
  systemdCryptsetup = "${pkgs.systemd}/lib/systemd/systemd-cryptsetup";
in
{
  options.keepNode.frostGate = {
    enable = lib.mkEnableOption "FROST-gated LUKS volume for Vaultwarden data (Approach B, v1: TPM-sealed)";

    volumeDevice = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Block device backing the encrypted vault volume (e.g. /dev/vdb in the VM).";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/vaultwarden";
      description = "Mount point for the decrypted volume (Vaultwarden's data dir).";
    };

    mapperName = lib.mkOption {
      type = lib.types.str;
      default = "keep-vault";
      description = "device-mapper name for the opened LUKS volume.";
    };

    quorum = lib.mkOption {
      default = { };
      description = "FROST t-of-n threshold (wired in v2). MVP: 2-of-3 (node + phone + replica/relay).";
      type = lib.types.submodule {
        options = {
          threshold = lib.mkOption {
            type = lib.types.int;
            default = 2;
          };
          total = lib.mkOption {
            type = lib.types.int;
            default = 3;
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.volumeDevice != null;
        message = "keepNode.frostGate.enable requires keepNode.frostGate.volumeDevice.";
      }
      {
        assertion = cfg.quorum.threshold <= cfg.quorum.total && cfg.quorum.threshold >= 1;
        message = "keepNode.frostGate.quorum: need 1 <= threshold <= total.";
      }
    ];

    # The gate: provision on first boot, unlock (TPM2) on every boot. Runs before the mount.
    systemd.services.keep-node-frost-gate = {
      description = "Unseal the FROST-gated vault volume (provision + TPM2 unlock)";
      wantedBy = [ "multi-user.target" ];
      before = [ "vaultwarden.service" ];
      path = [
        pkgs.cryptsetup
        pkgs.systemd
        pkgs.e2fsprogs
        pkgs.util-linux
        pkgs.coreutils
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      # Provision (first boot) or TPM2-unlock (later boots), then mount the volume at the data
      # dir. Doing the mount here (rather than a declarative fileSystems entry) keeps the
      # unlock+mount atomic and avoids depending on a fstab mount unit for a device that only
      # appears after this service runs.
      script = ''
        set -euo pipefail
        if ! cryptsetup isLuks ${cfg.volumeDevice}; then
          # First boot: provision. v2 replaces this random key with the FROST-quorum key.
          pass="$(head -c 32 /dev/urandom | base64)"
          echo -n "$pass" | cryptsetup luksFormat -q --iter-time 1000 ${cfg.volumeDevice} -
          PASSWORD="$pass" systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 ${cfg.volumeDevice}
          echo -n "$pass" | cryptsetup luksOpen ${cfg.volumeDevice} ${cfg.mapperName} -
          mkfs.ext4 -F /dev/mapper/${cfg.mapperName}
          unset pass
        elif [ ! -e /dev/mapper/${cfg.mapperName} ]; then
          # Subsequent boots: unlock via the TPM2 token (no passphrase).
          ${systemdCryptsetup} attach ${cfg.mapperName} ${cfg.volumeDevice} - tpm2-device=auto
        fi
        mkdir -p ${cfg.dataDir}
        mountpoint -q ${cfg.dataDir} || mount /dev/mapper/${cfg.mapperName} ${cfg.dataDir}
      '';
    };

    # Vaultwarden starts only once the gate has unsealed and mounted its storage (hard dep).
    systemd.services.vaultwarden = {
      after = [ "keep-node-frost-gate.service" ];
      requires = [ "keep-node-frost-gate.service" ];
    };
  };
}
