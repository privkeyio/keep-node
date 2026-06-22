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
# Scope/limits of v1 (intentional, not gaps to "fix" here):
#   * Auto-unlocks at boot with no PIN: the node must come back unattended after a power blip,
#     so this layer is full-disk-encryption at rest only. Making power-on insufficient to
#     decrypt is v2's job (the FROST quorum needs the phone share, so a powered-on box alone
#     cannot release the key).
#   * Bound to PCR 7 only: PCR 7 binding is weak until real measured boot exists. The proper
#     measured-boot PCR policy lands with the Lanzaboote work, not here.
#   * No local recovery keyslot: the random bootstrap passphrase is discarded after enrollment
#     on purpose. Writing a LUKS-unlocking recovery key to the (unencrypted) root would gut the
#     "steal the box, get nothing" premise. Recovery is the node replicas (other nodes hold the
#     data) and the v2 FROST quorum (the phone share), never a local secret at rest. The cost:
#     a PCR 7 change (firmware/Secure Boot/board swap) makes this node's volume unreadable until
#     re-provisioned from a replica. Fail-closed by design.
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

        dev=${cfg.volumeDevice}
        mapper=${cfg.mapperName}
        label=keep-node-frost-gate

        # Probe the device directly (don't trust the blkid cache, which can be stale this
        # early in boot). Our volume is a LUKS container carrying our label. PTTYPE catches a
        # disk that holds only a partition table (no whole-device signature) so the
        # wrong-device guard below still refuses it.
        luks_type="$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)"
        luks_label="$(blkid -p -o value -s LABEL "$dev" 2>/dev/null || true)"
        pt_type="$(blkid -p -o value -s PTTYPE "$dev" 2>/dev/null || true)"

        # First boot: format + TPM2-enroll + mkfs, atomically. On ANY in-script failure,
        # wipe our partial work so the next boot retries from a blank device instead of
        # bricking on a half-provisioned volume (e.g. enroll fails after luksFormat). The
        # random bootstrap key is discarded; no recovery keyslot is kept (see header).
        provision() {
          cleanup() {
            set +e
            [ -e /dev/mapper/"$mapper" ] && cryptsetup luksClose "$mapper"
            wipefs -a "$dev"
          }
          trap cleanup ERR
          pass="$(head -c 32 /dev/urandom | base64)"
          echo -n "$pass" | cryptsetup luksFormat -q --label "$label" --iter-time 1000 "$dev" -
          # Enroll the TPM2 token and drop the bootstrap passphrase slot in one authenticated
          # step: PASSWORD unlocks for the enrollment, then the password slot is wiped, leaving
          # TPM2 as the only keyslot (the documented v1 posture). A standalone wipe would have
          # no passphrase to authenticate with and would block on a prompt in this no-tty unit.
          PASSWORD="$pass" systemd-cryptenroll --wipe-slot=password --tpm2-device=auto --tpm2-pcrs=7 "$dev"
          unset pass
          # Open via the TPM2 token (now the only slot) and lay down the filesystem.
          ${systemdCryptsetup} attach "$mapper" "$dev" - tpm2-device=auto
          mkfs.ext4 -F /dev/mapper/"$mapper"
          # Completion marker: stamp the LUKS2 subsystem field now that a filesystem exists. The
          # recovery branch reads it to distinguish "interrupted first provision, no data, safe to
          # wipe" from "fully provisioned, may hold data, must fail closed" if the TPM2 token is
          # ever lost. It lives in our own header (cleared by wipefs on re-provision), carries no
          # secret, and is the last step so its presence implies mkfs completed. Re-set --label in
          # the same call: `cryptsetup config --subsystem` alone clears the existing label, which
          # would break the wrong-device guard and recovery detection on the next boot.
          cryptsetup config "$dev" --label "$label" --subsystem keep-node-provisioned
          trap - ERR
        }

        if [ "$luks_type" = crypto_LUKS ] && [ "$luks_label" = "$label" ]; then
          # Capture the listings first: piping straight into `grep -q` can SIGPIPE the producer
          # and, under pipefail, misreport a healthy volume as un-enrolled / un-marked.
          enrolled="$(systemd-cryptenroll "$dev")"
          dump="$(cryptsetup luksDump "$dev")"
          if grep -q tpm2 <<<"$enrolled"; then
            # Provisioned: unlock via the TPM2 token (no passphrase, PCR 7). Fails closed if
            # the TPM refuses (e.g. PCR change); vaultwarden then stays down, by design.
            [ -e /dev/mapper/"$mapper" ] || ${systemdCryptsetup} attach "$mapper" "$dev" - tpm2-device=auto
          elif grep -q keep-node-provisioned <<<"$dump"; then
            # Our label, no TPM2 token, but the completion marker is set: provisioning finished, so
            # this volume may hold real data, and its only keyslot is gone (a PCR change, TPM clear,
            # or a removed token). The data is unrecoverable on-box; per the fail-closed design
            # (header: recover from a replica, never keep a local secret) we MUST NOT reformat it.
            # Stay down so an operator re-provisions from a replica instead of silently wiping data.
            echo "frost-gate: $dev was provisioned but its TPM2 token is gone; refusing to reformat. Recover from a replica." >&2
            exit 1
          else
            # Our label, no TPM2 token, no completion marker: a first-boot provision interrupted
            # before mkfs (e.g. power loss). No filesystem was ever written; reclaim and redo it.
            wipefs -a "$dev"
            provision
          fi
        elif [ -n "$luks_type" ] || [ -n "$pt_type" ]; then
          # Device already holds data we did not create (a filesystem/crypto signature or a
          # partition table). Refuse rather than reformat; this guards a misconfigured
          # volumeDevice from silently destroying the wrong disk.
          echo "frost-gate: $dev already holds data (type='$luks_type' pttype='$pt_type') but is not a keep-node volume; refusing to reformat" >&2
          exit 1
        else
          # Blank device: first boot.
          provision
        fi

        mkdir -p ${cfg.dataDir}
        mountpoint -q ${cfg.dataDir} || mount /dev/mapper/"$mapper" ${cfg.dataDir}
      '';
    };

    # Vaultwarden starts only once the gate has unsealed and mounted its storage (hard dep).
    # Only wire this when vaultwarden is actually enabled, so enabling the gate alone never
    # materializes a phantom vaultwarden.service.
    systemd.services.vaultwarden = lib.mkIf config.services.vaultwarden.enable {
      after = [ "keep-node-frost-gate.service" ];
      requires = [ "keep-node-frost-gate.service" ];
    };
  };
}
