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

  # mode = "oprf": every-boot unlock. The keep DB password and this box's OPRF share are
  # TPM-decrypted (PCR 7) by systemd into $CREDENTIALS_DIRECTORY (ramfs) before this runs; the
  # quorum reconstructs the 32-byte LUKS key, which we pipe straight into cryptsetup (it never
  # touches disk). Fail-closed: any missing/changed PCR, absent marker, or failed quorum leaves
  # the volume locked and vaultwarden down. OPRF provisioning is operator-driven (the holders
  # must be online), so a blank/unprovisioned device does NOT auto-format here (unlike v1 TPM).
  oprfGateScript = ''
    set -euo pipefail

    dev=${cfg.volumeDevice}
    mapper=${cfg.mapperName}
    label=keep-node-frost-gate

    # Probe the device directly (the blkid cache can be stale this early in boot).
    luks_type="$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)"
    luks_label="$(blkid -p -o value -s LABEL "$dev" 2>/dev/null || true)"
    pt_type="$(blkid -p -o value -s PTTYPE "$dev" 2>/dev/null || true)"

    if [ "$luks_type" = crypto_LUKS ] && [ "$luks_label" = "$label" ]; then
      # Capture the dump first: piping into `grep -q` can SIGPIPE the producer and, under
      # pipefail, misreport a healthy volume as un-provisioned.
      dump="$(cryptsetup luksDump "$dev")"
      if grep -q keep-node-oprf <<<"$dump"; then
        # OPRF-provisioned: reconstruct the LUKS key from the quorum and open. The key is the
        # only thing on the CLI's stdout; everything else goes to stderr.
        if [ ! -e /dev/mapper/"$mapper" ]; then
          KEEP_PASSWORD="$(cat "$CREDENTIALS_DIRECTORY/keep-password")" \
            ${cfg.keepPackage}/bin/keep --path ${cfg.keepDbPath} frost network oprf-unlock \
              --group ${cfg.group} --relay ${cfg.relay} --share ${toString cfg.shareIndex} \
              --volume-id ${cfg.volumeId} --epoch ${toString cfg.epoch} \
              --share-file "$CREDENTIALS_DIRECTORY/oprf-share" \
            | cryptsetup open --key-file - --keyfile-size 32 "$dev" "$mapper"
        fi
      else
        # Our LUKS label but no OPRF completion marker: never provisioned for OPRF (or an
        # interrupted provision). Provisioning needs the phone + replica online, so it is
        # operator-driven; fail closed rather than guessing.
        echo "frost-gate(oprf): $dev carries our label but no keep-node-oprf marker; run 'systemctl start keep-node-frost-provision' with the holders online." >&2
        exit 1
      fi
    elif [ -n "$luks_type" ] || [ -n "$pt_type" ]; then
      # Device already holds data we did not create. Refuse rather than reformat (same
      # wrong-device guard as v1).
      echo "frost-gate(oprf): $dev already holds data (type='$luks_type' pttype='$pt_type') but is not a keep-node volume; refusing to touch it" >&2
      exit 1
    else
      # Blank device: OPRF provisioning is operator-driven, not auto-first-boot.
      echo "frost-gate(oprf): $dev is blank; OPRF provisioning needs the phone + replica online. Run 'systemctl start keep-node-frost-provision'." >&2
      exit 1
    fi

    mkdir -p ${cfg.dataDir}
    mountpoint -q ${cfg.dataDir} || mount /dev/mapper/"$mapper" ${cfg.dataDir}
  '';

  # Operator-driven one-time setup (NOT wantedBy boot). Needs KEEP_PASSWORD in the environment
  # and the OPRF holders online. Generates + distributes the OPRF key, seals this box's share and
  # the keep DB password to the TPM (PCR 7) as systemd-creds blobs, then LUKS-formats the volume
  # with the OPRF-derived key. All tmp secrets live on a private tmpfs and are shredded on exit.
  oprfProvisionScript = ''
    set -euo pipefail

    dev=${cfg.volumeDevice}
    mapper=${cfg.mapperName}
    label=keep-node-frost-gate

    : "''${KEEP_PASSWORD:?set KEEP_PASSWORD in the environment before provisioning}"

    tmpdir="$(mktemp -d)"
    keyfile="$tmpdir/luks.key"
    sharefile="$tmpdir/oprf.share"
    cleanup() {
      set +e
      [ -e "$keyfile" ] && shred -u "$keyfile"
      [ -e "$sharefile" ] && shred -u "$sharefile"
      rm -rf "$tmpdir"
    }
    trap cleanup EXIT

    # Wrong-device guard: refuse to clobber a device that already holds data we did not create,
    # and refuse to re-provision an already-OPRF volume (that would destroy its data).
    luks_type="$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)"
    luks_label="$(blkid -p -o value -s LABEL "$dev" 2>/dev/null || true)"
    pt_type="$(blkid -p -o value -s PTTYPE "$dev" 2>/dev/null || true)"
    if [ "$luks_type" = crypto_LUKS ] && [ "$luks_label" = "$label" ]; then
      if cryptsetup luksDump "$dev" | grep -q keep-node-oprf; then
        echo "frost-gate(oprf): $dev is already OPRF-provisioned; refusing to re-provision (would destroy data)." >&2
        exit 1
      fi
    elif [ -n "$luks_type" ] || [ -n "$pt_type" ]; then
      echo "frost-gate(oprf): $dev already holds data (type='$luks_type' pttype='$pt_type'); refusing to reformat." >&2
      exit 1
    fi

    # 1. Generate + distribute the OPRF key; emit the 32-byte LUKS key and this box's 64-byte
    #    share to the private tmpfs (the CLI writes them 0600 and only on successful distribution).
    KEEP_PASSWORD="$KEEP_PASSWORD" \
      ${cfg.keepPackage}/bin/keep --path ${cfg.keepDbPath} frost network oprf-provision \
        --group ${cfg.group} --relay ${cfg.relay} --share ${toString cfg.shareIndex} \
        --volume-id ${cfg.volumeId} --epoch ${toString cfg.epoch} \
        --threshold ${toString cfg.quorum.threshold} --total ${toString cfg.quorum.total} \
        --key-out "$keyfile" --share-out "$sharefile"

    # 2. Seal this box's OPRF share and the keep DB password to the TPM (PCR 7). At boot systemd
    #    re-decrypts these into the gate unit's $CREDENTIALS_DIRECTORY; a PCR change fails closed.
    install -d -m 0700 "$(dirname ${cfg.oprfShareCred})"
    install -d -m 0700 "$(dirname ${cfg.keepPasswordCred})"
    systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 --name=oprf-share "$sharefile" ${cfg.oprfShareCred}
    printf '%s' "$KEEP_PASSWORD" \
      | systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 --name=keep-password - ${cfg.keepPasswordCred}

    # 3. Lay down the LUKS volume keyed by the OPRF-derived 32-byte LUKS key, open it, mkfs.
    cryptsetup luksFormat -q --label "$label" --key-file "$keyfile" --keyfile-size 32 "$dev"
    cryptsetup open --key-file "$keyfile" --keyfile-size 32 "$dev" "$mapper"
    mkfs.ext4 -F /dev/mapper/"$mapper"

    # 4. Completion marker (distinct from v1's keep-node-provisioned): the gate reads this to know
    #    the volume is OPRF-provisioned. Re-set --label in the same call (--subsystem alone clears
    #    the label, which the wrong-device guard relies on).
    cryptsetup config "$dev" --label "$label" --subsystem keep-node-oprf

    echo "frost-gate(oprf): provisioned $dev. Reboot to unlock via the quorum." >&2
  '';
in
{
  options.keepNode.frostGate = {
    enable = lib.mkEnableOption "FROST-gated LUKS volume for Vaultwarden data (Approach B, v1: TPM-sealed)";

    mode = lib.mkOption {
      type = lib.types.enum [
        "tpm"
        "oprf"
      ];
      default = "tpm";
      description = ''
        Unlock backend. "tpm" (v1): the LUKS key is sealed to this box's TPM (PCR 7), so a
        powered-on box unlocks itself unattended. "oprf" (v2): the LUKS key is reconstructed at
        boot from a 2-of-3 threshold-OPRF quorum (this box's TPM-sealed OPRF share PLUS the
        remote holders), so a powered-on box alone cannot release the key.
      '';
    };

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

    # --- mode = "oprf" options (the v2 threshold-OPRF unlock) ---

    keepPackage = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "The keep-cli package (binary `keep`), built from privkeyio/keep. Drives the OPRF quorum unlock/provision (mode = \"oprf\").";
    };

    keepDbPath = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "keep data dir (the keep CLI's --path) holding this box's FROST share. Required for mode = \"oprf\".";
    };

    group = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "FROST group npub. Required for mode = \"oprf\".";
    };

    relay = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Coordination relay URL for the OPRF quorum. Required for mode = \"oprf\".";
    };

    shareIndex = lib.mkOption {
      type = lib.types.int;
      default = 1;
      description = "This box's FROST share index (the local u16 share id) used in the OPRF quorum.";
    };

    volumeId = lib.mkOption {
      type = lib.types.str;
      default = "vault0";
      description = "LUKS volume identifier passed to the OPRF unlock/provision (--volume-id).";
    };

    epoch = lib.mkOption {
      type = lib.types.int;
      default = 1;
      description = "OPRF key epoch (--epoch).";
    };

    keepPasswordCred = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path to the systemd-creds-encrypted (TPM2/PCR 7) blob holding the keep DB unlock password.
        Decrypted into the unit's $CREDENTIALS_DIRECTORY (ramfs) at start; if a PCR changed the
        decryption fails and the gate fails closed. Required for mode = "oprf".
      '';
    };

    oprfShareCred = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path to the systemd-creds-encrypted (TPM2/PCR 7) blob holding this box's 64-byte OPRF
        share. Decrypted into $CREDENTIALS_DIRECTORY at start (never written to persistent disk in
        the clear). Required for mode = "oprf".
      '';
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
      {
        assertion =
          cfg.mode != "oprf"
          || (
            cfg.keepPackage != null
            && cfg.group != null
            && cfg.relay != null
            && cfg.keepPasswordCred != null
            && cfg.oprfShareCred != null
            && cfg.keepDbPath != null
          );
        message = "keepNode.frostGate.mode = \"oprf\" requires keepPackage, group, relay, keepDbPath, keepPasswordCred, and oprfShareCred.";
      }
    ];

    # The gate. mode = "tpm" (v1): provision on first boot, TPM2-unlock every boot. mode = "oprf"
    # (v2): every-boot unlock from the threshold-OPRF quorum (provisioning is a separate
    # operator-driven oneshot). Either way it runs before the mount and before vaultwarden.
    systemd.services.keep-node-frost-gate = {
      description =
        if cfg.mode == "oprf" then
          "Unlock the FROST-gated vault volume (threshold-OPRF quorum)"
        else
          "Unseal the FROST-gated vault volume (provision + TPM2 unlock)";
      wantedBy = [ "multi-user.target" ];
      path =
        if cfg.mode == "oprf" then
          [
            pkgs.cryptsetup
            pkgs.systemd
            pkgs.util-linux
            pkgs.coreutils
            cfg.keepPackage
          ]
        else
          [
            pkgs.cryptsetup
            pkgs.systemd
            pkgs.e2fsprogs
            pkgs.util-linux
            pkgs.coreutils
          ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      }
      // lib.optionalAttrs (cfg.mode == "oprf") {
        # systemd TPM-decrypts these into $CREDENTIALS_DIRECTORY (ramfs) at unit start. If a PCR
        # changed, decryption fails, the unit fails, and the volume stays locked (fail-closed).
        LoadCredentialEncrypted = [
          "keep-password:${toString cfg.keepPasswordCred}"
          "oprf-share:${toString cfg.oprfShareCred}"
        ];
      };
      # Provision (first boot) or TPM2-unlock (later boots), then mount the volume at the data
      # dir. Doing the mount here (rather than a declarative fileSystems entry) keeps the
      # unlock+mount atomic and avoids depending on a fstab mount unit for a device that only
      # appears after this service runs.
      script =
        if cfg.mode == "oprf" then
          oprfGateScript
        else
          ''
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

    # Operator-driven OPRF provisioning (mode = "oprf" only). NOT wantedBy boot: the operator
    # runs `systemctl start keep-node-frost-provision` with KEEP_PASSWORD in the environment and
    # the OPRF holders (phone + replica) online. It distributes the OPRF key, seals this box's
    # share + the keep DB password to the TPM, and formats the volume.
    systemd.services.keep-node-frost-provision = lib.mkIf (cfg.mode == "oprf") {
      description = "Provision the FROST-gated vault volume (threshold-OPRF, operator-driven)";
      path = [
        pkgs.cryptsetup
        pkgs.systemd
        pkgs.e2fsprogs
        pkgs.util-linux
        pkgs.coreutils
        cfg.keepPackage
      ];
      serviceConfig = {
        Type = "oneshot";
        # Private tmpfs for the transient LUKS key + OPRF share before they are sealed/shredded.
        PrivateTmp = true;
      };
      script = oprfProvisionScript;
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
