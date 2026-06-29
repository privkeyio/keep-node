# FROST threshold volume gate.
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
#   * No local recovery keyslot by default: the random bootstrap passphrase is discarded after
#     enrollment on purpose. Writing a LUKS-unlocking recovery key to the (unencrypted) root would
#     gut the "steal the box, get nothing" premise. Recovery is the node replicas (other nodes hold
#     the data) and the v2 FROST quorum (the phone share), never a local secret at rest. The cost:
#     a PCR 7 change (firmware/Secure Boot/board swap) makes this node's volume unreadable until
#     re-provisioned from a replica. Fail-closed by design. (The opt-in `recoveryKeyFile` option
#     deliberately relaxes this for a single-node deploy with no replica yet; see that option.)
#
# Vaultwarden hard-requires the mount, so if the volume cannot be unlocked the password
# manager does not start.
{
  config,
  lib,
  pkgs,
  utils,
  ...
}:
let
  cfg = config.keepNode.frostGate;
  systemdCryptsetup = "${pkgs.systemd}/lib/systemd/systemd-cryptsetup";

  # The systemd .device unit for the backing volume (empty when unset). The gate orders after
  # and requires it so the probe never races a device that has not yet appeared/settled.
  deviceUnits = lib.optionals (cfg.volumeDevice != null) [
    "${utils.escapeSystemdPath cfg.volumeDevice}.device"
  ];

  # The LUKS2 label stamped on our container; the wrong-device guards key off it.
  label = "keep-node-frost-gate";

  # Probe a block device directly (the blkid cache can be stale this early in boot). Sets
  # luks_type / luks_label / pt_type for the caller's wrong-device guard. $dev must be set.
  # PTTYPE catches a disk that holds only a partition table (no whole-device signature).
  probeBlock = ''
    luks_type="$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)"
    luks_label="$(blkid -p -o value -s LABEL "$dev" 2>/dev/null || true)"
    pt_type="$(blkid -p -o value -s PTTYPE "$dev" 2>/dev/null || true)"
  '';

  # Ensure dataDir exists and our decrypted mapper is the thing mounted there. If dataDir
  # already has some OTHER source mounted, fail closed rather than write plaintext into a
  # location backed by the wrong (possibly unencrypted) device. $mapper must be set.
  mountTail = ''
    dd=${lib.escapeShellArg cfg.dataDir}
    mkdir -p "$dd"
    if mountpoint -q "$dd"; then
      cur="$(findmnt -no SOURCE "$dd" || true)"
      if [ "$cur" != "/dev/mapper/$mapper" ]; then
        echo "frost-gate: $dd already has '$cur' mounted (expected /dev/mapper/$mapper); refusing to proceed" >&2
        exit 1
      fi
    else
      mount /dev/mapper/"$mapper" "$dd"
    fi
  '';

  # mode = "oprf": every-boot unlock. The keep DB password and this box's OPRF share are
  # TPM-decrypted (PCR 7) by systemd into $CREDENTIALS_DIRECTORY (ramfs) before this runs; the
  # quorum reconstructs the 32-byte LUKS key into a RAM-only file ($RUNTIME_DIRECTORY tmpfs) that
  # feeds cryptsetup (it never touches persistent disk). Fail-closed: any missing/changed PCR,
  # absent marker, or failed quorum leaves the volume locked and vaultwarden down. OPRF
  # provisioning is operator-driven (the holders must be online), so a blank/unprovisioned device
  # does NOT auto-format here (unlike v1 TPM).
  # Deployment requirement (M1): the "no single box can decrypt" property holds only if the
  # external keep relay authenticates + throttles unlock requests and the box is bound by a real
  # measured-boot PCR policy. Both are external to this repo (relay infra + Lanzaboote).
  oprfGateScript = ''
    set -euo pipefail

    dev=${lib.escapeShellArg cfg.volumeDevice}
    mapper=${lib.escapeShellArg cfg.mapperName}
    label=${lib.escapeShellArg label}

    ${probeBlock}

    if [ "$luks_type" = crypto_LUKS ] && [ "$luks_label" = "$label" ]; then
      # Capture the dump first: piping into `grep -q` can SIGPIPE the producer and, under
      # pipefail, misreport a healthy volume as un-provisioned.
      dump="$(cryptsetup luksDump "$dev")"
      if grep -q keep-node-oprf <<<"$dump"; then
        # OPRF-provisioned: reconstruct the LUKS key from the quorum and open. The key is the
        # only thing on the CLI's stdout; everything else goes to stderr.
        if [ ! -e /dev/mapper/"$mapper" ]; then
          # Capture the 32-byte key to a RAM-only file (RuntimeDirectory is tmpfs under /run)
          # instead of piping straight into cryptsetup: cryptsetup reads only 32 bytes then
          # closes the pipe, and any trailing write by `keep` would take SIGPIPE which, under
          # pipefail, turns a correct unlock into a unit failure (boot fails closed). The key
          # never touches persistent disk and is removed immediately after open.
          keyf="$RUNTIME_DIRECTORY/luks.key"
          trap 'rm -f "$keyf"' EXIT
          # On a stop-timeout SIGTERM (or INT) scrub the key, then actually terminate rather
          # than resuming: the explicit exit fires the EXIT trap too (idempotent rm -f).
          trap 'rm -f "$keyf"; exit 1' TERM INT
          ( umask 077
            KEEP_PASSWORD="$(cat "$CREDENTIALS_DIRECTORY/keep-password")" \
              ${cfg.keepPackage}/bin/keep --path ${lib.escapeShellArg cfg.keepDbPath} frost network oprf-unlock \
                --group ${lib.escapeShellArg cfg.group} --relay ${lib.escapeShellArg cfg.relay} --share ${toString cfg.shareIndex} \
                --volume-id ${lib.escapeShellArg cfg.volumeId} --epoch ${toString cfg.epoch} \
                --tpm-tcti ${lib.escapeShellArg cfg.tpmTcti} \
                --share-file "$CREDENTIALS_DIRECTORY/oprf-share" \
                > "$keyf" )
          cryptsetup open --key-file "$keyf" --keyfile-size 32 "$dev" "$mapper"
          rm -f "$keyf"
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

    ${mountTail}
  '';

  # mode = "tpm" (v1): provision on first boot (format + TPM2-enroll + mkfs), then TPM2-unlock on
  # every boot, before the mount. Counterpart to oprfGateScript above; both end in mountTail.
  tpmGateScript = ''
    set -euo pipefail

    dev=${lib.escapeShellArg cfg.volumeDevice}
    mapper=${lib.escapeShellArg cfg.mapperName}
    label=${lib.escapeShellArg label}

    ${probeBlock}

    # First boot: format + TPM2-enroll + mkfs, atomically. On ANY in-script failure,
    # wipe our partial work so the next boot retries from a blank device instead of
    # bricking on a half-provisioned volume (e.g. enroll fails after luksFormat). The
    # random bootstrap key is discarded; no recovery keyslot is kept (see header).
    provision() {
      cleanup() {
        set +e
        [ -e /dev/mapper/"$mapper" ] && cryptsetup luksClose "$mapper"
        # Verify the wipe actually cleared our signature. A swallowed wipefs failure (device
        # busy / transient I/O) would leave the device with our label + TPM2 token + no
        # filesystem, masquerading as provisioned; retry, then warn loudly. The next boot
        # recovers it regardless: an absent completion marker forces re-provision (not a silent
        # "clean" state), so a failed wipe cannot pose as a healthy or a blank volume.
        for _ in 1 2 3; do
          wipefs -a "$dev" 2>/dev/null
          blkid -p "$dev" >/dev/null 2>&1 || return 0
          sleep 1
        done
        echo "frost-gate: WARNING could not wipe $dev during rollback; a signature persists. The next boot re-provisions it (no completion marker)." >&2
      }
      trap cleanup ERR
      pass="$(head -c 32 /dev/urandom | base64)"
      echo -n "$pass" | cryptsetup luksFormat -q --label "$label" --iter-time 1000 "$dev" -
      ${lib.optionalString (cfg.recoveryKeyFile != null) ''
        # Opt-in recovery keyslot (keepNode.frostGate.recoveryKeyFile). Enroll a high-entropy
        # recovery key, authorized by the bootstrap passphrase, BEFORE that slot is wiped, and
        # write the key to the operator's path (0600). This DELIBERATELY weakens the "steal the
        # box, get nothing" posture: whoever holds this key can unlock the volume without the
        # TPM, so MOVE IT OFFLINE and delete the on-disk copy. Default (null) keeps no local
        # secret at rest; this exists so a single-node deploy can survive a PCR change before
        # replica recovery (M1) lands.
        rkfile=${lib.escapeShellArg cfg.recoveryKeyFile}
        # Create the parent dir if absent WITHOUT forcing a mode on an existing one: `install -d
        # -m 0700` would re-chmod a shared dir (even /etc or /) to 0700 and break the system. The
        # key's protection comes from the explicit 0600 on the FILE, set before the secret lands
        # (umask alone only covers a freshly created file; an overwrite would keep a looser mode).
        mkdir -p "$(dirname "$rkfile")"
        rk="$(PASSWORD="$pass" systemd-cryptenroll --recovery-key "$dev")"
        ( umask 077; : > "$rkfile" )
        chmod 0600 "$rkfile"
        printf '%s\n' "$rk" > "$rkfile"
        unset rk
        echo "frost-gate: wrote a LUKS recovery key to $rkfile (0600). MOVE IT OFFLINE and delete the on-disk copy; it unlocks the vault without the TPM." >&2
      ''}
      # Enroll the TPM2 token and drop the bootstrap passphrase slot in one authenticated
      # step: PASSWORD unlocks for the enrollment, then the password slot is wiped, leaving
      # TPM2 (plus any opt-in recovery slot) as the keyslots. A standalone wipe would have
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
      if grep -q keep-node-provisioned <<<"$dump"; then
        # Provisioning ran to completion (the marker is written last, after mkfs), so a
        # filesystem exists and the volume may hold real data.
        if grep -q tpm2 <<<"$enrolled"; then
          # Unlock via the TPM2 token (no passphrase, PCR 7). Fails closed if the TPM refuses
          # (e.g. PCR change); vaultwarden then stays down, by design.
          [ -e /dev/mapper/"$mapper" ] || ${systemdCryptsetup} attach "$mapper" "$dev" - tpm2-device=auto
        else
          # Marked complete but the TPM2 token is gone (PCR change, TPM clear, or a removed
          # token): the only auto keyslot is lost and the data is unrecoverable on-box. Per the
          # fail-closed design (recover from a replica, never keep a local secret) we MUST NOT
          # reformat it. Stay down so an operator recovers from a replica (or with an opt-in
          # recovery key) instead of silently wiping data.
          echo "frost-gate: $dev was provisioned but its TPM2 token is gone; refusing to reformat. Recover from a replica or with the recovery key." >&2
          exit 1
        fi
      elif grep -q keep-node-oprf <<<"$dump"; then
        # Our label, no keep-node-provisioned marker, but the OPRF subsystem marker IS set: this is
        # an OPRF-provisioned volume (mode = "oprf") carrying real data under an OPRF-derived
        # keyslot this tpm-mode gate cannot reformat without destroying it. A mode switch from
        # "oprf" to "tpm" on an existing volume must fail closed, NOT fall through to the reclaim
        # wipe below. (oprfProvisionScript guards the reverse case symmetrically.)
        echo "frost-gate: $dev is OPRF-provisioned (mode=\"oprf\") but this gate is mode=\"tpm\"; refusing to reformat. Recover from a replica or set mode = \"oprf\"." >&2
        exit 1
      else
        # Our label but NO completion marker: a first-boot provision was interrupted before mkfs
        # (e.g. power loss), possibly AFTER the TPM2 token was enrolled. The marker is the sole
        # authority that a filesystem exists, so its absence means no data was ever written, even
        # if a token is present. The old token-first check would have taken the unlock path here,
        # attached an empty volume, then failed to mount it on every boot: a permanent brick.
        # Reclaim and redo from a blank device instead.
        [ -e /dev/mapper/"$mapper" ] && cryptsetup luksClose "$mapper"
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
      # Blank device: first boot. Positively confirm the device is READABLE before the
      # destructive provision: probeBlock's blkid uses `2>/dev/null || true`, so a transient read
      # failure (EBUSY, a slow/late device, a passing I/O error) yields the same empty signatures
      # as a genuinely blank device. Reformatting a momentarily-unreadable PROVISIONED volume
      # would destroy the vault, so require a successful read of the first sectors first (try
      # O_DIRECT, then buffered, since some backings reject O_DIRECT).
      if ! dd if="$dev" of=/dev/null bs=1M count=4 iflag=direct status=none 2>/dev/null \
         && ! dd if="$dev" of=/dev/null bs=1M count=4 status=none 2>/dev/null; then
        echo "frost-gate: $dev reports no signatures but is not readable; refusing to provision (a transient read failure on a provisioned device must not trigger a reformat)." >&2
        exit 1
      fi
      provision
    fi

    ${mountTail}
  '';

  # Operator-driven one-time setup (NOT wantedBy boot). Needs KEEP_PASSWORD in the environment
  # and the OPRF holders online. Generates + distributes the OPRF key, LUKS-formats the volume
  # with the OPRF-derived key, then seals this box's share and the keep DB password to the TPM
  # (PCR 7) as systemd-creds blobs. The transient LUKS key + share live on the unit's PrivateTmp
  # tmpfs: protection comes from that tmpfs being RAM-only and torn down when the unit exits, NOT
  # from secure erase (shred cannot guarantee erasure on tmpfs / copy-on-write backing).
  oprfProvisionScript = ''
    set -euo pipefail

    dev=${lib.escapeShellArg cfg.volumeDevice}
    mapper=${lib.escapeShellArg cfg.mapperName}
    label=${lib.escapeShellArg label}
    shareCred=${lib.escapeShellArg cfg.oprfShareCred}
    passCred=${lib.escapeShellArg cfg.keepPasswordCred}

    : "''${KEEP_PASSWORD:?set KEEP_PASSWORD in the environment before provisioning (see the unit comments)}"

    tmpdir="$(mktemp -d)"
    keyfile="$tmpdir/luks.key"
    sharefile="$tmpdir/oprf.share"

    # Failure rollback: undo partial on-disk work so a retry starts from a clean device. Removes
    # any half-written sealed creds, closes the mapper, and wipes the (possibly half-formatted)
    # LUKS header. The OPRF key already distributed to the holders in step 1 is inherent to the
    # quorum and cannot be recalled here; a retry re-runs provisioning against the same epoch.
    provisioned=0
    rollback() {
      set +e
      [ "$provisioned" = 1 ] && return 0
      rm -f "$shareCred" "$passCred"
      [ -e /dev/mapper/"$mapper" ] && cryptsetup close "$mapper"
      wipefs -a "$dev" 2>/dev/null
    }
    # tmpfs teardown happens on EXIT regardless of outcome; also close the mapper so the next
    # boot's gate (not this unit) opens it via the quorum.
    cleanup() {
      set +e
      [ -e /dev/mapper/"$mapper" ] && cryptsetup close "$mapper"
      rm -f "$keyfile" "$sharefile"
      rm -rf "$tmpdir"
    }
    trap rollback ERR
    trap cleanup EXIT

    # Wrong-device guard: refuse to clobber a device that already holds data we did not create,
    # and refuse to re-provision an already-OPRF volume (that would destroy its data).
    ${probeBlock}
    if [ "$luks_type" = crypto_LUKS ] && [ "$luks_label" = "$label" ]; then
      # Capture the dump first: piping into `grep -q` can SIGPIPE the producer and, under
      # pipefail, misreport an already-OPRF volume as un-provisioned and reformat it. Use
      # `|| true` so a transient luksDump failure cannot trip the rollback ERR trap (which
      # would wipefs the very volume this guard protects).
      dump="$(cryptsetup luksDump "$dev" || true)"
      if grep -q keep-node-oprf <<<"$dump"; then
        echo "frost-gate(oprf): $dev is already OPRF-provisioned; refusing to re-provision (would destroy data)." >&2
        exit 1
      elif grep -q keep-node-provisioned <<<"$dump"; then
        echo "frost-gate(oprf): $dev is already provisioned as a v1/tpm volume; refusing to reformat (would destroy data)." >&2
        exit 1
      fi
    elif [ -n "$luks_type" ] || [ -n "$pt_type" ]; then
      echo "frost-gate(oprf): $dev already holds data (type='$luks_type' pttype='$pt_type'); refusing to reformat." >&2
      exit 1
    fi

    # 1. Generate + distribute the OPRF key; emit the 32-byte LUKS key and this box's 64-byte
    #    share to the PrivateTmp tmpfs (the CLI writes them 0600 and only on successful distribution).
    KEEP_PASSWORD="$KEEP_PASSWORD" \
      ${cfg.keepPackage}/bin/keep --path ${lib.escapeShellArg cfg.keepDbPath} frost network oprf-provision \
        --group ${lib.escapeShellArg cfg.group} --relay ${lib.escapeShellArg cfg.relay} --share ${toString cfg.shareIndex} \
        --volume-id ${lib.escapeShellArg cfg.volumeId} --epoch ${toString cfg.epoch} \
        --threshold ${toString cfg.quorum.threshold} --total ${toString cfg.quorum.total} \
        --tpm-tcti ${lib.escapeShellArg cfg.tpmTcti} \
        --key-out "$keyfile" --share-out "$sharefile"

    # 2. Lay down the LUKS volume keyed by the OPRF-derived 32-byte LUKS key, open it, mkfs. Do
    #    this BEFORE sealing creds so a format/mkfs failure can't leave orphaned sealed creds for
    #    a volume that never formed (the rollback above wipes the header on any error).
    cryptsetup luksFormat -q --label "$label" --key-file "$keyfile" --keyfile-size 32 "$dev"
    cryptsetup open --key-file "$keyfile" --keyfile-size 32 "$dev" "$mapper"
    mkfs.ext4 -F /dev/mapper/"$mapper"

    # 3. Seal this box's OPRF share and the keep DB password to the TPM (PCR 7). At boot systemd
    #    re-decrypts these into the gate unit's $CREDENTIALS_DIRECTORY; a PCR change fails closed.
    install -d -m 0700 "$(dirname "$shareCred")"
    install -d -m 0700 "$(dirname "$passCred")"
    systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 --name=oprf-share "$sharefile" "$shareCred"
    printf '%s' "$KEEP_PASSWORD" \
      | systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7 --name=keep-password - "$passCred"

    # 4. Completion marker (distinct from v1's keep-node-provisioned): the gate reads this to know
    #    the volume is OPRF-provisioned. Re-set --label in the same call (--subsystem alone clears
    #    the label, which the wrong-device guard relies on). Last step: its presence implies the
    #    volume formed AND the creds sealed, so the gate can trust it.
    cryptsetup config "$dev" --label "$label" --subsystem keep-node-oprf
    provisioned=1

    echo "frost-gate(oprf): provisioned $dev. Reboot to unlock via the quorum." >&2
  '';
in
{
  options.keepNode.frostGate = {
    enable = lib.mkEnableOption "FROST-gated LUKS volume for Vaultwarden data (v1: TPM-sealed)";

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
        remote holders).

        SECURITY: "oprf" is NOT yet a meaningful threshold gate on its own. The box's OPRF share
        is sealed only to PCR 7 (Secure Boot state, trivially reproducible), so a stolen or
        rebooted box gets its own share back; if a remote holder then auto-answers, that box alone
        reaches the 2-of-3 threshold without the phone. The "a powered-on box cannot self-decrypt"
        property holds ONLY once the M1 deployment requirements are met: the holders/relay
        authenticate, throttle, and gate (do not auto-approve) unlock requests, AND the box is
        sealed under a real measured-boot PCR policy (e.g. Lanzaboote / PCR 11), not bare PCR 7.
        Both are external to this module. Until both are in place, treat "oprf" as full-disk
        encryption with a TPM-released key, no stronger than "tpm".
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

    recoveryKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        mode = "tpm" only. If set, first-boot provisioning enrolls an extra LUKS recovery
        keyslot and writes its high-entropy recovery key to this path (0600) for the operator to
        move OFFLINE and then delete. This is an opt-in escape hatch so a single-node deploy can
        survive a PCR 7 change (firmware/Secure Boot/board swap) before replica recovery exists;
        it DELIBERATELY weakens the "steal the box, get nothing" posture, since anyone holding the
        key can unlock the volume without the TPM. Leave null (the default) to keep no local
        secret at rest and recover only from a replica.
      '';
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

    tpmTcti = lib.mkOption {
      type = lib.types.str;
      default = "device:/dev/tpmrm0";
      description = ''
        TCTI for this box's TPM, passed as --tpm-tcti to oprf-provision and oprf-unlock so the box
        attaches a measured-boot quote to its requests. Required for mode = "oprf": holders gate
        enrollment and evaluation on a VERIFIED dealer, so a box that does not attest is refused
        and the boot unlock fails closed. The boot-time gate and the provision unit must also have
        access to this TPM device (see the runbook on keep-node-frost-provision).
      '';
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

    keepPasswordEnvFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Optional path to a 0400 systemd EnvironmentFile (containing `KEEP_PASSWORD=...`) that
        feeds the keep DB password to the operator-driven provision unit (mode = "oprf"). If set,
        it is wired as the provision unit's EnvironmentFile. If null, deliver the password ad hoc,
        e.g. `systemd-run -E KEEP_PASSWORD --pipe --wait --service-type=oneshot keep ...` against
        the provision script. Do NOT use `systemctl set-environment` to pass it: that leaks the
        password into the global systemd manager environment.
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
        assertion = cfg.recoveryKeyFile == null || cfg.mode == "tpm";
        message = "keepNode.frostGate.recoveryKeyFile is only honored in mode = \"tpm\" (it enrolls a LUKS recovery keyslot during first-boot provisioning); in mode = \"oprf\" it is silently ignored.";
      }
      {
        assertion = cfg.mode != "oprf" || cfg.quorum.threshold >= 2;
        message = "keepNode.frostGate.mode = \"oprf\" requires quorum.threshold >= 2 (threshold=1 collapses the threshold model).";
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
      {
        assertion =
          cfg.mode != "oprf"
          || (
            cfg.tpmTcti != ""
            && !(lib.hasInfix "mssim" cfg.tpmTcti)
            && !(lib.hasInfix "swtpm" cfg.tpmTcti)
            && !(lib.hasInfix "libtpms" cfg.tpmTcti)
          );
        message = "keepNode.frostGate.tpmTcti must be a hardware TPM TCTI in mode = \"oprf\" (a software/emulator TCTI such as mssim/swtpm/libtpms makes the measured-boot attestation fail open).";
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
      # Order after and require the backing device unit so the wrong-device probe never races a
      # device that has not yet appeared/settled: a not-yet-present device probes as blank, which
      # would otherwise reformat a real but late-arriving volume. `requires` (not `bindsTo`): the
      # start-ordering is all the race needs, and bindsTo would let a later spurious udev re-trigger
      # of the device unit tear the gate (and, via its requires, vaultwarden) down on an
      # otherwise-healthy unattended node. Empty when volumeDevice is unset.
      after = deviceUnits;
      requires = deviceUnits;
      # Shared base; oprf adds the keep CLI (quorum unlock), tpm adds e2fsprogs (first-boot mkfs).
      path = [
        pkgs.cryptsetup
        pkgs.systemd
        pkgs.util-linux
        pkgs.coreutils
      ]
      ++ (if cfg.mode == "oprf" then [ cfg.keepPackage ] else [ pkgs.e2fsprogs ]);
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
        # RAM-only ($RUNTIME_DIRECTORY is tmpfs under /run) scratch for the reconstructed LUKS
        # key, so it is fed to cryptsetup from a file rather than a SIGPIPE-prone pipe.
        RuntimeDirectory = "keep-node-frost-gate";
        RuntimeDirectoryMode = "0700";
        # Bound the boot unlock: a hostile or hung relay must not stall the gate (and thus boot)
        # indefinitely. On timeout the unit fails and the volume stays locked (fail-closed).
        TimeoutStartSec = 90;
      };
      # Provision (first boot) or TPM2-unlock (later boots), then mount the volume at the data
      # dir. Doing the mount here (rather than a declarative fileSystems entry) keeps the
      # unlock+mount atomic and avoids depending on a fstab mount unit for a device that only
      # appears after this service runs.
      script = if cfg.mode == "oprf" then oprfGateScript else tpmGateScript;
    };

    # Operator-driven OPRF provisioning (mode = "oprf" only). NOT wantedBy boot. It needs
    # KEEP_PASSWORD in its environment and the OPRF holders (phone + replica) online; it
    # distributes the OPRF key, formats the volume, and seals this box's share + the keep DB
    # password to the TPM.
    #
    # The box attests during provisioning AND every boot unlock: both call keep with
    # `--tpm-tcti ${cfg.tpmTcti}` so holders can verify this dealer (they refuse an unattested
    # one). That requires the keep-cli build to include the `tpm-attestation` feature and both
    # this unit and the boot-time keep-node-frost-gate unit to have access to the TPM device
    # (e.g. /dev/tpmrm0). Neither unit sandboxes devices, so a default root oneshot already has
    # access; if you add device sandboxing, allow the TPM (e.g. DeviceAllow=/dev/tpmrm0 rw).
    #
    # Delivering KEEP_PASSWORD (a plain `systemctl start` runs in a clean env, so the password
    # must be injected): set `keepPasswordEnvFile` to a 0400 EnvironmentFile (KEEP_PASSWORD=...)
    # and `systemctl start keep-node-frost-provision`, or pass it ad hoc without a file via
    #   systemd-run -E KEEP_PASSWORD --pipe --wait --service-type=oneshot \
    #     --property=PrivateTmp=yes keep ...
    # Never `systemctl set-environment KEEP_PASSWORD=...` (leaks it into the global manager env).
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
        # Private tmpfs for the transient LUKS key + OPRF share; torn down when the unit exits.
        PrivateTmp = true;
      }
      // lib.optionalAttrs (cfg.keepPasswordEnvFile != null) {
        EnvironmentFile = cfg.keepPasswordEnvFile;
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
