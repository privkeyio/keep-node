# Multi-node HA (M1) support for Vaultwarden. First increment: distribute a SHARED JWT signing key
# (rsa_key.pem) to every node. Vaultwarden signs its session JWTs with this key and generates a
# fresh one on first start if absent; if two nodes generate their own, a token minted on the active
# is rejected by a promoted standby and every client is forced to re-authenticate on failover. So
# the whole cluster must share one key: this module installs the operator-provided key into the
# vault data dir BEFORE vaultwarden starts, and only if absent (so a later replicated key is never
# clobbered). Later increments (DB WAL streaming, file replication, promotion) extend this module.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.vaultReplication;
  # The vault data dir: the FROST gate mounts the LUKS volume here, and vaultwarden writes
  # db.sqlite3 / rsa_key.pem / attachments here. Matches keepNode.frostGate.dataDir default.
  dataDir = "/var/lib/vaultwarden";
  # Whether the FROST gate encrypts this data dir. When it does, the shared signing key must only
  # be written after the LUKS volume is mounted, never onto the unencrypted root fs.
  gateEnabled = config.keepNode.frostGate.enable or false;
in
{
  options.keepNode.vaultReplication = {
    rsaKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Absolute path string to the shared Vaultwarden JWT signing key (`rsa_key.pem`, a 2048-bit
        RSA PKCS#8 private key) to install on this node. Generate it ONCE for the cluster and
        deliver the same bytes to every node so a session token minted on the active node is
        accepted by a promoted standby. Must be a path string on the target host, not a Nix-path
        literal, so the private key is never copied into the world-readable Nix store. Null leaves
        Vaultwarden to generate its own per-node key (single-node only). The key is seeded only if
        absent (a later replication step must never be clobbered), so rotating it means deleting
        `rsa_key.pem` on every node before redeploy; changing this path alone is a silent no-op.
      '';
    };
    rsaKeyPubFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional matching public key (`rsa_key.pub.pem`); derived by Vaultwarden if omitted.";
    };

    litestream = {
      enable = lib.mkEnableOption ''
        Litestream WAL streaming of Vaultwarden's SQLite vault DB. On the ACTIVE node this
        continuously ships db.sqlite3's write-ahead log to a replica directory; a standby (or a
        promotion step) restores from it. This increment writes the replica LOCALLY; a later
        increment ships it to the peer over the encrypted transport (the mesh, which does not exist
        yet). The vault DB stays single-writer, so this is active/standby, not active/active
      '';
      replicaDir = lib.mkOption {
        type = lib.types.str;
        default = "${dataDir}/replica";
        description = ''
          Directory Litestream writes the replica to. Defaults to a subdirectory of the vault data
          dir so that on a FROST-gated node it inherits the encrypted, mounted volume: the replica
          reconstructs the vault DB's contents (server-side secrets) and must not land on unencrypted
          disk. Must stay under the data dir (an assertion below enforces that): on a gated node that
          keeps the replica encrypted-at-rest, and it keeps the path inside the service sandbox's
          writable set so Litestream can actually create it.
        '';
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf (cfg.rsaKeyFile != null) {
      # The installer orders before/requiredBy vaultwarden.service; surface a misconfig instead of
      # wiring those ordering deps to a unit that never materializes.
      assertions = [
        {
          assertion = config.services.vaultwarden.enable;
          message = "keepNode.vaultReplication.rsaKeyFile is set but services.vaultwarden.enable is false: the shared-key installer has nothing to seed a key for.";
        }
      ];

      systemd.services.keep-node-vault-rsa-key = {
        description = "Install the shared Vaultwarden JWT signing key (multi-node HA)";
        wantedBy = [ "multi-user.target" ];
        # Must land the key before Vaultwarden starts (it generates its own if the file is absent),
        # and after the FROST gate has mounted the data volume (no-op ordering if the gate is off).
        before = [ "vaultwarden.service" ];
        requiredBy = [ "vaultwarden.service" ];
        after = [ "keep-node-frost-gate.service" ];
        # When the gate encrypts the data dir, bind to it: a failed unlock must abort the installer so
        # the cluster-wide RSA private key is never written to unencrypted disk. Mirrors the `requires`
        # that vaultwarden.service itself places on the gate.
        requires = lib.optional gateEnabled "keep-node-frost-gate.service";
        # `mountpoint` (util-linux) is not on the default service PATH; the guard below needs it.
        path = lib.optional gateEnabled pkgs.util-linux;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          set -euo pipefail
          d=${lib.escapeShellArg dataDir}
          ${lib.optionalString gateEnabled ''
            # Defense in depth beside the `requires` above: only write onto the mounted, encrypted
            # volume. If the gate somehow "succeeded" without mounting, fail closed rather than persist
            # the shared signing key on the unencrypted root fs.
            if ! mountpoint -q "$d"; then
              echo "keep-node-vault-rsa-key: $d is not a mountpoint (FROST volume not mounted); refusing to write key to unencrypted disk" >&2
              exit 1
            fi
          ''}
          # vaultwarden.service's StateDirectory would create this, but we run first; make it now with
          # the same owner/mode so systemd does not fight us.
          install -d -o vaultwarden -g vaultwarden -m 0700 "$d"
          # Only seed if absent: never clobber a key a future replication step may have delivered.
          if [ ! -e "$d/rsa_key.pem" ]; then
            install -o vaultwarden -g vaultwarden -m 0600 ${lib.escapeShellArg cfg.rsaKeyFile} "$d/rsa_key.pem"
            ${lib.optionalString (cfg.rsaKeyPubFile != null)
              ''install -o vaultwarden -g vaultwarden -m 0644 ${lib.escapeShellArg cfg.rsaKeyPubFile} "$d/rsa_key.pub.pem"''
            }
          fi
        '';
      };
    })

    (lib.mkIf cfg.litestream.enable {
      # The unit hard-requires vaultwarden.service and reads its db.sqlite3; surface a misconfig
      # instead of wiring ordering deps to a unit that never materializes. Also keep replicaDir under
      # the data dir so the replica (the vault DB's contents) inherits its encryption-at-rest and
      # stays inside the service sandbox's writable set.
      assertions = [
        {
          assertion = config.services.vaultwarden.enable;
          message = "keepNode.vaultReplication.litestream.enable is true but services.vaultwarden.enable is false: Litestream has no vault DB to replicate.";
        }
        {
          # Unconditional: on a gated node this keeps the replica on the encrypted volume, and in all
          # cases it keeps replicaDir inside the unit's single ReadWritePaths entry (dataDir) so the
          # sandbox can write it. Reject `/../` so the string prefix can't be escaped off the mount.
          assertion =
            lib.hasPrefix "${dataDir}/" cfg.litestream.replicaDir
            && !lib.hasInfix "/../" cfg.litestream.replicaDir;
          message = "keepNode.vaultReplication.litestream.replicaDir must live under ${dataDir} (it is set to ${cfg.litestream.replicaDir}) so the replica inherits the vault data dir's encryption and the service sandbox can create it.";
        }
      ];

      # Litestream's precondition: the DB must be in WAL mode. Vaultwarden defaults it on, but pin
      # it so a future config change can't silently break replication.
      services.vaultwarden.config.ENABLE_DB_WAL = true;

      systemd.services.keep-node-litestream = {
        description = "Litestream WAL replication of the Vaultwarden vault DB";
        wantedBy = [ "multi-user.target" ];
        # Replicate a running DB: start after Vaultwarden has created db.sqlite3, and after the FROST
        # gate mounted the (encrypted) data dir.
        after = [
          "vaultwarden.service"
          "keep-node-frost-gate.service"
        ];
        # Requires vaultwarden: without it there is no DB to replicate, so a stopped/failed vault
        # takes the replicator down too. A vault *restart* leaves db.sqlite3 in place, so Litestream
        # keeps following the same file and does not need to restart in lockstep. When the gate
        # encrypts the data dir, also require it: the replica reconstructs the vault DB, so a failed
        # unlock must abort replication rather than write plaintext to disk. Mirrors the RSA installer.
        requires = [ "vaultwarden.service" ] ++ lib.optional gateEnabled "keep-node-frost-gate.service";
        # Disable the start-limit (default 5 restarts / 10s): first-boot schema migrations can exceed
        # that window, and giving up would leave replication silently off forever. Retry until the DB
        # appears. (This is a [Unit] setting, hence not in serviceConfig.)
        startLimitIntervalSec = 0;
        serviceConfig = {
          # Run as the vaultwarden user: it owns the 0700 data dir, so this is the only uid that can
          # read db.sqlite3 and write Litestream's shadow WAL beside it.
          User = "vaultwarden";
          Group = "vaultwarden";
          ExecStartPre =
            # Defense in depth beside the `requires` above: only write the replica onto the mounted,
            # encrypted volume. If the gate "succeeded" without mounting, fail closed rather than
            # reconstruct the vault DB on the unencrypted root fs. The `+` prefix runs this guard
            # OUTSIDE the unit's mount namespace: ProtectSystem/ReadWritePaths bind-mounts dataDir
            # inside the sandbox, so an in-namespace `mountpoint` would read as mounted even when the
            # LUKS volume is absent. Running on the host mount table makes the check real. Use an
            # absolute mountpoint path since `+` execs do not get the unit `path`.
            lib.optional gateEnabled (
              "+"
              + pkgs.writeShellScript "keep-node-litestream-mount-guard" ''
                set -euo pipefail
                if ! ${pkgs.util-linux}/bin/mountpoint -q ${lib.escapeShellArg dataDir}; then
                  echo "keep-node-litestream: ${dataDir} is not a mountpoint (FROST volume not mounted); refusing to write the vault-DB replica to unencrypted disk" >&2
                  exit 1
                fi
              ''
            )
            # vaultwarden.service's StateDirectory creates dataDir at 0700; pre-create the replica
            # subdir 0700 so Litestream never widens it (it would create 0755). This runs as the
            # vaultwarden user (no `+` prefix), so the dir is vaultwarden-owned without a chown.
            ++ [
              "${pkgs.coreutils}/bin/install -d -m 0700 ${lib.escapeShellArg cfg.litestream.replicaDir}"
            ];
          ExecStart = "${pkgs.litestream}/bin/litestream replicate ${lib.escapeShellArg "${dataDir}/db.sqlite3"} ${lib.escapeShellArg "file://${cfg.litestream.replicaDir}"}";
          # db.sqlite3 does not exist until Vaultwarden's first start finishes creating it; retry
          # rather than fail the boot (start-limit disabled above so retries never exhaust).
          Restart = "on-failure";
          RestartSec = 2;
          # Local file:// replica: no network, no privilege escalation, read-only fs except the data
          # dir where db.sqlite3 and the replica (+ its shadow WAL) live.
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ReadWritePaths = [ dataDir ];
        };
      };

      # Litestream replicates ONLY db.sqlite3, never the attachment/Send files it references
      # (attachments/<cipher>/<id>, sends/<id> -- E2E ciphertext on disk). A separate periodic sync
      # mirrors those into the same replica dir so a promoted standby has the files a restored row
      # points at. Runs on a short timer AHEAD of / alongside the ~1s DB stream: two async
      # replicators cannot give atomic file-before-row, so this is bounded eventual consistency (the
      # design doc permits it) -- the window where a row is restored before its file is small and
      # self-heals on the next sync.
      systemd.services.keep-node-vault-files = {
        description = "Replicate Vaultwarden attachments + Sends (multi-node HA)";
        after = [
          "vaultwarden.service"
          "keep-node-frost-gate.service"
        ];
        requires = [ "vaultwarden.service" ] ++ lib.optional gateEnabled "keep-node-frost-gate.service";
        serviceConfig = {
          Type = "oneshot";
          User = "vaultwarden";
          Group = "vaultwarden";
          # Same fail-closed guard as the DB replica: never mirror the (E2E-ciphertext, but still
          # sensitive) files onto unencrypted disk when the gate failed to mount. `+` runs it on the
          # host mount table, outside the sandbox's dataDir bind-mount. Mirrors keep-node-litestream.
          ExecStartPre = lib.optional gateEnabled (
            "+"
            + pkgs.writeShellScript "keep-node-vault-files-mount-guard" ''
              set -euo pipefail
              if ! ${pkgs.util-linux}/bin/mountpoint -q ${lib.escapeShellArg dataDir}; then
                echo "keep-node-vault-files: ${dataDir} is not a mountpoint (FROST volume not mounted); refusing to mirror vault files to unencrypted disk" >&2
                exit 1
              fi
            ''
          );
          ExecStart = pkgs.writeShellScript "keep-node-vault-files-sync" ''
            set -euo pipefail
            install -d -m 0700 ${lib.escapeShellArg cfg.litestream.replicaDir}
            for sub in attachments sends; do
              # Vaultwarden creates these only on first attachment/Send; mkdir so rsync never errors
              # on a missing source, and --delete so a file removed on the active is removed here too.
              mkdir -p ${lib.escapeShellArg dataDir}/"$sub" ${lib.escapeShellArg cfg.litestream.replicaDir}/"$sub"
              ${pkgs.rsync}/bin/rsync -a --delete ${lib.escapeShellArg dataDir}/"$sub"/ ${lib.escapeShellArg cfg.litestream.replicaDir}/"$sub"/
            done
          '';
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ReadWritePaths = [ dataDir ];
        };
      };
      systemd.timers.keep-node-vault-files = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "20s";
          OnUnitActiveSec = "15s";
          Unit = "keep-node-vault-files.service";
        };
      };
    })
  ];
}
