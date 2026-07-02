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
        default = "/var/lib/vault-replica";
        description = ''
          Directory Litestream writes the replica to. On a FROST-gated node this is on the
          unencrypted root fs by default, so a hardened deployment should point it at the encrypted
          volume or a tmpfs; the replica contains the vault DB's contents (server-side secrets).
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
      # Litestream's precondition: the DB must be in WAL mode. Vaultwarden defaults it on, but pin
      # it so a future config change can't silently break replication.
      services.vaultwarden.config.ENABLE_DB_WAL = true;

      systemd.services.keep-node-litestream = {
        description = "Litestream WAL replication of the Vaultwarden vault DB";
        wantedBy = [ "multi-user.target" ];
        # Replicate a running DB: start after Vaultwarden has created db.sqlite3, and after the FROST
        # gate mounted the (encrypted) data dir. requires vaultwarden so it stops if the vault stops.
        after = [
          "vaultwarden.service"
          "keep-node-frost-gate.service"
        ];
        requires = [ "vaultwarden.service" ];
        serviceConfig = {
          # Run as the vaultwarden user: it owns the 0700 data dir, so this is the only uid that can
          # read db.sqlite3 and write Litestream's shadow WAL beside it.
          User = "vaultwarden";
          Group = "vaultwarden";
          StateDirectory = "vault-replica";
          ExecStart = "${pkgs.litestream}/bin/litestream replicate ${lib.escapeShellArg "${dataDir}/db.sqlite3"} ${lib.escapeShellArg "file://${cfg.litestream.replicaDir}"}";
          # db.sqlite3 does not exist until Vaultwarden's first start finishes creating it; retry
          # rather than fail the boot.
          Restart = "on-failure";
          RestartSec = 2;
        };
      };
    })
  ];
}
