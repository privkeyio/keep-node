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
  ...
}:
let
  cfg = config.keepNode.vaultReplication;
  # The vault data dir: the FROST gate mounts the LUKS volume here, and vaultwarden writes
  # db.sqlite3 / rsa_key.pem / attachments here. Matches keepNode.frostGate.dataDir default.
  dataDir = "/var/lib/vaultwarden";
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
        Vaultwarden to generate its own per-node key (single-node only).
      '';
    };
    rsaKeyPubFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional matching public key (`rsa_key.pub.pem`); derived by Vaultwarden if omitted.";
    };
  };

  config = lib.mkIf (cfg.rsaKeyFile != null) {
    systemd.services.keep-node-vault-rsa-key = {
      description = "Install the shared Vaultwarden JWT signing key (multi-node HA)";
      wantedBy = [ "multi-user.target" ];
      # Must land the key before Vaultwarden starts (it generates its own if the file is absent),
      # and after the FROST gate has mounted the data volume (no-op ordering if the gate is off).
      before = [ "vaultwarden.service" ];
      requiredBy = [ "vaultwarden.service" ];
      after = [ "keep-node-frost-gate.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        d=${lib.escapeShellArg dataDir}
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
  };
}
