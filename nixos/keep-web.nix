# keep-web: the Keep headless daemon (encrypted vault, FROST co-signer, NIP-46 bunker,
# authenticated admin API). Built from privkeyio/keep (crate `keep-web`); the package is
# passed in via the flake (keepNode.keepWeb.package).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.keepWeb;
in
{
  options.keepNode.keepWeb = {
    enable = lib.mkEnableOption "keep-web headless daemon (from privkeyio/keep)";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "The keep-web package (built from privkeyio/keep).";
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:8080";
      description = ''
        KEEP_WEB_LISTEN address. Defaults to loopback: the admin API and NIP-46 bunker are not
        exposed off-box. Reach them over the encrypted transport (mesh/Tor); bind a wider
        address and open the firewall explicitly only if you really need direct external access.
      '';
    };

    path = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/keep-node/vault";
      description = ''
        KEEP_PATH vault directory. keep-web creates this itself on first boot, so it must be a
        path that does NOT already exist (a subdir of the StateDirectory, which systemd
        creates as the writable parent). Pointing KEEP_PATH at a pre-existing empty dir makes
        keep-web fail with a NotFound error.
      '';
    };

    passwordFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the vault unlock password (KEEP_PASSWORD_FILE). For now this is a dev
        secret; in production the unlock is driven by the FROST quorum (keepNode.frostGate),
        not a static file.
      '';
    };

    authTokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the keep-web admin API bearer token (KEEP_WEB_AUTH_TOKEN_FILE). If unset,
        keep-web generates a fresh random token on every start, so the admin API token rotates on
        each reboot (fine while `listen` is loopback-only). Pin it to a stable secret before
        keep-web is reachable off-box. Only the file PATH is placed in the environment; the token
        itself stays in the file.
      '';
    };

    stateRelay = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        KEEP_STATE_RELAY: the Nostr relay keep-web publishes its vault state to (active) or consumes
        it from (standby), for multi-node keep-state replication. In a keepNode cluster this is the
        on-box wisp over the mesh (e.g. `ws://<mesh-ip>:7777`). Null disables keep-state replication.
        Requires stateIdentityFile.
      '';
    };

    stateIdentityFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the SHARED cluster keep identity (an `nsec1...`) that all nodes replicate under
        (KEEP_STATE_IDENTITY). Generate it once for the cluster and deliver the SAME bytes to every
        node out-of-band (like the shared Vaultwarden JWT key). Must be a runtime path, not a Nix
        store path. Delivered via a systemd credential and exported into the daemon's environment.
      '';
    };

    stateRole = lib.mkOption {
      type = lib.types.enum [
        "active"
        "standby"
      ];
      default = "active";
      description = ''
        KEEP_STATE_ROLE: `active` publishes local vault-state writes to stateRelay; `standby`
        subscribes and reconstructs. Single-writer active/standby; a promoted standby is redeployed as
        `active`.
      '';
    };

    allowInsecureWs = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        TEST-ONLY: set KEEP_ALLOW_WS=1 so keep-web accepts a plaintext `ws://` stateRelay (the in-VM
        mesh wisp). Production keep-state replication must use `wss://`; never set this on a real box.
      '';
    };

    storageKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File holding the SHARED cluster vault data key (KEEP_STORAGE_KEY, 64 hex chars), used ONLY when
        this node first creates its vault. Every cluster node seeds the SAME data key so a standby can
        decrypt the records the active replicates. Deliver the same bytes to every node out-of-band onto
        the encrypted volume (like rsaKeyFile / stateIdentityFile). Must be a runtime path, not a Nix
        store path. Delivered via a systemd credential and exported into the daemon's environment.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "keepNode.keepWeb.enable requires keepNode.keepWeb.package (set by the flake).";
      }
      {
        assertion =
          cfg.passwordFile == null || !(lib.hasPrefix builtins.storeDir (toString cfg.passwordFile));
        message = "keepNode.keepWeb.passwordFile must be a runtime path (e.g. /run/secrets/...), not a Nix store path: the password would be world-readable in /nix/store.";
      }
      {
        assertion =
          cfg.authTokenFile == null || !(lib.hasPrefix builtins.storeDir (toString cfg.authTokenFile));
        message = "keepNode.keepWeb.authTokenFile must be a runtime path (e.g. /run/secrets/...), not a Nix store path: the token would be world-readable in /nix/store.";
      }
      {
        assertion =
          cfg.stateIdentityFile == null
          || !(lib.hasPrefix builtins.storeDir (toString cfg.stateIdentityFile));
        message = "keepNode.keepWeb.stateIdentityFile must be a runtime path, not a Nix store path: the shared cluster nsec would be world-readable in /nix/store.";
      }
      {
        assertion = cfg.stateRelay == null || cfg.stateIdentityFile != null;
        message = "keepNode.keepWeb.stateRelay requires stateIdentityFile (the shared cluster identity keep-web publishes/consumes state under).";
      }
      {
        assertion =
          cfg.storageKeyFile == null || !(lib.hasPrefix builtins.storeDir (toString cfg.storageKeyFile));
        message = "keepNode.keepWeb.storageKeyFile must be a runtime path, not a Nix store path: the shared cluster vault key would be world-readable in /nix/store.";
      }
    ];

    warnings =
      lib.optional
        (
          cfg.authTokenFile == null
          && !(
            lib.hasPrefix "127." cfg.listen
            || lib.hasPrefix "localhost" cfg.listen
            || lib.hasPrefix "[::1]" cfg.listen
          )
        )
        "keepNode.keepWeb.listen is non-loopback but authTokenFile is unset; the admin API bearer token regenerates on every reboot.";

    systemd.services.keep-web = {
      description = "keep-web headless daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment = {
        KEEP_WEB_LISTEN = cfg.listen;
        KEEP_PATH = cfg.path;
      }
      // lib.optionalAttrs (cfg.passwordFile != null) {
        KEEP_PASSWORD_FILE = "%d/password";
      }
      // lib.optionalAttrs (cfg.authTokenFile != null) {
        KEEP_WEB_AUTH_TOKEN_FILE = "%d/authtoken";
      }
      // lib.optionalAttrs (cfg.stateRelay != null) {
        # KEEP_STATE_IDENTITY is exported by the ExecStart wrapper from the credential, not here, so the
        # nsec never sits in the unit's declarative environment.
        KEEP_STATE_RELAY = cfg.stateRelay;
        KEEP_STATE_ROLE = cfg.stateRole;
      }
      // lib.optionalAttrs cfg.allowInsecureWs {
        KEEP_ALLOW_WS = "1";
      };
      serviceConfig = {
        # When keep-state replication is on, wrap the daemon so its cluster secrets are read from 0400
        # credential files into the environment at start (keep-web reads them from env), rather than
        # placing the nsec / vault key in the declarative unit environment.
        ExecStart =
          let
            exports = lib.concatStringsSep "\n" (
              lib.optional (
                cfg.stateIdentityFile != null
              ) ''export KEEP_STATE_IDENTITY="$(cat "$CREDENTIALS_DIRECTORY/stateidentity")"''
              ++ lib.optional (
                cfg.storageKeyFile != null
              ) ''export KEEP_STORAGE_KEY="$(cat "$CREDENTIALS_DIRECTORY/storagekey")"''
            );
          in
          if exports != "" then
            pkgs.writeShellScript "keep-web-start" ''
              ${exports}
              exec ${lib.getExe cfg.package}
            ''
          else
            lib.getExe cfg.package;
        DynamicUser = true;
        # Create the writable parent; keep-web creates the vault subdir (cfg.path) itself.
        StateDirectory = "keep-node";
        # Deliver operator secrets via systemd credentials: read as root, re-exposed at
        # 0400 in $CREDENTIALS_DIRECTORY (%d) for the transient DynamicUser UID.
        LoadCredential =
          lib.optional (cfg.passwordFile != null) "password:${toString cfg.passwordFile}"
          ++ lib.optional (cfg.authTokenFile != null) "authtoken:${toString cfg.authTokenFile}"
          ++ lib.optional (cfg.stateIdentityFile != null) "stateidentity:${toString cfg.stateIdentityFile}"
          ++ lib.optional (cfg.storageKeyFile != null) "storagekey:${toString cfg.storageKeyFile}";
        Restart = "on-failure";
      };
    };
  };
}
