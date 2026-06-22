# keep-web: the Keep headless daemon (encrypted vault, FROST co-signer, NIP-46 bunker,
# authenticated admin API). Built from privkeyio/keep (crate `keep-web`); the package is
# passed in via the flake (keepNode.keepWeb.package).
{ config, lib, ... }:
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
        File holding the vault unlock password (KEEP_PASSWORD_FILE). For M0 this is a dev
        secret; in production the unlock is driven by the FROST quorum (keepNode.frostGate),
        not a static file.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "keepNode.keepWeb.enable requires keepNode.keepWeb.package (set by the flake).";
      }
    ];

    systemd.services.keep-web = {
      description = "keep-web headless daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment = {
        KEEP_WEB_LISTEN = cfg.listen;
        KEEP_PATH = cfg.path;
      }
      // lib.optionalAttrs (cfg.passwordFile != null) {
        KEEP_PASSWORD_FILE = toString cfg.passwordFile;
      };
      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        DynamicUser = true;
        # Create the writable parent; keep-web creates the vault subdir (cfg.path) itself.
        StateDirectory = "keep-node";
        Restart = "on-failure";
      };
    };
  };
}
