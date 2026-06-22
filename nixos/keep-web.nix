# keep-web: the Keep headless daemon (encrypted vault, FROST co-signer, NIP-46 bunker,
# authenticated admin API). Reused from privkeyio/keep (crate `keep-web`).
#
# Not yet packaged here. Wire it via a `keep` flake input that exposes a keep-web package,
# then set keepNode.keepWeb.package. Until then this module is a no-op (enable = false) so the
# M0 VM boots Vaultwarden without it.
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
      description = "The keep-web binary. Build from privkeyio/keep (crate keep-web).";
    };
    listen = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:8080";
      description = "KEEP_WEB_LISTEN address.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "keepNode.keepWeb.enable requires keepNode.keepWeb.package (build from privkeyio/keep).";
      }
    ];

    systemd.services.keep-web = {
      description = "keep-web headless daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      environment.KEEP_WEB_LISTEN = cfg.listen;
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/keep-web";
        DynamicUser = true;
        StateDirectory = "keep-node/keep";
        # KEEP_PATH / KEEP_PASSWORD_FILE / KEEP_WEB_AUTH_TOKEN_FILE wired in M0+.
      };
    };
  };
}
