# keep-node mesh transport: the encrypted node-to-node overlay that carries vault replication
# between nodes. Runs nostr-vpn's `nvpn` daemon (boringtun USERSPACE WireGuard + Nostr-authenticated
# peers) headless. This first increment packages and runs the daemon and forms a static two-node
# mesh; a later increment points the replicator at the peer's mesh IP. boringtun means the daemon
# needs only /dev/net/tun (the generic tun module) plus CAP_NET_ADMIN, never a kernel `wg` module,
# which is all a plain VM provides.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.mesh;
in
{
  options.keepNode.mesh = {
    enable = lib.mkEnableOption "nvpn encrypted mesh transport (nostr-vpn)";

    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "The nvpn package (built from mmalmi/nostr-vpn).";
    };

    listenPort = lib.mkOption {
      type = lib.types.port;
      default = 51820;
      description = "UDP port the mesh (boringtun WireGuard underlay) listens on; opened in the firewall.";
    };

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/keep-node-mesh";
      description = ''
        HOME for the nvpn daemon: its Nostr mesh identity (`.config/nvpn/config.toml`, a secret key)
        lives here. On a FROST-gated node this should sit on the encrypted volume, like `rsa_key.pem`,
        so the mesh identity is not persisted in the clear; defaults to a plain state dir for bring-up.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.package != null;
        message = "keepNode.mesh.enable is true but keepNode.mesh.package is null: no nvpn binary to run.";
      }
    ];

    # boringtun is a userspace WireGuard: the daemon opens /dev/net/tun (generic tun module) and needs
    # CAP_NET_ADMIN, never a kernel wg module. Ensure tun is loadable.
    boot.kernelModules = [ "tun" ];

    # nvpn on PATH for provisioning (init/set) and status (ip/status), by the operator or the test.
    environment.systemPackages = [ cfg.package ];

    # The mesh underlay (WireGuard) speaks UDP on the listen port; peers must reach it.
    networking.firewall.allowedUDPPorts = [ cfg.listenPort ];

    # Persist the mesh identity dir before the daemon (or provisioning) writes into it.
    systemd.tmpfiles.rules = [ "d ${cfg.stateDir} 0700 root root -" ];

    systemd.services.keep-node-mesh = {
      description = "nvpn encrypted mesh transport (nostr-vpn private mesh)";
      # The daemon shells out to `ip` (iproute2) to configure its userspace-WireGuard tun interface
      # and routes; without it on PATH, tunnel setup fails with ENOENT.
      path = [ pkgs.iproute2 ];
      # Deliberately NOT wantedBy multi-user.target in this increment: the mesh identity (`nvpn init`)
      # and the peer roster/endpoints (`nvpn set`) are provisioned first (by onboarding, or by the
      # test), then this is started. A later increment provisions them declaratively and enables it at
      # boot; it will also confine the daemon (this runs as root for now to reach /dev/net/tun).
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} connect";
        # nvpn reads $HOME/.config/nvpn/config.toml.
        Environment = "HOME=${cfg.stateDir}";
        Restart = "on-failure";
        RestartSec = 2;
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
      };
    };
  };
}
