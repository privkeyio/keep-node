# On-box wisp nostr relay, reachable ONLY over the encrypted nvpn mesh. Thin wrapper over wisp's
# upstream `services.wisp` module (from the wisp flake): it binds the relay and opens its port only on
# the mesh interface, the same mesh-is-the-perimeter pattern as the vault-replication receiver and
# admin SSH, so only rostered, WireGuard-authenticated peers can reach it. The relay is what the
# threshold-OPRF quorum coordinates over, and (later) what carries relay-based mesh peer discovery.
#
# OPT-IN: a config using this must ALSO import wisp's module, e.g. in the flake's module list:
#   modules = [ inputs.wisp.nixosModules.wisp ./nixos/wisp.nix ]; keepNode.wisp.enable = true;
# (This wrapper only drives `services.wisp`, which that module defines.)
{ config, lib, ... }:
let
  cfg = config.keepNode.wisp;
in
{
  options.keepNode.wisp = {
    enable = lib.mkEnableOption "on-box wisp relay bound to the encrypted mesh";

    port = lib.mkOption {
      type = lib.types.port;
      default = 7777;
      description = "TCP port the relay listens on; opened ONLY on the mesh interface.";
    };

    meshInterface = lib.mkOption {
      type = lib.types.str;
      default = "utun100";
      description = ''
        The nvpn mesh interface. The relay's port is opened only here, so the LAN and the WireGuard
        underlay never reach it. Must match nvpn's runtime tun device (same coupling the other
        mesh-scoped services carry).
      '';
    };

    settings = lib.mkOption {
      type = lib.types.attrs;
      default = { };
      description = "Extra `services.wisp.settings` (merged; see the wisp module for the surface).";
    };
  };

  config = lib.mkIf cfg.enable {
    services.wisp = {
      enable = true;
      # Bind all interfaces at the socket; the mesh-interface firewall rule below is the perimeter (the
      # mesh IP is runtime-assigned, so binding it directly is not an option). Matches the rsync
      # receiver / sshd, which also listen broadly and are firewalled to the mesh.
      host = "0.0.0.0";
      port = cfg.port;
      openFirewall = false; # NOT global; the interface-scoped rule below is the only opening
      settings = cfg.settings;
    };

    # The perimeter is the mesh: open the relay port ONLY on the mesh interface.
    networking.firewall.interfaces.${cfg.meshInterface}.allowedTCPPorts = [ cfg.port ];
  };
}
