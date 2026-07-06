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
      type = lib.types.attrsOf lib.types.anything;
      default = { };
      description = "Extra `services.wisp.settings` (merged; see the wisp module for the surface).";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # The mesh-only perimeter is enforced by the interface-scoped firewall rule below; if the
        # firewall is off, that rule does nothing and the relay is reachable on 0.0.0.0 from the
        # LAN/underlay. firewall.enable is only mkDefault true, so a host can silently turn it off.
        # Unlike sshd (AllowUsers @10.44/16) and the rsync receiver (hosts allow = 10.44/16), wisp has
        # NO application-layer source backstop, so this firewall rule is the ONLY perimeter and this
        # assertion is load-bearing.
        assertion = config.networking.firewall.enable;
        message = "keepNode.wisp.enable is true but networking.firewall.enable is false: the mesh-only relay perimeter is the interface-scoped firewall rule, and wisp has no application-layer source restriction behind it. Enable the firewall (or leave wisp off).";
      }
      {
        # wisp scopes its port to the mesh interface, which only exists when the mesh is up. Without the
        # mesh, the interface rule opens a port on a non-existent iface: fail-closed (unreachable) with
        # the firewall on, but combined with a disabled firewall it is a globally exposed relay.
        assertion = config.keepNode.mesh.enable;
        message = "keepNode.wisp.enable requires keepNode.mesh.enable (the transport the relay is scoped to; its port is opened only on the mesh interface).";
      }
    ];

    services.wisp = {
      enable = true;
      # Bind all interfaces at the socket; the mesh-interface firewall rule below is the perimeter (the
      # mesh IP is runtime-assigned, so binding it directly is not an option). Like the rsync receiver /
      # sshd, the socket listens broadly and the firewall scopes it to the mesh, but those two ALSO
      # carry an app-layer source ACL (hosts allow / AllowUsers) that wisp lacks, so here the firewall
      # rule (assertion-guarded above) is the sole perimeter.
      host = "0.0.0.0";
      port = cfg.port;
      openFirewall = false; # NOT global; the interface-scoped rule below is the only opening
      settings = cfg.settings;
    };

    # The perimeter is the mesh: open the relay port ONLY on the mesh interface.
    networking.firewall.interfaces.${cfg.meshInterface}.allowedTCPPorts = [ cfg.port ];
  };
}
