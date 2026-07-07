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

    meshCidr = lib.mkOption {
      type = lib.types.strMatching "([0-9]{1,3}[.]){3}[0-9]{1,3}/[0-9]{1,2}";
      default = "10.44.0.0/16";
      description = ''
        The nvpn mesh subnet (nvpn assigns 10.44.x.y). Used for the firewall source backstop below:
        the relay port is refused from any out-of-CIDR source regardless of interface. This is a
        weaker, firewall-layer stand-in for the app-layer source ACLs the sibling services carry
        (sshd AllowUsers @10.44/16, rsyncd hosts allow = 10.44/16); it filters on source address
        only, so it does not defend against a spoofed in-CIDR source.
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
        # The mesh-only perimeter is enforced entirely in the firewall (the interface-scoped rule plus
        # the source-CIDR backstop below); wisp has no application-layer ACL of its own, so if the
        # firewall is off BOTH do nothing and the relay is reachable on 0.0.0.0 from the LAN/underlay.
        # firewall.enable is only mkDefault true, so a host can silently turn it off -- this assertion
        # is load-bearing.
        assertion = config.networking.firewall.enable;
        message = "keepNode.wisp.enable is true but networking.firewall.enable is false: wisp's mesh-only perimeter lives entirely in the firewall (the interface-scoped rule plus the source-CIDR backstop) and wisp has no application-layer source restriction behind it, so both vanish when the firewall is off. Enable the firewall (or leave wisp off).";
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
      # Bind all interfaces at the socket; the firewall scopes it to the mesh (the mesh IP is
      # runtime-assigned, so binding it directly is not an option). Like the rsync receiver / sshd, the
      # socket listens broadly and the firewall confines it. Those two also carry an app-layer source
      # ACL (hosts allow / AllowUsers); wisp has none, so the source-CIDR firewall backstop below is the
      # nearest stand-in (weaker: firewall-layer, not app-layer). Both firewall rules are
      # assertion-guarded above.
      host = "0.0.0.0";
      port = cfg.port;
      openFirewall = false; # NOT global; the interface-scoped rule below is the only opening
      settings = cfg.settings;
    };

    # The primary perimeter is the mesh: open the relay port ONLY on the mesh interface.
    networking.firewall.interfaces.${cfg.meshInterface}.allowedTCPPorts = [ cfg.port ];

    # Defense-in-depth source backstop at the firewall layer, standing in for the app-layer source
    # ACLs the siblings carry (sshd AllowUsers @meshCidr, rsyncd hosts allow = meshCidr) that wisp
    # cannot (upstream, no native host ACL). It is weaker than those: it matches on source address
    # only, so it does not stop a spoofed in-CIDR source. Refuse the relay port from any out-of-CIDR
    # source, inserted AHEAD of the interface accept so an out-of-CIDR source is still refused if
    # meshInterface drifts to a LAN iface (the interface rule would then accept, but the refuse runs
    # first). Loopback is accepted (via -i lo) for on-box clients; IPv6 is refused outright since the
    # mesh is IPv4. Each `! -s <cidr>` match needs its own rule, so they are inserted in reverse (last
    # insert lands on top).
    # Ceiling: iptables backend only. Switching to the nftables firewall fails the build (that module
    # asserts networking.firewall.extraCommands == ""); port this block to
    # networking.firewall.extraInputRules first (`tcp dport <port> ip saddr != <cidr> drop`).
    networking.firewall.extraCommands = ''
      iptables  -I nixos-fw -p tcp --dport ${toString cfg.port} ! -s ${cfg.meshCidr} -j nixos-fw-refuse
      iptables  -I nixos-fw -p tcp --dport ${toString cfg.port} -i lo -j nixos-fw-accept
      ip6tables -I nixos-fw -p tcp --dport ${toString cfg.port} ! -s ::1/128 -j nixos-fw-refuse
    '';
  };
}
