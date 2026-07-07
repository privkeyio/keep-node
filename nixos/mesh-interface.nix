# Single source of truth for the nvpn mesh interface name. The mesh-scoped services (the wisp relay,
# the vault-replication receiver, admin SSH) each open their port ONLY on this interface, so they must
# all agree on nvpn's runtime tun device or a service silently opens the wrong (or no) interface.
# Declaring it once here -- imported by each of those modules -- means an operator sets it in one place
# and every service inherits it, instead of three per-module options that can drift apart. This is a
# thin, options-only module (no config), so a module can import it without pulling in the mesh daemon,
# keeping admin-access.nix usable standalone (its bring-up firewall tests import it without mesh.nix).
{ lib, ... }:
{
  options.keepNode.mesh.interface = lib.mkOption {
    type = lib.types.str;
    default = "utun100";
    description = ''
      The nvpn mesh tun device. Mesh-scoped services (wisp relay, vault-replication receiver, admin
      SSH) open their port only on this interface, so the LAN and the WireGuard underlay never reach
      them; it must match nvpn's runtime device. Set it here once; the per-service
      `keepNode.{wisp,adminAccess,vaultReplication.meshReplication}.meshInterface` options each default
      to it, so they cannot drift apart unless deliberately overridden.
    '';
  };
}
