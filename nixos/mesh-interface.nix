# Single source of truth for the nvpn mesh interface name. The mesh-scoped services (the wisp relay,
# the vault-replication receiver, admin SSH) each open their port ONLY on this interface, so they must
# all agree on nvpn's runtime tun device or a service silently opens the wrong (or no) interface.
# Declaring it once here -- imported by each of those modules -- means an operator sets it in one place
# and every service inherits it, instead of three per-module options that can drift apart. It carries
# only the option and a non-empty assertion (no service config, no mesh daemon), so a module can import
# it standalone -- e.g. admin-access.nix and its bring-up firewall tests import it without mesh.nix.
{ lib, config, ... }:
{
  options.keepNode.mesh.interface = lib.mkOption {
    type = lib.types.str;
    default = "utun100";
    description = ''
      The nvpn mesh tun device. Mesh-scoped services (wisp relay, vault-replication receiver, admin
      SSH) open their port only on this interface, so the LAN and the WireGuard underlay never reach
      them. This name is passed to the daemon (`nvpn connect --iface`), so nvpn creates exactly this
      device , the firewall scoping and the runtime interface cannot drift apart. Set it here once; the
      per-service `keepNode.{wisp,adminAccess,vaultReplication.meshReplication}.meshInterface` options
      each default to it, so they stay consistent unless deliberately overridden.
    '';
  };

  # The name is both a firewall attr key (scoping the wisp, admin-SSH, and vault-replication ports) AND
  # the device nvpn creates via `--iface`, so constrain it to a valid Linux interface name (IFNAMSIZ 15,
  # leading letter). The leading letter is load-bearing beyond rejecting empty/whitespace: a PURELY
  # NUMERIC name makes boringtun's TunSocket parse it as a pre-opened file descriptor instead of creating
  # a device, so nvpn would bring up NO interface by that name while the firewall still scopes every mesh
  # port to it , the exact silent, fail-closed drift this consolidation exists to prevent. (Over-length
  # or whitespace names fail loudly at daemon start; the numeric case is the only silent one.)
  config.assertions = [
    {
      assertion = builtins.match "[a-zA-Z][a-zA-Z0-9._-]{0,14}" config.keepNode.mesh.interface != null;
      message = "keepNode.mesh.interface (${config.keepNode.mesh.interface}) must be a valid Linux interface name: a letter followed by up to 14 of [A-Za-z0-9._-] (IFNAMSIZ 15). It scopes the wisp, admin-SSH, and vault-replication firewall ports and is the device nvpn creates via --iface; an empty, whitespace, over-long, or purely-numeric name mis-scopes those ports or (numeric) makes boringtun treat it as a file descriptor so no device is created. Use e.g. utun100.";
    }
  ];
}
