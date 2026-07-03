# KeepNode appliance composition.
#
# Pulls together the security services (Vaultwarden), the Keep daemon (keep-web), and the
# FROST threshold volume gate. For now only Vaultwarden is enabled by default so the node
# boots end-to-end in a VM with no hardware. keep-web is a real built package (see flake.nix),
# off by default here but enabled by the single-node test; the frost-gate is opt-in and
# enabled by its own test. These get wired into the default composition as the build matures.
{ lib, ... }:
{
  imports = [
    ./vaultwarden.nix
    ./keep-web.nix
    ./frost-gate.nix
    ./ingress.nix
    ./vault-replication.nix
    ./mesh.nix
  ];

  # Appliance defaults (overridable). Hostname is left to the host/VM/test layer so it does
  # not conflict with the nixosTest framework's per-node naming.
  networking.firewall.enable = lib.mkDefault true;

  # Vaultwarden is the headline service and boots by default.
  keepNode.vaultwarden.enable = lib.mkDefault true;

  # keep-web and frost-gate are off until their pieces land (see their modules).
  keepNode.keepWeb.enable = lib.mkDefault false;
  keepNode.frostGate.enable = lib.mkDefault false;

  system.stateVersion = "24.11";
}
