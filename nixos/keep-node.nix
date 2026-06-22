# KeepNode appliance composition.
#
# Pulls together the security services (Vaultwarden), the Keep daemon (keep-web), and the
# FROST threshold volume gate. For M0 only Vaultwarden is enabled by default so the node
# boots end-to-end in a VM with no hardware. keep-web is a real built package (see flake.nix),
# off by default here but enabled by the M0 test; the frost-gate is still an opt-in stub. These
# get wired into the default composition as the build progresses (M0 -> M1 -> M2).
#
# See the design docs (kept outside this repo): KEEP-NODE.md, BUILD-PLAN.md,
# SPIKE-vaultwarden-unlock.md (Approach B).
{ lib, ... }:
{
  imports = [
    ./vaultwarden.nix
    ./keep-web.nix
    ./frost-gate.nix
  ];

  # Appliance defaults (overridable). Hostname is left to the host/VM/test layer so it does
  # not conflict with the nixosTest framework's per-node naming.
  networking.firewall.enable = lib.mkDefault true;

  # M0: Vaultwarden is the headline service and boots by default.
  keepNode.vaultwarden.enable = lib.mkDefault true;

  # keep-web and frost-gate are off until their pieces land (see their modules).
  keepNode.keepWeb.enable = lib.mkDefault false;
  keepNode.frostGate.enable = lib.mkDefault false;

  system.stateVersion = "24.11";
}
