# VM-only overrides for `nix run .#keep-node-vm` (local M0 development, no hardware).
# The nixosTest nodes do NOT import this; the test framework provides its own VM settings.
{ lib, ... }:
{
  virtualisation.vmVariant.virtualisation = {
    memorySize = 2048;
    cores = 2;
    graphics = false;
    # Reach Vaultwarden from the host at http://localhost:8222
    forwardPorts = [
      {
        from = "host";
        host.port = 8222;
        guest.port = 8222;
      }
    ];
  };

  networking.hostName = lib.mkDefault "keep-node";
  services.getty.autologinUser = lib.mkDefault "root";
  # Dev convenience only; never ship a passwordless appliance.
  users.users.root.password = lib.mkDefault "";
}
