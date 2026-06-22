# Vaultwarden, threshold-gated per Approach B (see SPIKE-vaultwarden-unlock.md).
#
# Vaultwarden is zero-knowledge end-to-end: the server only ever holds the *encrypted* user
# key plus an auth hash, so it cannot decrypt a vault. We therefore do NOT modify Vaultwarden
# or its clients. Instead the threshold/seedless guarantee is delivered at the data-at-rest +
# service-availability layer:
#
#   * Vaultwarden's whole state dir lives on a LUKS volume (keepNode.frostGate.volumeDevice).
#   * That volume's key is released only when the FROST quorum approves (frost-gate.nix).
#   * vaultwarden.service is ordered After= the gate, so it starts only once unlocked.
#
# For the M0 VM there is no LUKS/hardware; state is on plain disk so the node boots and serves.
{ config, lib, ... }:
let
  cfg = config.keepNode.vaultwarden;
in
{
  options.keepNode.vaultwarden = {
    enable = lib.mkEnableOption "Vaultwarden (threshold-gated, Approach B)";
    port = lib.mkOption {
      type = lib.types.port;
      default = 8222;
      description = "Vaultwarden HTTP port.";
    };
    signupsAllowed = lib.mkOption {
      type = lib.types.bool;
      default = false; # default-deny; first user via admin/invite, never open self-registration
      description = "Allow self-registration. Off by default; the node is not an open signup endpoint.";
    };
  };

  config = lib.mkIf cfg.enable {
    services.vaultwarden = {
      enable = true;
      dbBackend = "sqlite"; # default datastore; matches the active/standby replication plan
      config = {
        # Bind localhost only. The vault is never exposed as plaintext HTTP on the LAN;
        # access is over the encrypted transport (nvpn/WireGuard mesh, Tor, start-tunnel),
        # which terminates to localhost. TLS is handled at that ingress layer (and Bitwarden
        # clients require HTTPS anyway, so a raw LAN HTTP bind is not even usable by them).
        ROCKET_ADDRESS = "127.0.0.1";
        ROCKET_PORT = cfg.port;
        SIGNUPS_ALLOWED = cfg.signupsAllowed;
      };
    };

    # No firewall port opened: nothing reaches Vaultwarden except via localhost / the mesh.
    # M1 hook: the vaultwarden state dir (managed by the NixOS module) is the bind/mount
    # target for the FROST-gated LUKS volume. frost-gate.nix orders the unlock before this.
  };
}
