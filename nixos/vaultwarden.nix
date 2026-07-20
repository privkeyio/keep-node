# Vaultwarden, its data volume threshold-gated by the FROST volume gate.
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
# When the frost-gate is disabled there is no LUKS volume; state is on plain disk so the node
# still boots and serves (used by the single-node test).
{ config, lib, ... }:
let
  cfg = config.keepNode.vaultwarden;
in
{
  options.keepNode.vaultwarden = {
    enable = lib.mkEnableOption "Vaultwarden (data volume threshold-gated)";
    port = lib.mkOption {
      type = lib.types.port;
      default = 8222;
      description = "Vaultwarden HTTP port.";
    };
    domain = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "http://localhost:8222";
      description = ''
        The exact origin clients reach this vault on, published to Vaultwarden as DOMAIN. WebAuthn
        (YubiKey as 2FA or passkey) binds every credential to this origin: registered against the wrong
        DOMAIN, the token silently fails to verify on the next login. Set it to the origin you actually
        type , `http://localhost:8222` for the SSH-tunnelled default (localhost is a secure context, so
        WebAuthn works there without TLS), or the mesh URL you use. Left null, Vaultwarden falls back to
        its own default and WebAuthn registration is unreliable.

        Use `http://` ONLY for `localhost`. Browsers treat plain HTTP on any other host (a mesh IP, a
        LAN name) as a non-secure context and refuse WebAuthn outright, and Vaultwarden drops secure
        cookies there , so a token cannot be registered at all. Off localhost, reach the vault over an
        SSH tunnel to `http://localhost:PORT`, or terminate real HTTPS in front of it
        (`keepNode.ingress`) and use that hostname.

        Only a default: `keepNode.ingress` sets DOMAIN to its own public HTTPS hostname and takes
        precedence, since that is then the real client-facing origin.
      '';
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
      }
      # mkDefault so keepNode.ingress, which knows the real public origin, wins when it is enabled.
      // lib.optionalAttrs (cfg.domain != null) { DOMAIN = lib.mkDefault cfg.domain; };
    };

    # No firewall port opened: nothing reaches Vaultwarden except via localhost / the mesh.
    # The vaultwarden state dir is where the frost-gate mounts the FROST-gated LUKS volume,
    # and vaultwarden.service is ordered after the gate (see frost-gate.nix).
  };
}
