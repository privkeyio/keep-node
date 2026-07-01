# Opt-in test access for bring-up on real hardware. INSECURE BY DESIGN: a known root password,
# password SSH, and the web vault exposed on the LAN over a self-signed cert. This exists so a
# freshly installed node can be reached without the mesh/Tor transport that production uses.
# Turn it off (keepNode.debugAccess.enable = false) once the real transport is in place.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.keepNode.debugAccess;
in
{
  options.keepNode.debugAccess.enable = lib.mkEnableOption "insecure test access: SSH, console autologin, LAN web UI over self-signed TLS";

  config = lib.mkIf cfg.enable {
    # Console autologin + a known password so you can also SSH in. CHANGE THIS after first boot.
    services.getty.autologinUser = "root";
    users.users.root.initialPassword = "keepnode";

    services.openssh = {
      enable = true;
      settings = {
        PermitRootLogin = "yes";
        PasswordAuthentication = true;
      };
    };

    # Vaultwarden binds localhost only; the Bitwarden web vault needs a secure context (HTTPS or
    # localhost), so plain http://<lan-ip> can't log in. nginx terminates a self-signed cert and
    # proxies to it, giving working LAN access (accept the browser warning once).
    systemd.services.keepnode-selfsigned = {
      wantedBy = [ "multi-user.target" ];
      before = [ "nginx.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      path = [ pkgs.openssl ];
      script = ''
        set -euo pipefail
        d=/var/lib/keepnode-tls
        # Regenerate unless BOTH files are present: an interrupted first run can leave the key
        # without the cert, and nginx would then fail forever on the missing/half-written pair.
        if [ ! -f "$d/key.pem" ] || [ ! -f "$d/cert.pem" ]; then
          mkdir -p "$d"
          openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -subj "/CN=keepnode" -addext "subjectAltName=DNS:keepnode" \
            -keyout "$d/key.pem" -out "$d/cert.pem"
        fi
        # nginx's config test runs as the nginx user, so it must be able to traverse the dir
        # and read the key; grant access via the nginx group rather than world-readable.
        chown -R root:nginx "$d"
        chmod 750 "$d"
        chmod 640 "$d/key.pem"
        chmod 644 "$d/cert.pem"
      '';
    };

    services.nginx = {
      enable = true;
      recommendedProxySettings = true;
      virtualHosts."keepnode" = {
        default = true;
        addSSL = true;
        sslCertificate = "/var/lib/keepnode-tls/cert.pem";
        sslCertificateKey = "/var/lib/keepnode-tls/key.pem";
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString config.keepNode.vaultwarden.port}";
          proxyWebsockets = true;
        };
      };
    };
    systemd.services.nginx = {
      after = [ "keepnode-selfsigned.service" ];
      requires = [ "keepnode-selfsigned.service" ];
    };

    # SSH and the TLS web UI. Vaultwarden's own port stays closed (localhost only).
    networking.firewall.allowedTCPPorts = [
      22
      443
    ];
  };
}
