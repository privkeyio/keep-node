# Optional TLS-terminating ingress for direct (non-mesh) HTTPS access to Vaultwarden.
#
# The M0 default is loopback-only: Vaultwarden binds 127.0.0.1 and is reached over the encrypted
# mesh (which terminates to localhost), so no ingress is needed. This module is for deployments
# that want to expose Vaultwarden directly over HTTPS on the LAN/internet. It is OFF by default and
# imposes no certificate strategy: provide your own cert, or opt into ACME.
#
# When enabled it terminates TLS at nginx (HSTS on), proxies to Vaultwarden on loopback (with the
# WebSocket upgrade its live-sync hub needs), applies a light per-IP request rate limit, and runs a
# fail2ban jail that bans IPs after repeated FAILED logins (the brute-force defense; nginx's blanket
# rate limit cannot tell a failed login from a legitimate token refresh, so fail2ban watches the
# Vaultwarden log instead).
#
# WARNING: this ingress must be the direct network edge for the client, i.e. nginx must see the real
# client IP in $remote_addr. The per-IP rate limit and the fail2ban brute-force ban both key on that
# address. If it is placed behind a CDN, reverse proxy, or load balancer, $remote_addr is the proxy's
# IP: rate limiting collapses to per-proxy (no per-client protection) and fail2ban bans the proxy
# (self-DoS). There is deliberately no set_real_ip_from/real_ip_header trusted-proxy config here.
{
  config,
  lib,
  ...
}:
let
  cfg = config.keepNode.ingress;
  vwPort = config.keepNode.vaultwarden.port;
in
{
  options.keepNode.ingress = {
    enable = lib.mkEnableOption ''
      TLS-terminating nginx ingress in front of Vaultwarden. This must be the direct network edge:
      nginx must see the real client IP in $remote_addr, since the per-IP rate limit and fail2ban
      brute-force ban key on it. Behind a CDN/reverse-proxy/load balancer $remote_addr is the
      proxy's IP, which breaks per-IP rate limiting and makes fail2ban ban the proxy (self-DoS)
    '';

    hostName = lib.mkOption {
      type = lib.types.str;
      example = "vault.example.com";
      description = "Public FQDN the ingress serves (the nginx vhost and the Vaultwarden DOMAIN).";
    };

    tlsCertFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Absolute path string to the PEM certificate (chain) for hostName on the target host
        (e.g. "/var/lib/secrets/vault-cert.pem"). Required unless useACME is set. Must be a path
        string, not a Nix-path literal, so it is never copied into the world-readable Nix store.
      '';
    };

    tlsKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Absolute path string to the PEM private key for tlsCertFile on the target host
        (e.g. "/var/lib/secrets/vault-key.pem"). Required unless useACME is set. Must be a path
        string, not a Nix-path literal, so the private key is never copied into the
        world-readable Nix store.
      '';
    };

    useACME = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Obtain the certificate via ACME (Let's Encrypt) instead of providing one. Requires a
        publicly resolvable hostName reachable on port 80 (or a configured DNS-01 challenge) and
        acceptance of the ACME terms via security.acme.
      '';
    };

    authRatePerMinute = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = "Per-IP request/minute cap nginx applies to the auth + admin endpoints (DoS guard).";
    };

    fail2ban = {
      maxRetry = lib.mkOption {
        type = lib.types.int;
        default = 5;
        description = "Failed logins from one IP before fail2ban bans it.";
      };
      banTime = lib.mkOption {
        type = lib.types.str;
        default = "1h";
        description = "How long a banned IP stays blocked.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.useACME || (cfg.tlsCertFile != null && cfg.tlsKeyFile != null);
        message = "keepNode.ingress requires either useACME = true or both tlsCertFile and tlsKeyFile.";
      }
      {
        assertion = config.keepNode.vaultwarden.enable;
        message = "keepNode.ingress requires keepNode.vaultwarden.enable (it proxies to Vaultwarden).";
      }
    ];

    # Vaultwarden must know its public URL (links, WebAuthn, etc.) and must trust the proxy's
    # forwarded client IP, so its log (and thus fail2ban) bans the real attacker, not 127.0.0.1.
    services.vaultwarden.config = {
      DOMAIN = "https://${cfg.hostName}";
      IP_HEADER = "X-Real-IP";
    };

    services.nginx = {
      enable = true;
      recommendedTlsSettings = true;
      recommendedProxySettings = true;
      recommendedOptimisation = true;
      recommendedGzipSettings = true;

      # Per-IP rate-limit zone for the auth/admin endpoints (DoS guard; brute-force is fail2ban's job).
      appendHttpConfig = ''
        limit_req_zone $binary_remote_addr zone=keepauth:10m rate=${toString cfg.authRatePerMinute}r/m;
      '';

      virtualHosts.${cfg.hostName} = {
        forceSSL = true;
        enableACME = cfg.useACME;
        sslCertificate = lib.mkIf (!cfg.useACME) cfg.tlsCertFile;
        sslCertificateKey = lib.mkIf (!cfg.useACME) cfg.tlsKeyFile;

        extraConfig = ''
          add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        '';

        locations = {
          "/" = {
            proxyPass = "http://127.0.0.1:${toString vwPort}";
          };
          # Vaultwarden's live-sync hub is a WebSocket; it needs the Upgrade headers.
          "/notifications/hub" = {
            proxyPass = "http://127.0.0.1:${toString vwPort}";
            proxyWebsockets = true;
          };
          # Rate-limit the password/token endpoint and the admin panel against floods.
          "/identity/connect/token" = {
            proxyPass = "http://127.0.0.1:${toString vwPort}";
            extraConfig = "limit_req zone=keepauth burst=10 nodelay;";
          };
          "/admin" = {
            proxyPass = "http://127.0.0.1:${toString vwPort}";
            extraConfig = "limit_req zone=keepauth burst=5 nodelay;";
          };
        };
      };
    };

    networking.firewall.allowedTCPPorts = [
      80
      443
    ];

    # Brute-force defense: ban an IP after repeated FAILED logins, which Vaultwarden logs to the
    # journal with the client IP (from IP_HEADER above). This targets failures specifically, unlike
    # the blanket nginx rate limit which would also throttle legitimate token refreshes.
    services.fail2ban = {
      enable = true;
      jails.keep-vaultwarden.settings = {
        enabled = true;
        backend = "systemd";
        filter = "keep-vaultwarden";
        maxretry = cfg.fail2ban.maxRetry;
        bantime = cfg.fail2ban.banTime;
        findtime = "1h";
      };
    };

    environment.etc."fail2ban/filter.d/keep-vaultwarden.conf".text = ''
      [Definition]
      failregex = ^.*Username or password is incorrect\. Try again\. IP: <ADDR>\. Username:.*$
      journalmatch = _SYSTEMD_UNIT=vaultwarden.service
    '';
  };
}
