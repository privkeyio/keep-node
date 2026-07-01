# The opt-in TLS ingress terminates HTTPS at nginx, proxies to Vaultwarden, sets HSTS, and loads
# the fail2ban brute-force jail. A self-signed cert stands in for the operator-provided one.
# Run: nix build .#checks.x86_64-linux.ingress
{ ... }:
let
  hostName = "vault.test";
in
{
  name = "keep-node-ingress";

  nodes.node =
    { pkgs, ... }:
    let
      cert = pkgs.runCommand "selfsigned-${hostName}" { nativeBuildInputs = [ pkgs.openssl ]; } ''
        mkdir -p "$out"
        openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
          -keyout "$out/key.pem" -out "$out/cert.pem" \
          -subj "/CN=${hostName}" -addext "subjectAltName=DNS:${hostName}"
      '';
    in
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.vaultwarden.enable = true;
      keepNode.ingress = {
        enable = true;
        hostName = hostName;
        tlsCertFile = "${cert}/cert.pem";
        tlsKeyFile = "${cert}/key.pem";
      };

      environment.systemPackages = [
        pkgs.curl
        pkgs.fail2ban
      ];
    };

  testScript = ''
    base = "curl -fsS -k --resolve ${hostName}:443:127.0.0.1 https://${hostName}"

    node.start()
    node.wait_for_unit("vaultwarden.service")
    node.wait_for_unit("nginx.service")
    node.wait_for_open_port(443)
    # vaultwarden.service goes active before Rocket binds its port; wait for the actual listener so
    # the proxy does not race it with a connection-refused 502.
    node.wait_for_open_port(8222)

    # TLS terminates at nginx and the request is proxied through to Vaultwarden's health route.
    node.succeed(f"{base}/alive")

    # HSTS is set on responses.
    node.succeed(f"{base}/ -I | grep -qi '^strict-transport-security:'")

    # The brute-force jail is loaded and watching the Vaultwarden journal.
    node.wait_for_unit("fail2ban.service")
    node.succeed("fail2ban-client status keep-vaultwarden")

    # The failregex actually matches a real Vaultwarden failed-login line. This is the fragile,
    # security-critical piece: if Vaultwarden's message drifts the ban control fails open silently.
    attacker = "203.0.113.7"
    logline = f"Username or password is incorrect. Try again. IP: {attacker}. Username: alice@example.com."
    out = node.succeed(
        f"fail2ban-regex '{logline}' /etc/fail2ban/filter.d/keep-vaultwarden.conf"
    )
    assert "1 matched" in out, f"expected exactly one failregex match, got:\n{out}"

    # Port 80 is open and redirects to HTTPS (forceSSL), not served plaintext.
    node.succeed(
        "test \"$(curl -s -o /dev/null -w '%{http_code}' --resolve ${hostName}:80:127.0.0.1 http://${hostName}/)\" = 301"
    )

    # End-to-end brute-force ban: exercise the WHOLE chain, not just that the filter parses a
    # hand-written line. A real attacker's repeated failed logins must actually get banned:
    # Vaultwarden emits the failure line -> fail2ban's journalmatch + failregex parse it -> ban
    # after maxRetry. Vaultwarden reads the client IP from X-Real-IP (IP_HEADER), so hit it directly
    # (bypassing nginx, which would rewrite X-Real-IP to 127.0.0.1) with a TEST-NET-3 source that is
    # not in fail2ban's localhost ignore list. The attempt count sits in a window bounded on BOTH
    # sides: it must exceed maxRetry (default 5) to trip the ban, and stay under Vaultwarden's login
    # rate limit (LOGIN_RATELIMIT_MAX_BURST, default 10/60s) or excess attempts return 429 before
    # credential validation and never emit the failure line the jail counts. 6 sits safely between.
    bad_login = (
        "curl -s -o /dev/null -H 'X-Real-IP: " + attacker + "' "
        "--data-urlencode grant_type=password "
        "--data-urlencode username=nobody@keep.test "
        "--data-urlencode password=wrongpassword "
        "--data-urlencode 'scope=api offline_access' "
        "--data-urlencode client_id=web "
        "--data-urlencode deviceType=10 "
        "--data-urlencode deviceIdentifier=fail2ban-test "
        "--data-urlencode deviceName=fail2ban-test "
        "http://127.0.0.1:8222/identity/connect/token"
    )
    for _ in range(6):
        node.succeed(bad_login)

    # Vaultwarden logged the failure with the forwarded attacker IP (the exact line the filter keys
    # on; if this format drifts the ban fails open silently, so assert the real emitted line).
    node.wait_until_succeeds(
        f"journalctl -b -u vaultwarden.service | grep -F 'IP: {attacker}'", timeout=30
    )
    # ...and fail2ban decided to ban that IP (it appears in the jail's banned list; this asserts the
    # ban decision, not that the nftables drop rule is installed and dropping packets).
    node.wait_until_succeeds(
        f"fail2ban-client status keep-vaultwarden | grep -F '{attacker}'", timeout=60
    )
  '';
}
