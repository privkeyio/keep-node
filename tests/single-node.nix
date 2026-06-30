# A single KeepNode boots and serves both Vaultwarden and keep-web.
# Run: nix flake check   (or: nix build .#checks.x86_64-linux.single-node)
{ keepWebPackage, ... }:
{
  name = "keep-node-single-node";

  nodes.node =
    { ... }:
    {
      imports = [ ../nixos/keep-node.nix ];

      keepNode.keepWeb = {
        enable = true;
        package = keepWebPackage;
        passwordFile = "/etc/keep-node/dev-password";
        authTokenFile = "/etc/keep-node/dev-auth-token";
      };
      # Dev-only unlock secret for the VM test. Production unlock is FROST-driven.
      environment.etc."keep-node/dev-password".text = "dev-password-vm-only";
      # Dev-only pinned admin token for the VM test (proves KEEP_WEB_AUTH_TOKEN_FILE pinning).
      environment.etc."keep-node/dev-auth-token".text = "vm-only-pinned-token";
    };

  testScript = ''
    start_all()

    # Vaultwarden (the password manager) comes up.
    node.wait_for_unit("vaultwarden.service")
    node.wait_for_open_port(8222)
    node.succeed("curl -fsS http://localhost:8222/alive")

    # keep-web (the Keep daemon) comes up and serves its unauthenticated health route.
    node.wait_for_unit("keep-web.service")
    node.wait_for_open_port(8080)
    node.succeed("curl -fsS http://localhost:8080/api/health")

    # The admin API token is PINNED from KEEP_WEB_AUTH_TOKEN_FILE, not regenerated each boot.
    node.succeed("journalctl -u keep-web.service | grep -q 'auth token configured'")
    node.fail("journalctl -u keep-web.service | grep -q 'generated a random one'")
    # ...and it is enforced: an authed endpoint rejects a missing token (401) and accepts the
    # pinned value (anything but 401 means auth passed and the handler ran).
    code = lambda hdr: (
        "curl -s -o /dev/null -w '%{http_code}' " + hdr + " http://localhost:8080/api/peers"
    )
    assert node.succeed(code("")).strip() == "401", "authed endpoint must reject a missing token"
    assert node.succeed(
        code("-H 'Authorization: Bearer vm-only-pinned-token'")
    ).strip() != "401", "the pinned token must be accepted"

    # Done = both core services are up on a freshly booted node.
  '';
}
