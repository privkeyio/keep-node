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
      };
      # Dev-only unlock secret for the VM test. Production unlock is FROST-driven.
      environment.etc."keep-node/dev-password".text = "dev-password-vm-only";
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

    # Done = both core services are up on a freshly booted node.
  '';
}
