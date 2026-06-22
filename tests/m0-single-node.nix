# M0: a single KeepNode boots and serves Vaultwarden.
# Run: nix flake check   (or: nix build .#checks.x86_64-linux.m0)
{ ... }:
{
  name = "keep-node-m0-single-node";

  nodes.node =
    { ... }:
    {
      imports = [ ../nixos/keep-node.nix ];
    };

  testScript = ''
    start_all()
    node.wait_for_unit("vaultwarden.service")
    node.wait_for_open_port(8222)
    # Vaultwarden's liveness endpoint returns a timestamp.
    node.succeed("curl -fsS http://localhost:8222/alive")
    # M0 done = the password manager is up on a freshly booted node.
  '';
}
