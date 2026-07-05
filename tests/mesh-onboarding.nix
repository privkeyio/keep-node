# Declarative mesh onboarding (Onboarding PR1): two nodes whose NixOS config already carries each
# other's npub + endpoint form the encrypted mesh AT BOOT, with ZERO imperative `nvpn init/set`. This
# is the co-owned-cluster path (static endpoints, no relay discovery) that makes the mesh operable and
# lets the insecure installer debug profile go. Contrast tests/mesh.nix, which drives the whole
# init -> set --participant -> set --endpoint -> connect dance by hand from the testScript.
#
# Each node's identity is a pre-generated fixture (nvpnIdentityFixture), so the PEER's npub is known at
# eval time and goes straight into `keepNode.mesh.peers` (the deploy-time roster). keep-node-mesh-prepare
# installs the identity + applies the roster from config; keep-node-mesh.service is wantedBy boot.
#
# Run: nix build .#checks.x86_64-linux.mesh-onboarding
{
  nvpnPackage,
  nvpnIdentityFixture,
  ...
}:
let
  npubA = builtins.readFile "${nvpnIdentityFixture}/npub-a";
  npubB = builtins.readFile "${nvpnIdentityFixture}/npub-b";
  port = 51820;
in
{
  name = "keep-node-mesh-onboarding";

  nodes.nodeA =
    { nodes, ... }:
    {
      imports = [ ../nixos/mesh.nix ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
        identityDir = "${nvpnIdentityFixture}/a";
        selfEndpoint = "${nodes.nodeA.networking.primaryIPAddress}:${toString port}";
        peers = [
          {
            npub = npubB;
            endpoint = "${nodes.nodeB.networking.primaryIPAddress}:${toString port}";
          }
        ];
      };
    };
  nodes.nodeB =
    { nodes, ... }:
    {
      imports = [ ../nixos/mesh.nix ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
        identityDir = "${nvpnIdentityFixture}/b";
        selfEndpoint = "${nodes.nodeB.networking.primaryIPAddress}:${toString port}";
        peers = [
          {
            npub = npubA;
            endpoint = "${nodes.nodeA.networking.primaryIPAddress}:${toString port}";
          }
        ];
      };
    };

  testScript =
    { nodes, ... }:
    let
      stateDir = nodes.nodeA.keepNode.mesh.stateDir;
    in
    ''
      start_all()

      # The whole point: NO imperative nvpn init/set here (contrast tests/mesh.nix). The mesh is
      # provisioned + started from declarative config at boot. Assert it forms with no manual steps.
      for node in [nodeA, nodeB]:
          node.wait_for_unit("keep-node-mesh-prepare.service")
          node.wait_for_unit("keep-node-mesh.service")
          node.wait_until_succeeds(
              "journalctl -u keep-node-mesh.service | grep -q 'mesh: 1/1 peers connected'",
              timeout=120,
          )

      H = "HOME=${stateDir}"

      # The injected identities are the ones in effect (fixed npubs, so the declarative roster matched).
      def selfnpub(node):
          return node.succeed(
              "awk '/^\\[nostr\\]/{n=1;next} /^\\[/{n=0} n&&/^public_key/{print $3}' "
              "${stateDir}/.config/nvpn/config.toml"
          ).strip().strip('\"')

      assert selfnpub(nodeA) == "${npubA}".strip(), "nodeA is not running the injected identity A"
      assert selfnpub(nodeB) == "${npubB}".strip(), "nodeB is not running the injected identity B"

      # Reach the peer over the TUNNEL (deterministic 10.44.x.y), proving the roster + static endpoints
      # from config actually established the tunnel.
      meshB = nodeA.succeed(f"{H} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      meshA = nodeB.succeed(f"{H} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      assert meshB.startswith("10.44.") and meshA.startswith("10.44."), (meshA, meshB)
      nodeA.succeed(f"ping -c3 -W2 {meshB}")
      nodeB.succeed(f"ping -c3 -W2 {meshA}")

      # Confinement still in effect on the boot-enabled daemon.
      for prop in ["ProtectSystem=strict", "MemoryDenyWriteExecute=yes"]:
          nodeA.succeed(f"systemctl show keep-node-mesh.service | grep -qx '{prop}'")
    '';
}
