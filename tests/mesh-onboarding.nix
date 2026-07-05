# Declarative mesh onboarding (Onboarding PR1): two nodes whose NixOS config already carries each
# other's npub + endpoint form the encrypted mesh AT BOOT, with ZERO imperative `nvpn init/set`. This
# is the co-owned-cluster path (static endpoints, no relay discovery) that makes the mesh operable and
# lets the insecure installer debug profile go. Contrast tests/mesh.nix, which drives the whole
# init -> set --participant -> set --endpoint -> connect dance by hand from the testScript.
#
# Each node's identity is a pre-generated fixture (nvpnIdentityFixture), so the PEER's npub is known at
# eval time and goes straight into `keepNode.mesh.peers` (the deploy-time roster). The fixture lives in
# the Nix store, but `identityDir` refuses a store path (the secret key must not land in the
# world-readable store), so a tmpfiles rule copies the identity onto a runtime /run path FIRST -- the
# out-of-band delivery a real deploy does via agenix/sops. keep-node-mesh-prepare then installs the
# identity + applies the roster from config; keep-node-mesh.service is wantedBy boot.
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
  # Where each node's identity is delivered on the target (off the store, as a real deploy would).
  identityDir = "/run/keep-node-mesh-identity";
  # One node's declarative config: its own fixture id copied to a runtime path, plus the peer's roster
  # entry. Endpoints derive the port from the module's own listenPort so they stay aligned with it.
  meshNode =
    {
      self,
      peer,
      fixtureId,
      peerNpub,
    }:
    { nodes, ... }:
    {
      imports = [ ../nixos/mesh.nix ];
      systemd.tmpfiles.rules = [
        "C ${identityDir} 0700 root root - ${nvpnIdentityFixture}/${fixtureId}"
      ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
        inherit identityDir;
        selfEndpoint = "${nodes.${self}.networking.primaryIPAddress}:${
          toString nodes.${self}.keepNode.mesh.listenPort
        }";
        peers = [
          {
            npub = peerNpub;
            endpoint = "${nodes.${peer}.networking.primaryIPAddress}:${
              toString nodes.${peer}.keepNode.mesh.listenPort
            }";
          }
        ];
      };
    };
in
{
  name = "keep-node-mesh-onboarding";

  nodes.nodeA = meshNode {
    self = "nodeA";
    peer = "nodeB";
    fixtureId = "a";
    peerNpub = npubB;
  };
  nodes.nodeB = meshNode {
    self = "nodeB";
    peer = "nodeA";
    fixtureId = "b";
    peerNpub = npubA;
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
      # keep-node-mesh-prepare publishes the resolved npub to this file, so read it rather than
      # re-parsing config.toml's TOML here.
      def selfnpub(node):
          return node.succeed("cat ${stateDir}/selfnpub").strip()

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
