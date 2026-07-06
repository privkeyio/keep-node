# Relay-based mesh discovery (bead keep-node-6wj / d3s), topology A. Two nodes form the encrypted mesh
# with NO static peer endpoints , they advertise + learn each other's addresses over an off-mesh wisp
# relay (nvpn kind-37195 adverts). nvpn refuses to advertise RFC1918 addresses, so each node advertises
# a routable-looking alias and its peer discovers THAT address over the relay. Proves relay-only
# discovery end to end; the npub roster still gates who may join.
#
# This is the "dynamic/LAN address, no static endpoint" capability. True symmetric-NAT traversal
# additionally needs wisp to relay ephemeral events (kind 21059, bead keep-node-1to) + a STUN server.
#
# Run: nix build .#checks.x86_64-linux.mesh-discovery
{
  nvpnPackage,
  nvpnIdentityFixture,
  wispModule,
  ...
}:
let
  npubA = builtins.readFile "${nvpnIdentityFixture}/npub-a";
  npubB = builtins.readFile "${nvpnIdentityFixture}/npub-b";
  identityDir = "/run/keep-node-mesh-identity";

  # A discovery-mode mesh node: it advertises its OWN address (selfEndpoint) over the relay but lists
  # NO peer endpoint , the peer's address is what discovery resolves. Contrast static onboarding, where
  # each node's config carries every peer's address.
  # nvpn's advert refuses to publish an RFC1918 address (is_unroutable_advert_ip rejects private IPs),
  # so give each node a ROUTABLE-looking alias on the test LAN and advertise THAT. The two aliases share
  # a /24, so a peer that discovers one dials it directly over the same L2. This models "nodes with
  # routable/dynamic addresses discover each other over a relay" (the real use case); the RFC1918 VM
  # network still carries the relay traffic.
  pubIp = self: "51.15.0.${if self == "nodeA" then "10" else "11"}";
  meshNode =
    {
      self,
      fixtureId,
      peerNpub,
    }:
    { nodes, ... }:
    {
      imports = [ ../nixos/mesh.nix ];
      networking.interfaces.eth1.ipv4.addresses = [
        {
          address = pubIp self;
          prefixLength = 24;
        }
      ];
      systemd.tmpfiles.rules = [
        "C ${identityDir} 0700 root root - ${nvpnIdentityFixture}/${fixtureId}"
      ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
        inherit identityDir;
        selfEndpoint = "${pubIp self}:51820";
        # Roster npub only, NO peer endpoint: discovery resolves the peer's address over the relay.
        peers = [ { npub = peerNpub; } ];
        discovery = {
          enable = true;
          relays = [ "ws://${nodes.relay.networking.primaryIPAddress}:7777" ];
          # TEST-ONLY: the in-VM wisp relay is plaintext ws://; production discovery must use wss://.
          allowInsecureWs = true;
        };
      };
    };
in
{
  name = "keep-node-mesh-discovery";

  # Off-mesh bootstrap relay: a plain wisp on the LAN (NOT keepNode.wisp, which is mesh-only) , a
  # not-yet-meshed node must reach it before any mesh exists.
  nodes.relay =
    { ... }:
    {
      imports = [ wispModule ];
      services.wisp = {
        enable = true;
        host = "0.0.0.0";
        openFirewall = true;
      };
    };

  nodes.nodeA = meshNode {
    self = "nodeA";
    fixtureId = "a";
    peerNpub = npubB;
  };
  nodes.nodeB = meshNode {
    self = "nodeB";
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

      relay.wait_for_unit("wisp.service")
      relay.wait_for_open_port(7777)

      for node in [nodeA, nodeB]:
          node.wait_for_unit("keep-node-mesh-prepare.service")
          node.wait_for_unit("keep-node-mesh.service")

      # The whole point: the mesh forms with NO static endpoints , each node discovered the other's
      # address over the relay. Discovery + dial takes longer than static, so a generous window.
      for node in [nodeA, nodeB]:
          node.wait_until_succeeds(
              "journalctl -u keep-node-mesh.service | grep -q 'mesh: 1/1 peers connected'",
              timeout=240,
          )

      # The discovered tunnel carries traffic (deterministic 10.44.x.y).
      meshB = nodeA.succeed("HOME=${stateDir} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      assert meshB.startswith("10.44."), meshB
      nodeA.succeed(f"ping -c3 -W2 {meshB}")

      # Discovery is configured (relays written to [nostr]) and static endpoints are absent: nvpn writes
      # operator-set peer endpoints as a `fips_peer_endpoints` table, which must NOT appear here.
      nodeA.succeed("grep -q '^relays = ' ${stateDir}/.config/nvpn/config.toml")
      nodeA.fail("grep -q 'fips_peer_endpoints' ${stateDir}/.config/nvpn/config.toml")
    '';
}
