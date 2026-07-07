# wisp relay over the mesh (bead keep-node-xbs). Two nodes form the encrypted mesh via declarative
# onboarding and each run keepNode.wisp; node B reaches node A's relay OVER THE MESH (a NIP-01 REQ
# draws a response), while the same relay is REFUSED on node A's LAN/underlay address -- proving the
# on-box relay is mesh-only, the transport the OPRF quorum + peer discovery will ride.
#
# Run: nix build .#checks.x86_64-linux.wisp-mesh
{
  nvpnPackage,
  nvpnIdentityFixture,
  wispModule,
  pkgs,
  ...
}:
let
  npubA = builtins.readFile "${nvpnIdentityFixture}/npub-a";
  npubB = builtins.readFile "${nvpnIdentityFixture}/npub-b";
  identityDir = "/run/keep-node-mesh-identity";
  port = 51820;

  pyClient = pkgs.python3.withPackages (ps: [ ps.websockets ]);
  # Connects to ws://<host>:<port>, sends a NIP-01 REQ, and requires a protocol response. open_timeout
  # bounds the connect so the negative (LAN) leg fails fast instead of hanging.
  probe = pkgs.writeText "wisp-probe.py" ''
    import asyncio, json, sys, websockets

    async def main():
        host, port = sys.argv[1], sys.argv[2]
        async with websockets.connect(f"ws://{host}:{port}", open_timeout=5) as ws:
            await ws.send(json.dumps(["REQ", "t", {"limit": 0}]))
            msg = await asyncio.wait_for(ws.recv(), timeout=10)
            assert json.loads(msg)[0] in ("EVENT", "EOSE", "NOTICE", "CLOSED"), msg
        print("nip-01 ok")

    asyncio.run(main())
  '';

  meshNode =
    {
      self,
      peer,
      fixtureId,
      peerNpub,
    }:
    { nodes, ... }:
    {
      imports = [
        ../nixos/mesh.nix
        ../nixos/wisp.nix
        wispModule
      ];
      systemd.tmpfiles.rules = [
        "C ${identityDir} 0700 root root - ${nvpnIdentityFixture}/${fixtureId}"
      ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
        inherit identityDir;
        selfEndpoint = "${nodes.${self}.networking.primaryIPAddress}:${toString port}";
        peers = [
          {
            npub = peerNpub;
            endpoint = "${nodes.${peer}.networking.primaryIPAddress}:${toString port}";
          }
        ];
      };
      keepNode.wisp.enable = true;
    };
in
{
  name = "keep-node-wisp-mesh";

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
      stateDir = nodes.nodeB.keepNode.mesh.stateDir;
      ipAUnderlay = nodes.nodeA.networking.primaryIPAddress;
      relayPort = toString nodes.nodeA.keepNode.wisp.port;
    in
    ''
      start_all()

      for node in [nodeA, nodeB]:
          node.wait_for_unit("keep-node-mesh.service")
          node.wait_until_succeeds(
              "journalctl -u keep-node-mesh.service | grep -q 'mesh: 1/1 peers connected'",
              timeout=120,
          )
          node.wait_for_unit("wisp.service")

      # node A's deterministic mesh IP, resolved from node B.
      meshA = nodeB.succeed("HOME=${stateDir} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      assert meshA.startswith("10.44."), meshA

      # 1. node B reaches node A's relay OVER THE MESH and gets a NIP-01 response.
      nodeB.wait_until_succeeds(f"${pyClient}/bin/python3 ${probe} {meshA} ${relayPort}", timeout=60)

      # 2. The SAME relay is REFUSED on node A's LAN/underlay address (mesh-only firewall).
      nodeB.fail("${pyClient}/bin/python3 ${probe} ${ipAUnderlay} ${relayPort}")

      # 3. The daemon-level source backstop is wired: the relay port is refused from any non-mesh
      # source regardless of interface, so meshInterface drift can't expose it. (Parity with the
      # sshd/rsyncd app-layer ACLs wisp lacks.) Assert the source-CIDR refuse rule is installed.
      nodeA.succeed("iptables -S nixos-fw | grep -- '--dport ${relayPort}' | grep -q nixos-fw-refuse")
    '';
}
