# M1 mesh transport (PR-a): two nodes package + run the nvpn daemon and form a STATIC, relay-less
# encrypted mesh, then reach each other over the tunnel. Proves nvpn builds under Nix, runs headless
# in a VM (boringtun userspace WireGuard over /dev/net/tun, no kernel wg module), and peers with a
# static roster + endpoints and NO Nostr relay -- mirroring nostr-vpn's own scripts/e2e-connect
# harness (init -> read npub -> set --participant roster -> set --endpoint/--fips-peer-endpoint ->
# connect -> "mesh: 1/1 peers connected" -> nvpn ip --peer -> ping over the tunnel).
#
# A later increment (PR-b) points the vault replicator at the peer's mesh IP; here we only prove the
# transport comes up and carries traffic.
#
# Run: nix build .#checks.x86_64-linux.mesh
{ nvpnPackage, ... }:
{
  name = "keep-node-mesh";

  nodes.nodeA =
    { ... }:
    {
      imports = [ ../nixos/mesh.nix ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
      };
    };
  nodes.nodeB =
    { ... }:
    {
      imports = [ ../nixos/mesh.nix ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
      };
    };

  # testScript is a function so it can read each node's underlay IP (the nixosTest bridge address)
  # for the static peer endpoints, the same way tests/oprf-unlock.nix addresses its relay.
  testScript =
    { nodes, ... }:
    let
      ipA = nodes.nodeA.networking.primaryIPAddress;
      ipB = nodes.nodeB.networking.primaryIPAddress;
      port = toString nodes.nodeA.keepNode.mesh.listenPort;
      stateDir = nodes.nodeA.keepNode.mesh.stateDir;
    in
    ''
      start_all()
      nodeA.wait_for_unit("multi-user.target")
      nodeB.wait_for_unit("multi-user.target")

      # nvpn reads its config from $HOME; the mesh service uses the same HOME, so provisioning here
      # writes the very config the daemon will run with.
      H = "HOME=${stateDir}"
      CONFIG = "${stateDir}/.config/nvpn/config.toml"

      # 1. Each node generates its own Nostr mesh identity (offline; no relay, no fixture).
      nodeA.succeed(f"{H} nvpn init --force")
      nodeB.succeed(f"{H} nvpn init --force")

      # 2. Read each node's npub from the [nostr] section of its config (as the upstream e2e does).
      def npub(node):
          raw = node.succeed(
              "awk '/^\\[nostr\\]/{n=1;next} /^\\[/{n=0} "
              f"n&&/^public_key/{{print $3}}' {CONFIG}"
          )
          return raw.strip().strip('\"')

      npubA = npub(nodeA)
      npubB = npub(nodeB)
      assert npubA.startswith("npub1") and npubB.startswith("npub1"), (npubA, npubB)
      assert npubA != npubB, "both nodes generated the same identity"

      # 3. Both nodes agree on the participant roster.
      for node in [nodeA, nodeB]:
          node.succeed(f"{H} nvpn set --participant {npubA} --participant {npubB}")

      # 4. Static peering: each node advertises its own underlay endpoint and is handed the peer's,
      #    so discovery never needs a Nostr relay (nvpn ships with no default relays).
      nodeA.succeed(
          f"{H} nvpn set --network-id keepnode --endpoint ${ipA}:${port} "
          f"--listen-port ${port} --fips-advertise-endpoint true "
          f"--fips-peer-endpoint {npubB}=${ipB}:${port}"
      )
      nodeB.succeed(
          f"{H} nvpn set --network-id keepnode --endpoint ${ipB}:${port} "
          f"--listen-port ${port} --fips-advertise-endpoint true "
          f"--fips-peer-endpoint {npubA}=${ipA}:${port}"
      )

      # 5. Bring the mesh up. The daemon logs "mesh: 1/1 peers connected" once the tunnel is live.
      nodeA.systemctl("start keep-node-mesh.service")
      nodeB.systemctl("start keep-node-mesh.service")
      for node in [nodeA, nodeB]:
          node.wait_for_unit("keep-node-mesh.service")
          node.wait_until_succeeds(
              "journalctl -u keep-node-mesh.service | grep -q 'mesh: 1/1 peers connected'",
              timeout=90,
          )

      # The confinement is the whole point of this unit; assert the load-bearing directives are actually
      # in effect (and the daemon still peered above WHILE confined) so a refactor can't silently drop
      # them -- the daemon would keep forming the mesh either way, so the peering check alone won't catch it.
      for prop in ["ProtectSystem=strict", "DevicePolicy=closed", "MemoryDenyWriteExecute=yes"]:
          nodeA.succeed(f"systemctl show keep-node-mesh.service | grep -qx '{prop}'")

      # 6. Reach the peer over the TUNNEL (its deterministic 10.44.x.y mesh IP), not the underlay.
      meshB = nodeA.succeed(f"{H} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      meshA = nodeB.succeed(f"{H} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      assert meshB.startswith("10.44.") and meshA.startswith("10.44."), (meshA, meshB)
      nodeA.succeed(f"ping -c3 -W2 {meshB}")
      nodeB.succeed(f"ping -c3 -W2 {meshA}")
    '';
}
