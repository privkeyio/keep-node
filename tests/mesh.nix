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
        # A NON-default name (nvpn's Linux default is utun100): the daemon must create THIS device, not
        # its default, proving keepNode.mesh.interface is wired into `nvpn connect --iface` and so cannot
        # drift from the mesh-scoped firewall rules.
        interface = "utun77";
      };
    };
  nodes.nodeB =
    { ... }:
    {
      imports = [ ../nixos/mesh.nix ];
      keepNode.mesh = {
        enable = true;
        package = nvpnPackage;
        interface = "utun77";
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
      meshIface = nodes.nodeA.keepNode.mesh.interface;
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
              timeout=120,
          )

      # The confinement is the whole point of this unit; assert the load-bearing directives are actually
      # in effect (and the daemon still peered above WHILE confined) so a refactor can't silently drop
      # them -- the daemon would keep forming the mesh either way, so the peering check alone won't catch it.
      for prop in [
          "ProtectSystem=strict",
          "DevicePolicy=closed",
          "MemoryDenyWriteExecute=yes",
          "User=keep-node-mesh",
      ]:
          nodeA.succeed(f"systemctl show keep-node-mesh.service | grep -qx '{prop}'")

      # Load-bearing: the daemon actually RUNS as the non-root user (a regression to root, which still
      # forms the mesh, must fail here). Read the real uid of the MainPID from /proc, so ambient
      # CAP_NET_ADMIN + a non-zero uid is proven, not just the configured directive.
      for node in [nodeA, nodeB]:
          pid = node.succeed("systemctl show -p MainPID --value keep-node-mesh.service").strip()
          assert pid != "0", "keep-node-mesh has no MainPID"
          uid = node.succeed(f"awk '/^Uid:/{{print $2}}' /proc/{pid}/status").strip()
          assert uid != "0", f"mesh daemon (pid {pid}) runs as uid {uid}, expected a non-root uid"

      # The daemon created the CONFIGURED (non-default) interface, not nvpn's utun100 default: proof
      # keepNode.mesh.interface is wired into `nvpn connect --iface`, so the firewall's mesh-scoped
      # rules can never target a device nvpn didn't bring up.
      for node in [nodeA, nodeB]:
          node.succeed("ip link show ${meshIface}")
          node.fail("ip link show utun100")

      # 6. Reach the peer over the TUNNEL (its deterministic 10.44.x.y mesh IP), not the underlay.
      meshB = nodeA.succeed(f"{H} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      meshA = nodeB.succeed(f"{H} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      assert meshB.startswith("10.44.") and meshA.startswith("10.44."), (meshA, meshB)
      nodeA.succeed(f"ping -c3 -W2 {meshB}")
      nodeB.succeed(f"ping -c3 -W2 {meshA}")
    '';
}
