# Hardened SSH admin access over the mesh (Onboarding PR2). Two nodes form the mesh via declarative
# onboarding, then the "operator" (nodeA, a mesh peer) keys into nodeB's keepadmin account OVER THE
# MESH tunnel, while the same SSH is REFUSED on nodeB's LAN/underlay address -- proving the mesh is the
# perimeter (the hostile LAN never reaches sshd). Also checks the hardened sshd posture (key-only, no
# root, no keyboard-interactive) and that keepadmin's sudo is passwordless.
#
# Run: nix build .#checks.x86_64-linux.mesh-admin-ssh
{
  nvpnPackage,
  nvpnIdentityFixture,
  adminKeyFixture,
  ...
}:
let
  npubA = builtins.readFile "${nvpnIdentityFixture}/npub-a";
  npubB = builtins.readFile "${nvpnIdentityFixture}/npub-b";
  adminPubKey = builtins.readFile "${adminKeyFixture}/id.pub";
  identityDir = "/run/keep-node-mesh-identity";
  port = 51820;
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
        ../nixos/admin-access.nix
      ];
      # Deliver the fixture identity to a runtime path (identityDir refuses a /nix/store path).
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
      keepNode.adminAccess = {
        enable = true;
        authorizedKeys = [ adminPubKey ];
      };
    };
in
{
  name = "keep-node-mesh-admin-ssh";

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
      ipBUnderlay = nodes.nodeB.networking.primaryIPAddress;
    in
    ''
      start_all()

      # Mesh forms from declarative config (as in tests/mesh-onboarding.nix).
      for node in [nodeA, nodeB]:
          node.wait_for_unit("keep-node-mesh.service")
          node.wait_until_succeeds(
              "journalctl -u keep-node-mesh.service | grep -q 'mesh: 1/1 peers connected'",
              timeout=120,
          )
          node.wait_for_unit("sshd.service")

      # Hardened sshd posture on the target (effective config via `sshd -T`).
      for prop in [
          "passwordauthentication no",
          "kbdinteractiveauthentication no",
          "permitrootlogin no",
          "maxauthtries 3",
      ]:
          nodeB.succeed(f"sshd -T | grep -qx '{prop}'")

      # The operator's private key on a 0600 path for the ssh client (the store copy is 0444).
      nodeA.succeed("install -m 0600 ${adminKeyFixture}/id /root/id")
      ssh = (
          "ssh -i /root/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          "-o ConnectTimeout=10 -o BatchMode=yes"
      )

      # Resolve nodeB's deterministic mesh IP.
      meshB = nodeA.succeed("HOME=${stateDir} nvpn ip --peer --discover-secs 0").strip().splitlines()[0].strip()
      assert meshB.startswith("10.44."), meshB

      # 1. Key-in over the MESH succeeds -> a mesh peer is the intended admin path. Retry: the tunnel
      # takes a moment to carry a fresh TCP connection after "1/1 connected" (as ping -c3 masks with its
      # own retries in tests/mesh-onboarding.nix); a single SSH attempt does not, so poll until settled.
      nodeA.wait_until_succeeds(f"{ssh} keepadmin@{meshB} true", timeout=90)
      # ...and keepadmin's sudo is passwordless (key-only account, still logged as keepadmin).
      nodeA.succeed(f"{ssh} keepadmin@{meshB} sudo -n true")

      # 2. The SAME SSH on nodeB's LAN/underlay address is REFUSED -- sshd is opened only on the mesh
      # interface, so the hostile LAN never reaches it. (ConnectTimeout bounds a dropped-packet hang.)
      nodeA.fail(
          "ssh -i /root/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          "-o ConnectTimeout=5 -o BatchMode=yes keepadmin@${ipBUnderlay} true"
      )
    '';
}
