# Bring-up admin access (Onboarding PR3). A freshly-installed generic node is not on a mesh yet, so the
# hardened key-only SSH is reachable over the LAN (`lanBringup`) with the operator key provisioned into
# a RUNTIME file (`authorizedKeysFile`) AFTER install -- not baked into the closure (the installer ships
# a fixed closure, so it writes the key at install time instead). This proves the mechanism the
# installer uses to ship a hardened, reachable node with no known password. Still key-only, no root.
#
# Run: nix build .#checks.x86_64-linux.adminaccess-bringup
{
  adminKeyFixture,
  ...
}:
let
  keysFile = "/etc/keepnode/admin_authorized_keys";
in
{
  name = "keep-node-adminaccess-bringup";

  nodes.box =
    { ... }:
    {
      imports = [ ../nixos/admin-access.nix ];
      keepNode.adminAccess = {
        enable = true;
        # NO inline authorizedKeys -> a successful login proves the RUNTIME file path is honoured.
        authorizedKeysFile = keysFile;
        lanBringup = true;
      };
    };

  testScript =
    { nodes, ... }:
    let
      lan = nodes.box.networking.primaryIPAddress;
    in
    ''
      start_all()
      box.wait_for_unit("sshd.service")

      # Simulate install-keepnode enrolling the operator key into the mutable runtime file post-install.
      box.succeed("install -d -m 0755 /etc/keepnode")
      box.succeed("install -m 0644 ${adminKeyFixture}/id.pub ${keysFile}")
      box.succeed("install -m 0600 ${adminKeyFixture}/id /root/id")

      ssh = (
          "ssh -i /root/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          "-o BatchMode=yes -o ConnectTimeout=10"
      )

      # Hardened posture holds even in bring-up: key-only, no root.
      box.succeed("sshd -T | grep -qx 'passwordauthentication no'")
      box.succeed("sshd -T | grep -qx 'permitrootlogin no'")

      # LAN-reachable (lanBringup) AND the runtime-file key is honoured -> login over the LAN IP succeeds
      # with passwordless sudo. If lanBringup were off, the LAN would be firewalled and this would fail.
      box.wait_until_succeeds(f"{ssh} keepadmin@${lan} true", timeout=30)
      box.succeed(f"{ssh} keepadmin@${lan} sudo -n true")

      # root is still refused over the network.
      box.fail(f"{ssh} root@${lan} true")
    '';
}
