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

      # Anti-lockout runtime backstop: at boot the runtime authorizedKeysFile is not provisioned yet, so
      # keepadmin has NO usable key. The check unit must FAIL loudly (surfacing the otherwise-silent
      # lockout) and log the alert. Nothing requires it, so boot and sshd are unaffected (asserted below).
      box.wait_until_succeeds("systemctl is-failed --quiet keep-node-admin-key-check.service")
      box.succeed("journalctl -u keep-node-admin-key-check.service --no-pager | grep -q 'ANTI-LOCKOUT'")

      # Simulate install-keepnode enrolling the operator key into the mutable runtime file post-install.
      box.succeed("install -d -m 0755 /etc/keepnode")
      box.succeed("install -m 0644 ${adminKeyFixture}/id.pub ${keysFile}")
      box.succeed("install -m 0600 ${adminKeyFixture}/id /root/id")

      # With a usable key now present, the check passes , no false alarm on a valid config.
      box.succeed("systemctl restart keep-node-admin-key-check.service")
      box.succeed("systemctl is-active --quiet keep-node-admin-key-check.service")

      ssh = (
          "ssh -i /root/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
          "-o BatchMode=yes -o ConnectTimeout=10"
      )

      # Hardened posture holds even in bring-up: key-only (no password, no keyboard-interactive), no root.
      box.succeed("sshd -T | grep -qx 'passwordauthentication no'")
      box.succeed("sshd -T | grep -qx 'kbdinteractiveauthentication no'")
      box.succeed("sshd -T | grep -qx 'permitrootlogin no'")

      # Bring-up widens the source restriction to RFC1918 rather than dropping it: a public/WAN source is
      # still refused at auth time even though the firewall opening is global during bring-up. sshd -T
      # emits one `allowusers` line per entry.
      box.succeed("sshd -T | grep -qx 'allowusers keepadmin@10.0.0.0/8'")
      box.succeed("sshd -T | grep -qx 'allowusers keepadmin@172.16.0.0/12'")
      box.succeed("sshd -T | grep -qx 'allowusers keepadmin@192.168.0.0/16'")

      # LAN-reachable (lanBringup) AND the runtime-file key is honoured -> login over the LAN IP succeeds
      # with passwordless sudo. If lanBringup were off, the LAN would be firewalled and this would fail.
      box.wait_until_succeeds(f"{ssh} keepadmin@${lan} true", timeout=30)
      box.succeed(f"{ssh} keepadmin@${lan} sudo -n true")

      # root is still refused over the network.
      box.fail(f"{ssh} root@${lan} true")
    '';
}
